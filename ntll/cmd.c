// cmd.c - Builtin Windows cmd.exe interpreter for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// A cmd-compatible console shell that runs inside the LSW Windows
// environment. It maps C:\ onto the distro rootfs (drive_c) so commands
// like `dir`, `cd`, `type`, `copy` operate on the Windows filesystem.
//
// Also provides small builtin "Windows software": winver, hostname,
// whoami, echo, ver - invoked like `lsw winver.exe`.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "ntll.h"

#define CMD_INVAL_CMD "The syntax of the command is incorrect.\n"
#define CMD_NOT_FOUND "'%s' is not recognized as an internal or external command,\noperable program or batch file.\n"

#define CMD_EXIT_SENTINEL 100

#define CMD_MAX_LINE 8192
#define CMD_MAX_TOKENS 128
#define CMD_MAX_ENV 256

static int cmd_execute_line(char* line);

static char g_rootfs[4096];           /* distro rootfs (from LSW_ROOTFS) */
static char g_drive_c[4096];          /* unix path of the C: drive root */
static char g_cwd[4096];
static char g_prompt_tpl[128] = "$P$G";
static int  g_echo_on = 1;

static char cmd_env[CMD_MAX_ENV][512];
static int  cmd_env_count = 0;

static int cmd_run_batch(const char* path);

/* ---------- small helpers ---------- */

static void cmd_seed_env(void) {
    cmd_env_count = 0;
    const char* vars[] = { "OS", "SystemRoot", "SystemDrive", "USERPROFILE",
                           "PROCESSOR_ARCHITECTURE", "ComSpec", "PATH",
                           "COMPUTERNAME", "USERNAME", "WINDIR" };
    size_t n = sizeof(vars) / sizeof(vars[0]);
    for (size_t i = 0; i < n && cmd_env_count < CMD_MAX_ENV; i++) {
        const char* v = getenv(vars[i]);
        if (v) {
            snprintf(cmd_env[cmd_env_count], sizeof(cmd_env[0]), "%s=%s", vars[i], v);
            cmd_env_count++;
        }
    }
}

static const char* cmd_get_env(const char* name) {
    size_t nl = strlen(name);
    for (int i = 0; i < cmd_env_count; i++) {
        if (strncmp(cmd_env[i], name, nl) == 0 && cmd_env[i][nl] == '=') {
            return cmd_env[i] + nl + 1;
        }
    }
    return getenv(name);
}

static void cmd_set_env(const char* name, const char* value) {
    size_t nl = strlen(name);
    for (int i = 0; i < cmd_env_count; i++) {
        if (strncmp(cmd_env[i], name, nl) == 0 && cmd_env[i][nl] == '=') {
            snprintf(cmd_env[i], sizeof(cmd_env[0]), "%s=%s", name, value ? value : "");
            return;
        }
    }
    if (cmd_env_count < CMD_MAX_ENV) {
        snprintf(cmd_env[cmd_env_count], sizeof(cmd_env[0]), "%s=%s", name, value ? value : "");
        cmd_env_count++;
    }
}

/* Windows path (C:\foo, \foo, or relative) -> unix path in out */
static void win_to_unix(const char* win, char* out, size_t out_sz) {
    char tmp[CMD_MAX_LINE];
    if (isalpha((unsigned char)win[0]) && win[1] == ':') {
        char drive_lc = (char)tolower((unsigned char)win[0]);
        if (nt_mount_lookup(drive_lc, tmp, sizeof(tmp)) == 0) {
            char joined[CMD_MAX_LINE];
            snprintf(joined, sizeof(joined), "%s%s", tmp, win + 2);
            snprintf(tmp, sizeof(tmp), "%s", joined);
        } else {
            snprintf(tmp, sizeof(tmp), "%s/drive_%c%s", g_rootfs, drive_lc, win + 2);
        }
    } else if (win[0] == '\\') {
        snprintf(tmp, sizeof(tmp), "%s%s", g_drive_c, win);
    } else if (win[0] == '/') {
        snprintf(tmp, sizeof(tmp), "%s", win);
    } else if (strncmp(win, "./", 2) == 0) {
        snprintf(tmp, sizeof(tmp), "%s/%s", g_cwd, win + 2);
    } else {
        snprintf(tmp, sizeof(tmp), "%s/%s", g_cwd, win);
    }
    for (char* p = tmp; *p; p++) if (*p == '\\') *p = '/';
    /* collapse duplicate slashes and copy bounded */
    size_t i = 0;
    size_t j = 0;
    while (tmp[i] && j + 1 < out_sz) {
        if (tmp[i] == '/' && tmp[i + 1] == '/') { i++; continue; }
        out[j++] = tmp[i++];
    }
    out[j] = '\0';
    if (j > 1 && out[j - 1] == '/') out[j - 1] = '\0';
}

/* unix path -> Windows path (C:\...) in out */
static void unix_to_win(const char* unix_path, char* out, size_t out_sz) {
    size_t dc = strlen(g_drive_c);
    if (strncmp(unix_path, g_drive_c, dc) == 0) {
        const char* rest = (unix_path[dc] == '/') ? unix_path + dc + 1 : unix_path + dc;
        snprintf(out, out_sz, "C:\\%s", rest);
    } else {
        /* host mounts (D: -> /, ...) take precedence over drive_c paths */
        char m[4096];
        int mapped = 0;
        for (char d = 'a'; d <= 'z' && !mapped; d++) {
            if (nt_mount_lookup(d, m, sizeof(m)) != 0) continue;
            size_t ml = strlen(m);
            int root_mount = (ml == 1 && m[0] == '/');
            if (strncmp(unix_path, m, ml) == 0 &&
                (root_mount || unix_path[ml] == '/' || unix_path[ml] == '\0')) {
                const char* rest = root_mount ? unix_path + ml : (unix_path[ml] ? unix_path + ml + 1 : "");
                snprintf(out, out_sz, "%c:\\%s", (char)(d - 'a' + 'A'), rest);
                mapped = 1;
            }
        }
        if (!mapped) snprintf(out, out_sz, "%s", unix_path);
    }
    for (char* p = out; *p; p++) if (*p == '/') *p = '\\';
    if (strcmp(out, "C:\\") == 0) out[2] = '\0';
}

/* Expand %VAR% / %% in a command line in place */
static void cmd_expand_vars(char* line) {
    char out[CMD_MAX_LINE];
    char* o = out;
    for (char* p = line; *p && o < out + sizeof(out) - 1; ) {
        if (*p == '%') {
            if (p[1] == '%') { *o++ = '%'; p += 2; continue; }
            char* end = strchr(p + 1, '%');
            if (end) {
                size_t n = (size_t)(end - p - 1);
                char name[512];
                if (n >= sizeof(name)) n = sizeof(name) - 1;
                memcpy(name, p + 1, n);
                name[n] = '\0';
                const char* v = cmd_get_env(name);
                if (v) {
                    for (const char* s = v; *s && o < out + sizeof(out) - 1; s++, o++) *o = *s;
                } else {
                    for (char* q = p; q <= end && o < out + sizeof(out) - 1; q++, o++) *o = *q;
                }
                p = end + 1;
                continue;
            }
        }
        *o++ = *p++;
    }
    *o = '\0';
    strcpy(line, out);
}

/* Tokenize a line (handles quotes). Returns count. */
static int cmd_tokenize(char* line, char* argv[], int max) {
    int n = 0;
    char* p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        if (n >= max - 1) break;
        argv[n++] = p;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        }
        if (*p) *p++ = '\0';
    }
    argv[n] = NULL;
    return n;
}

/* ---------- commands ---------- */

static void cmd_banner(void) {
    const NTLL_OS_VERSION* v = nt_get_os_version();
    printf("Microsoft Windows [Version 10.0.%u.%u.%u]\n", v->major, v->minor, v->build);
    printf("(c) LSW Contributors. Built on the NTLL compatibility layer.\n\n");
}

static void cmd_ver(void) {
    const NTLL_OS_VERSION* v = nt_get_os_version();
    printf("\nMicrosoft Windows [Version 10.0.%u.%u.%u]\n", v->major, v->minor, v->build);
}

static void cmd_prompt_make(char* out, size_t out_sz) {
    char win_cwd[CMD_MAX_LINE];
    unix_to_win(g_cwd, win_cwd, sizeof(win_cwd));
    out[0] = '\0';
    for (const char* p = g_prompt_tpl; *p; p++) {
        if (*p == '$' && p[1]) {
            p++;
            size_t l = strlen(out);
            switch (*p) {
                case 'P': strncat(out, win_cwd, out_sz - l - 1); break;
                case 'G': strncat(out, ">", out_sz - l - 1); break;
                case 'N': strncat(out, "C", out_sz - l - 1); break;
                case 'D': {
                    char d[64]; time_t t = time(NULL); struct tm* tm = localtime(&t);
                    strftime(d, sizeof(d), "%a %d/%m/%Y", tm);
                    strncat(out, d, out_sz - l - 1); break;
                }
                case 'T': {
                    char d[64]; time_t t = time(NULL); struct tm* tm = localtime(&t);
                    strftime(d, sizeof(d), "%H:%M:%S", tm);
                    strncat(out, d, out_sz - l - 1); break;
                }
                default: { char b[2] = { *p, '\0' }; strncat(out, b, out_sz - l - 1); break; }
            }
        } else if (strlen(out) < out_sz - 1) {
            size_t l = strlen(out);
            out[l] = *p;
            out[l + 1] = '\0';
        }
    }
}

static int cmd_cd(int argc, char** argv) {
    if (argc > 2) { printf(CMD_INVAL_CMD); return 1; }
    if (argc == 1) {
        char c[CMD_MAX_LINE];
        unix_to_win(g_cwd, c, sizeof(c));
        printf("%s\n", c);
        return 0;
    }
    if (strcmp(argv[1], "..") == 0) {
        char* s = strrchr(g_cwd, '/');
        if (s && s != g_cwd) {
            *s = '\0';
            return 0;
        }
        snprintf(g_cwd, sizeof(g_cwd), "%s", g_drive_c);
        return 0;
    }
    char target[CMD_MAX_LINE];
    win_to_unix(argv[1], target, sizeof(target));
    struct stat st;
    if (stat(target, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(g_cwd, sizeof(g_cwd), "%s", target);
        return 0;
    }
    printf("The system cannot find the path specified.\n");
    return 1;
}

static int cmd_dir(int argc, char** argv) {
    (void)argc;
    const char* what = (argc > 1) ? argv[1] : ".";
    char dir[CMD_MAX_LINE];
    win_to_unix(what, dir, sizeof(dir));

    DIR* d = opendir(dir);
    if (!d) {
        printf("File Not Found\n");
        return 1;
    }
    char win_dir[CMD_MAX_LINE];
    unix_to_win(dir, win_dir, sizeof(win_dir));
    printf(" Volume in drive C has no label.\n");
    printf(" Directory of %s\n\n", win_dir);

    unsigned long long total = 0;
    struct dirent* e;
    int files = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[CMD_MAX_LINE];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            printf("<DIR>          %s\n", e->d_name);
        } else {
            total += (unsigned long long)st.st_size;
            files++;
            printf("%12llu    %s\n", (unsigned long long)st.st_size, e->d_name);
        }
    }
    closedir(d);
    printf("               %d File(s)  %llu bytes\n", files, total);
    return 0;
}

static int cmd_echo(int argc, char** argv) {
    if (argc == 1) { printf("\n"); return 0; }
    if (strcasecmp(argv[1], "on") == 0)  { g_echo_on = 1; return 0; }
    if (strcasecmp(argv[1], "off") == 0) { g_echo_on = 0; return 0; }
    for (int i = 1; i < argc; i++) {
        printf("%s%s", i > 1 ? " " : "", argv[i]);
    }
    printf("\n");
    return 0;
}

static int cmd_set(int argc, char** argv) {
    if (argc == 1) {
        for (int i = 0; i < cmd_env_count; i++) printf("%s\n", cmd_env[i]);
        return 0;
    }
    char* arg = argv[1];
    char* eq = strchr(arg, '=');
    if (eq) {
        *eq = '\0';
        char value[1024];
        value[0] = '\0';
        if (eq[1] != '\0') {
            strncat(value, eq + 1, sizeof(value) - 1);
        }
        for (int i = 2; i < argc; i++) {
            strncat(value, " ", sizeof(value) - strlen(value) - 1);
            strncat(value, argv[i], sizeof(value) - strlen(value) - 1);
        }
        cmd_set_env(arg, value);
        return 0;
    }
    const char* v = cmd_get_env(arg);
    if (v) { printf("%s=%s\n", arg, v); return 0; }
    printf("Environment variable %s not defined\n", arg);
    return 1;
}

static int cmd_type(int argc, char** argv) {
    if (argc < 2) { printf(CMD_INVAL_CMD); return 1; }
    char path[CMD_MAX_LINE];
    win_to_unix(argv[1], path, sizeof(path));
    FILE* f = fopen(path, "rb");
    if (!f) { printf("The system cannot find the file specified.\n"); return 1; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

static int is_directory(const char* path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int cmd_copy(int argc, char** argv) {
    if (argc < 3) { printf(CMD_INVAL_CMD); return 1; }
    char src[CMD_MAX_LINE], dst[CMD_MAX_LINE];
    win_to_unix(argv[1], src, sizeof(src));
    win_to_unix(argv[2], dst, sizeof(dst));

    FILE* in = fopen(src, "rb");
    if (!in) { printf("The system cannot find the file specified.\n"); return 1; }
    char target[CMD_MAX_LINE];
    snprintf(target, sizeof(target), "%s", dst);
    if (is_directory(dst)) {
        const char* base = strrchr(src, '/');
        base = base ? base + 1 : src;
        snprintf(target, sizeof(target), "%s/%s", dst, base);
    }
    FILE* out = fopen(target, "wb");
    if (!out) { fclose(in); printf("Access is denied.\n"); return 1; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
    printf("        1 file(s) copied.\n");
    return 0;
}

static int cmd_del(int argc, char** argv) {
    if (argc < 2) { printf(CMD_INVAL_CMD); return 1; }
    char path[CMD_MAX_LINE];
    win_to_unix(argv[1], path, sizeof(path));
    if (remove(path) == 0) {
        printf("        1 file(s) deleted.\n");
        return 0;
    }
    printf("Could Not Find %s\n", argv[1]);
    return 1;
}

static int cmd_md(int argc, char** argv) {
    if (argc < 2) { printf(CMD_INVAL_CMD); return 1; }
    char path[CMD_MAX_LINE];
    win_to_unix(argv[1], path, sizeof(path));
    if (mkdir(path, 0755) == 0) return 0;
    if (errno == EEXIST) {
        printf("A subdirectory or file %s already exists.\n", argv[1]);
        return 1;
    }
    printf("The system cannot find the path specified.\n");
    return 1;
}

static int cmd_rd(int argc, char** argv) {
    if (argc < 2) { printf(CMD_INVAL_CMD); return 1; }
    char path[CMD_MAX_LINE];
    win_to_unix(argv[1], path, sizeof(path));
    if (rmdir(path) == 0) return 0;
    if (errno == ENOTEMPTY || errno == EEXIST) {
        printf("The directory is not empty.\n");
        return 1;
    }
    printf("The system cannot find the file specified.\n");
    return 1;
}

static int cmd_ren(int argc, char** argv) {
    if (argc < 3) { printf(CMD_INVAL_CMD); return 1; }
    char oldu[CMD_MAX_LINE];
    win_to_unix(argv[1], oldu, sizeof(oldu));
    char dir[CMD_MAX_LINE];
    strncpy(dir, oldu, sizeof(dir));
    char* s = strrchr(dir, '/');
    if (s) *s = '\0';
    if (dir[0] == '\0') snprintf(dir, sizeof(dir), "%s", g_drive_c);

    char newname[CMD_MAX_LINE];
    snprintf(newname, sizeof(newname), "%s", argv[2]);
    for (char* p = newname; *p; p++) if (*p == '\\' || *p == '/' || *p == ':') *p = '\0';

    char newfull[CMD_MAX_LINE];
    snprintf(newfull, sizeof(newfull), "%s/%s", dir, newname);
    if (rename(oldu, newfull) == 0) return 0;
    printf("The system cannot find the file specified.\n");
    return 1;
}

static int cmd_move(int argc, char** argv) {
    if (argc < 3) { printf(CMD_INVAL_CMD); return 1; }
    char src[CMD_MAX_LINE], dst[CMD_MAX_LINE];
    win_to_unix(argv[1], src, sizeof(src));
    win_to_unix(argv[2], dst, sizeof(dst));
    char target[CMD_MAX_LINE];
    snprintf(target, sizeof(target), "%s", dst);
    if (is_directory(dst)) {
        const char* base = strrchr(src, '/');
        base = base ? base + 1 : src;
        snprintf(target, sizeof(target), "%s/%s", dst, base);
    }
    if (rename(src, target) == 0) {
        printf("        1 file(s) moved.\n");
        return 0;
    }
    printf("The system cannot find the file specified.\n");
    return 1;
}

static char* cmd_hostname_str(char* buf, size_t len) {
    if (gethostname(buf, len) != 0) strcpy(buf, "unknown");
    return buf;
}

static int cmd_hostname(void) {
    char h[256] = {0};
    printf("%s\n", cmd_hostname_str(h, sizeof(h)));
    return 0;
}

static int cmd_whoami(void) {
    const char* u = cmd_get_env("USERNAME");
    if (!u) u = getenv("USER");
    if (!u) u = "Administrator";
    const char* c = cmd_get_env("COMPUTERNAME");
    char local[256] = {0};
    if (!c) {
        cmd_hostname_str(local, sizeof(local));
        c = local;
    }
    printf("%s\\%s\n", c, u);
    return 0;
}

static int cmd_winver(void) {
    const NTLL_OS_VERSION* v = nt_get_os_version();
    printf("Windows Version 10.0.%u.%u.%u\n", v->major, v->minor, v->build);
    printf("LSW NTLL compatibility layer\n");
    return 0;
}

static int cmd_date(void) {
    char d[64];
    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
    strftime(d, sizeof(d), "%a %m/%d/%Y", tm);
    printf("%s\n", d);
    return 0;
}

static int cmd_time(void) {
    char d[64];
    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
    strftime(d, sizeof(d), "%H:%M:%S.00", tm);
    printf("%s\n", d);
    return 0;
}

static int cmd_path(void) {
    const char* p = cmd_get_env("PATH");
    printf("%s\n", p ? p : "");
    return 0;
}

static void cmd_help(void) {
    printf("For more information on a specific command, type HELP command-name\n\n");
    printf("CD       Displays the name of or changes the current directory.\n");
    printf("DIR      Displays a list of files and subdirectories in a directory.\n");
    printf("CLS      Clears the screen.\n");
    printf("ECHO     Displays messages, or turns command echoing on or off.\n");
    printf("SET      Displays, sets, or removes environment variables.\n");
    printf("TYPE     Displays the contents of a text file.\n");
    printf("COPY     Copies one or more files to another location.\n");
    printf("DEL      Deletes one or more files.\n");
    printf("MD       Creates a directory.\n");
    printf("RD       Removes a directory.\n");
    printf("REN      Renames a file or directory.\n");
    printf("MOVE     Moves a file or directory.\n");
    printf("VER      Displays the Windows version.\n");
    printf("HOSTNAME Displays host name.\n");
    printf("WHOAMI   Displays the current user.\n");
    printf("DATE     Displays the date.\n");
    printf("TIME     Displays the time.\n");
    printf("EXIT     Quits the cmd.exe program.\n");
}

/* Run a batch file (.bat / .cmd) */
static int cmd_run_batch(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) { printf("The system cannot find the batch file.\n"); return 1; }
    char line[CMD_MAX_LINE];
    int saved_echo = g_echo_on;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;
        if (line[0] == '@') {
            memmove(line, line + 1, strlen(line));
            int r = cmd_execute_line(line);
            if (r == CMD_EXIT_SENTINEL) break;
            continue;
        }
        if (g_echo_on) printf("%s\n", line);
        int r = cmd_execute_line(line);
        if (r == CMD_EXIT_SENTINEL) break;
    }
    g_echo_on = saved_echo;
    fclose(f);
    return 0;
}

/* Main per-line interpreter. Returns 0/1, or CMD_EXIT_SENTINEL to quit. */
static int cmd_execute_command(char* line) {
    cmd_expand_vars(line);

    char* argv[CMD_MAX_TOKENS];
    int argc = cmd_tokenize(line, argv, CMD_MAX_TOKENS);
    if (argc == 0) return 0;

    char cmd[CMD_MAX_LINE];
    snprintf(cmd, sizeof(cmd), "%s", argv[0]);
    for (char* p = cmd; *p; p++) *p = (char)tolower((unsigned char)*p);

    if (strcmp(cmd, "cd") == 0 || strcmp(cmd, "chdir") == 0) return cmd_cd(argc, argv);
    if (strcmp(cmd, "dir") == 0) return cmd_dir(argc, argv);
    if (strcmp(cmd, "cls") == 0) { printf("\033[H\033[2J"); return 0; }
    if (strcmp(cmd, "echo") == 0) return cmd_echo(argc, argv);
    if (strcmp(cmd, "set") == 0) return cmd_set(argc, argv);
    if (strcmp(cmd, "type") == 0) return cmd_type(argc, argv);
    if (strcmp(cmd, "copy") == 0) return cmd_copy(argc, argv);
    if (strcmp(cmd, "del") == 0 || strcmp(cmd, "erase") == 0) return cmd_del(argc, argv);
    if (strcmp(cmd, "md") == 0 || strcmp(cmd, "mkdir") == 0) return cmd_md(argc, argv);
    if (strcmp(cmd, "rd") == 0 || strcmp(cmd, "rmdir") == 0) return cmd_rd(argc, argv);
    if (strcmp(cmd, "ren") == 0 || strcmp(cmd, "rename") == 0) return cmd_ren(argc, argv);
    if (strcmp(cmd, "move") == 0) return cmd_move(argc, argv);
    if (strcmp(cmd, "ver") == 0) { cmd_ver(); return 0; }
    if (strcmp(cmd, "hostname") == 0) return cmd_hostname();
    if (strcmp(cmd, "whoami") == 0) return cmd_whoami();
    if (strcmp(cmd, "winver") == 0) return cmd_winver();
    if (strcmp(cmd, "date") == 0) return cmd_date();
    if (strcmp(cmd, "time") == 0) return cmd_time();
    if (strcmp(cmd, "path") == 0) return cmd_path();
    if (strcmp(cmd, "help") == 0) { cmd_help(); return 0; }
    if (strcmp(cmd, "prompt") == 0) {
        if (argc > 1) snprintf(g_prompt_tpl, sizeof(g_prompt_tpl), "%s", argv[1]);
        return 0;
    }
    if (strcmp(cmd, "exit") == 0) return CMD_EXIT_SENTINEL;
    if (strcmp(cmd, "rem") == 0) return 0;

    /* Windows builtin software invoked as a program */
    int r = nt_builtin_exec(argv[0], argc, argv);
    if (r >= 0) return r;

    /* Native reimplementations of bundled System32 CLI tools */
    r = nt_tool_dispatch(argv[0], argc, argv);
    if (r >= 0) return r;

    /* attempt to run a batch file placed in cwd */
    char trypath[CMD_MAX_LINE];
    win_to_unix(argv[0], trypath, sizeof(trypath));
    if ((strstr(argv[0], ".bat") || strstr(argv[0], ".cmd")) && access(trypath, F_OK) == 0) {
        return cmd_run_batch(trypath);
    }
    if (access(trypath, F_OK) == 0) {
        r = nt_builtin_exec(argv[0], argc, argv);
        if (r >= 0) return r;
    }
    printf(CMD_NOT_FOUND, argv[0]);
    return 1;
}

/* Extract '>' / '>>' redirection. The cleaned command lands in out; if a
   redirect was found, redir_file is a malloc'd filename and *append is set. */
static void cmd_split_redirect(char* line, char* out, char** redir_file, int* append) {
    *redir_file = NULL;
    *append = 0;
    int in_quote = 0;
    char* r = line;
    char* o = out;
    while (*r == ' ' || *r == '\t') r++;
    for (; *r; r++) {
        if (*r == '"') {
            in_quote = !in_quote;
            *o++ = *r;
            continue;
        }
        if (*r == '>' && !in_quote) {
            if (r[1] == '>') {
                *append = 1;
                r++;
            }
            r++;
            while (*r == ' ' || *r == '\t') r++;
            char fn[CMD_MAX_LINE];
            char* f = fn;
            if (*r == '"') {
                r++;
                while (*r && *r != '"' && f < fn + sizeof(fn) - 1) *f++ = *r++;
                if (*r) r++;
            } else {
                while (*r && *r != ' ' && *r != '\t' && f < fn + sizeof(fn) - 1) *f++ = *r++;
            }
            *f = '\0';
            *redir_file = strdup(fn);
            while (o > out && (o[-1] == ' ' || o[-1] == '\t')) o--;
            *o = '\0';
            return;
        }
        *o++ = *r;
    }
    *o = '\0';
}

/* Execute a line with optional > / >> file redirection. */
static int cmd_execute_line(char* line) {
    char cmdline[CMD_MAX_LINE];
    char* redir_file = NULL;
    int append = 0;
    cmd_split_redirect(line, cmdline, &redir_file, &append);

    int saved_fd = -1;
    FILE* rf = NULL;
    if (redir_file) {
        cmd_expand_vars(redir_file);
        char rpath[CMD_MAX_LINE];
        win_to_unix(redir_file, rpath, sizeof(rpath));
        rf = fopen(rpath, append ? "ab" : "wb");
        if (!rf) {
            free(redir_file);
            printf("The system cannot find the path specified.\n");
            return 1;
        }
        free(redir_file);
        saved_fd = dup(STDOUT_FILENO);
        dup2(fileno(rf), STDOUT_FILENO);
    }
    int rc = cmd_execute_command(cmdline);
    if (rf) {
        fflush(stdout);
        dup2(saved_fd, STDOUT_FILENO);
        close(saved_fd);
        fclose(rf);
    }
    return rc;
}

static void cmd_mkdir_p(const char* path) {
    char tmp[CMD_MAX_LINE];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void ensure_drive_c(void) {
    const char* rootfs = getenv("LSW_ROOTFS");
    const char* drive = (rootfs && *rootfs) ? rootfs : "/var/lib/lsw/root";
    snprintf(g_rootfs, sizeof(g_rootfs), "%s", drive);
    snprintf(g_drive_c, sizeof(g_drive_c), "%s/drive_c", drive);
    struct stat st;
    if (stat(g_drive_c, &st) != 0 || !S_ISDIR(st.st_mode)) {
        cmd_mkdir_p(g_drive_c);
    }
    snprintf(g_cwd, sizeof(g_cwd), "%s/Users/Administrator", g_drive_c);
    if (stat(g_cwd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(g_cwd, sizeof(g_cwd), "%s", g_drive_c);
    }
}

/* ---------- public builtins (called from runtime.c) ---------- */

/* Bundled Windows software - returns >=0 if handled, -1 if not. */
int nt_builtin_exec(const char* program, int argc, char** argv) {
    if (strcasecmp(program, "winver") == 0 || strcasecmp(program, "winver.exe") == 0)
        return cmd_winver();
    if (strcasecmp(program, "hostname") == 0 || strcasecmp(program, "hostname.exe") == 0)
        return cmd_hostname();
    if (strcasecmp(program, "whoami") == 0 || strcasecmp(program, "whoami.exe") == 0)
        return cmd_whoami();
    if (strcasecmp(program, "ver") == 0 || strcasecmp(program, "ver.exe") == 0) {
        cmd_ver();
        return 0;
    }
    if (strcasecmp(program, "date") == 0 || strcasecmp(program, "date.exe") == 0)
        return cmd_date();
    if (strcasecmp(program, "time") == 0 || strcasecmp(program, "time.exe") == 0)
        return cmd_time();
    if (strcasecmp(program, "echo") == 0 || strcasecmp(program, "echo.exe") == 0) {
        for (int i = 1; i < argc; i++) printf("%s%s", i > 1 ? " " : "", argv[i]);
        printf("\n");
        return 0;
    }
    return -1;
}

/* cmd.exe interpreter entry point - called from runtime.c */
int nt_builtin_cmd(int argc, char** argv) {
    cmd_seed_env();
    ensure_drive_c();

    cmd_banner();

    /* batch mode: a .bat/.cmd file path passed as the program */
    if (argc > 0 && (strstr(argv[0], ".bat") || strstr(argv[0], ".cmd"))) {
        char path[CMD_MAX_LINE];
        if (argv[0][0] == '/' || strncmp(argv[0], "./", 2) == 0 ||
            access(argv[0], F_OK) == 0) {
            snprintf(path, sizeof(path), "%s", argv[0]);
        } else {
            win_to_unix(argv[0], path, sizeof(path));
        }
        if (access(path, F_OK) == 0) {
            cmd_run_batch(path);
            return 0;
        }
    }

    char line[CMD_MAX_LINE];
    for (;;) {
        char prompt[CMD_MAX_LINE] = "";
        cmd_prompt_make(prompt, sizeof(prompt));
        fputs(prompt, stdout);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\r\n")] = '\0';
        int r = cmd_execute_line(line);
        if (r == CMD_EXIT_SENTINEL) break;
    }
    putchar('\n');
    return 0;
}