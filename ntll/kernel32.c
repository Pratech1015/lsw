// kernel32.c - kernel32.dll implementation for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// This file implements the core of the Windows kernel32.dll API surface
// used by PE executables once their imports are resolved by the loader.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <wctype.h>

#include "ntll.h"

extern wchar_t g_cmdline[4096];
extern void* g_procparams;
char* g_image_path = NULL;

#define WINDOWS_TICK ((uint64_t)10000000)
#define SEC_TO_UNIX_EPOCH ((uint64_t)11644473600LL)
#define ERROR_FILE_NOT_FOUND 0x02
#define FILE_ATTRIBUTE_READONLY  0x0001
#define FILE_ATTRIBUTE_HIDDEN    0x0002
#define FILE_ATTRIBUTE_DIRECTORY 0x0010
#define FILE_ATTRIBUTE_NORMAL    0x0080

static DWORD g_last_error = 0;
static pthread_mutex_t g_error_lock = PTHREAD_MUTEX_INITIALIZER;

DWORD win32_get_last_error(void) { return g_last_error; }
void win32_set_last_error(DWORD error) { g_last_error = error; }

// Translate errno to Win32 error codes
static DWORD errno_to_win32(int e) {
    switch (e) {
        case ENOENT:    return 0x02;
        case EACCES:    return 0x05;
        case EEXIST:    return 0x0B;
        case ENOTDIR:   return 0x03;
        case EISDIR:    return 0x05;
        case ENOMEM:    return 0x08;
        case EBADF:     return 0x06;
        case EINVAL:    return 0x57;
        case ENOSPC:    return 0x70;
        case ENFILE:    return 0x04;
        case ENOSYS:    return 0x1C;
        case EPERM:     return 0x05;
        default:        return 0x0A;
    }
}

// Windows HANDLEs are mapped to Linux fds via a global table.
#define MAX_WIN_HANDLES 4096
static int g_handle_table[MAX_WIN_HANDLES];
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;

static void handle_table_init(void) {
    for (int i = 0; i < MAX_WIN_HANDLES; i++) g_handle_table[i] = -1;
}

HANDLE win32_handle_alloc(int linux_fd) {
    pthread_mutex_lock(&g_handle_lock);
    for (int i = 0; i < MAX_WIN_HANDLES; i++) {
        if (g_handle_table[i] == -1) {
            g_handle_table[i] = linux_fd;
            pthread_mutex_unlock(&g_handle_lock);
            return (HANDLE)(uintptr_t)(0x100 | i);
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return (HANDLE)INVALID_HANDLE_VALUE;
}

static int handle_lookup(HANDLE h) {
    int slot = (int)((uintptr_t)h & 0xFFF);
    if (slot < 0 || slot >= MAX_WIN_HANDLES) return -1;
    return g_handle_table[slot];
}

static void handle_free(HANDLE h) {
    int slot = (int)((uintptr_t)h & 0xFFF);
    if (slot >= 0 && slot < MAX_WIN_HANDLES) g_handle_table[slot] = -1;
}

static int initialized = 0;
static void ensure_handles(void) {
    if (!initialized) {
        handle_table_init();
        initialized = 1;
    }
}

// Windows CWD stored as UTF-16LE (2-byte units)
static uint16_t g_windows_cwd[MAX_PATH];
static int g_cwd_initialized = 0;
static void ensure_cwd_init(void) {
    if (!g_cwd_initialized) {
        g_cwd_initialized = 1;
        g_windows_cwd[0] = 'C';
        g_windows_cwd[1] = ':';
        g_windows_cwd[2] = '\\';
        g_windows_cwd[3] = 0;
    }
}

BOOL SetCurrentDirectoryW_impl(const wchar_t* wpath) {
    if (!wpath) { win32_set_last_error(87); return FALSE; }
    const uint16_t* src = (const uint16_t*)wpath;
    size_t len = 0;
    while (src[len]) { len++; }
    if (len >= MAX_PATH) len = MAX_PATH - 1;
    memcpy(g_windows_cwd, src, len * sizeof(uint16_t));
    g_windows_cwd[len] = 0;
    return TRUE;
}

DWORD GetCurrentDirectoryW(DWORD len, wchar_t* buf) {
    ensure_cwd_init();
    DWORD needed = 0;
    const uint16_t* p = g_windows_cwd;
    while (*p) { needed++; p++; }
    if (buf && len > needed) {
        uint16_t* wb = (uint16_t*)buf;
        memcpy(wb, g_windows_cwd, (needed + 1) * sizeof(uint16_t));
    }
    return needed;
}

static int match_wildcard(const char* pattern, const char* name) {
    const char* p = pattern;
    const char* n = name;
    const char* star_p = NULL;
    const char* star_n = NULL;
    while (*n) {
        if (*p == '*') {
            star_p = p++;
            star_n = n;
        } else if (*p == '?' || *p == *n) {
            p++; n++;
        } else if (star_p) {
            p = star_p + 1;
            n = ++star_n;
        } else {
            return 0;
        }
    }
    while (*p == '*') p++;
    return *p == 0;
}

// UTF-16LE ↔ UTF-8 conversion (Windows wchar_t = 2 bytes, Linux wchar_t = 4 bytes)
int k32_utf16le_to_utf8(const void* wide_, char* narrow, size_t max_out) {
    const uint16_t* wide = (const uint16_t*)wide_;
    if (!wide || !narrow || max_out == 0) return 0;
    size_t j = 0;
    for (size_t i = 0; wide[i] && j < max_out - 1; i++) {
        uint32_t cp = wide[i];
        if (cp < 0x80) {
            narrow[j++] = (char)cp;
        } else if (cp < 0x800) {
            if (j + 2 >= max_out) break;
            narrow[j++] = (char)(0xC0 | (cp >> 6));
            narrow[j++] = (char)(0x80 | (cp & 0x3F));
        } else {
            if (j + 3 >= max_out) break;
            narrow[j++] = (char)(0xE0 | (cp >> 12));
            narrow[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            narrow[j++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    narrow[j] = 0;
    return (int)j;
}

int k32_utf8_to_utf16le(const char* narrow, void* wide_, size_t max_out) {
    uint16_t* wide = (uint16_t*)wide_;
    if (!narrow || !wide || max_out == 0) return 0;
    size_t j = 0;
    for (size_t i = 0; narrow[i] && j < max_out - 1; i++) {
        unsigned char c = (unsigned char)narrow[i];
        if (c < 0x80) {
            wide[j++] = c;
        } else if ((c & 0xE0) == 0xC0) {
            uint32_t cp = (c & 0x1F) << 6;
            if (narrow[i+1]) cp |= (unsigned char)narrow[++i] & 0x3F;
            wide[j++] = (uint16_t)cp;
        } else if ((c & 0xF0) == 0xE0) {
            uint32_t cp = (c & 0x0F) << 12;
            if (narrow[i+1]) cp |= ((unsigned char)narrow[++i] & 0x3F) << 6;
            if (narrow[i+1]) cp |= (unsigned char)narrow[++i] & 0x3F;
            wide[j++] = (uint16_t)cp;
        } else {
            i += 2;
            if (narrow[i]) i++;
        }
    }
    wide[j] = 0;
    return (int)j;
}

// Path conversion helpers (also exposed in ntll.h)

const char* nt_get_system_root(void) {
    static char sysroot[1024] = {0};
    if (sysroot[0]) return sysroot;
    const char* img = g_image_path;
    if (!img) { strcpy(sysroot, "/var/lib/lsw/distros/windows-11/rootfs"); return sysroot; }
    const char* rootfs = strstr(img, "/rootfs/");
    if (rootfs) {
        size_t len = (size_t)(rootfs - img + 8);  /* include "/rootfs/" */
        if (len >= sizeof(sysroot)) len = sizeof(sysroot) - 1;
        memcpy(sysroot, img, len);
        sysroot[len] = 0;
    } else {
        strcpy(sysroot, "/var/lib/lsw/distros/windows-11/rootfs");
    }
    return sysroot;
}

const char* nt_get_windows_dir(void) {
    static char windir[1024] = {0};
    if (!windir[0]) snprintf(windir, sizeof(windir), "%s/Windows", nt_get_system_root());
    return windir;
}

const char* nt_get_system32_dir(void) {
    static char sys32[1024] = {0};
    if (!sys32[0]) snprintf(sys32, sizeof(sys32), "%s/Windows/System32", nt_get_system_root());
    return sys32;
}

int nt_to_unix_path(const char* nt_path, char* unix_path, int max_len) {
    const char* system_root = nt_get_system_root();
    char buffer[MAX_PATH * 4];
    if (nt_path[0] >= 'A' && nt_path[0] <= 'Z' && nt_path[1] == ':') {
        char mounts[1024];
        if (nt_mount_lookup((char)(nt_path[0] - 'A' + 'a'), mounts, sizeof(mounts)) == 0) {
            snprintf(buffer, sizeof(buffer), "%s%s", mounts, nt_path + 2);
        } else {
            snprintf(buffer, sizeof(buffer), "%s/drive_%c/%s", system_root,
                     (char)(nt_path[0] - 'A' + 'a'), nt_path + 3);
        }
    } else if (nt_path[0] == '\\' && nt_path[1] == '\\') {
        snprintf(buffer, sizeof(buffer), "%s/drive_c/share%s", system_root, nt_path + 2);
    } else if (nt_path[0] == '\\') {
        snprintf(buffer, sizeof(buffer), "%s/drive_c/%s", system_root, nt_path + 1);
    } else {
        snprintf(buffer, sizeof(buffer), "%s", nt_path);
    }
    for (char* p = buffer; *p; p++) { if (*p == '\\') *p = '/'; }
    if (max_len <= 0) return -1;
    strncpy(unix_path, buffer, (size_t)max_len - 1);
    unix_path[max_len - 1] = '\0';
    return 0;
}

int unix_to_nt_path(const char* unix, char* nt, int max_len) {
    const char* system_root = nt_get_system_root();
    const char* rel = unix;
    if (strncmp(unix, system_root, strlen(system_root)) == 0) {
        rel = unix + strlen(system_root);
        while (*rel == '/') rel++;
    }
    snprintf(nt, max_len, "C:\\%s", rel);
    for (char* p = nt; *p; p++) { if (*p == '/') *p = '\\'; }
    return 0;
}

// ---- File I/O ----

HANDLE win32_create_file(const char* path, DWORD access, DWORD share,
                        void* sa, DWORD create, DWORD flags, HANDLE templ) {
    (void)share; (void)sa; (void)flags; (void)templ;
    ensure_handles();

    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));

    int oflag = O_RDONLY;
    if (access & 0x40000000) /* GENERIC_WRITE */ oflag = O_RDWR;

    switch (create) {
        case 1: oflag |= O_CREAT | O_EXCL; break;
        case 2: oflag |= O_CREAT | O_TRUNC; break;
        case 3: break;
        case 4: oflag |= O_CREAT; break;
        default: break;
    }

    int fd = open(unix_path, oflag, 0644);
    if (fd < 0) {
        win32_set_last_error(errno_to_win32(errno));
        return (HANDLE)INVALID_HANDLE_VALUE;
    }
    return win32_handle_alloc(fd);
}

BOOL win32_read_file(HANDLE handle, void* buf, DWORD len, DWORD* bytes_read,
                    void* overlapped) {
    (void)overlapped;
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) { win32_set_last_error(6); return FALSE; }
    ssize_t n = read(fd, buf, len);
    if (n < 0) { win32_set_last_error(errno_to_win32(errno)); return FALSE; }
    if (bytes_read) *bytes_read = (DWORD)n;
    return TRUE;
}

BOOL win32_write_file(HANDLE handle, void* buf, DWORD len, DWORD* written,
                     void* overlapped) {
    (void)overlapped;
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) { win32_set_last_error(6); return FALSE; }
    ssize_t n = write(fd, buf, len);
    if (n < 0) { win32_set_last_error(errno_to_win32(errno)); return FALSE; }
    if (written) *written = (DWORD)n;
    return TRUE;
}

BOOL win32_close_handle(HANDLE handle) {
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) { win32_set_last_error(6); return FALSE; }
    close(fd);
    handle_free(handle);
    return TRUE;
}

DWORD win32_get_file_size(HANDLE handle, DWORD* high) {
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) { win32_set_last_error(6); return 0xFFFFFFFF; }
    struct stat st;
    if (fstat(fd, &st) != 0) { win32_set_last_error(errno_to_win32(errno)); return 0xFFFFFFFF; }
    if (high) *high = (DWORD)((st.st_size >> 32) & 0xFFFFFFFF);
    return (DWORD)(st.st_size & 0xFFFFFFFF);
}

BOOL win32_flush_file_buffers(HANDLE handle) {
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) return FALSE;
    return fsync(fd) == 0;
}

BOOL win32_set_file_pointer(HANDLE handle, LONG dist_lo, LONG* dist_hi,
                           DWORD method, DWORD* new_pos) {
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) return FALSE;
    off_t off = dist_lo;
    if (dist_hi) off |= ((off_t)(*dist_hi)) << 32;
    int whence;
    switch (method) {
        case 0: whence = SEEK_SET; break;
        case 1: whence = SEEK_CUR; break;
        case 2: whence = SEEK_END; break;
        default: return FALSE;
    }
    off_t pos = lseek(fd, off, whence);
    if (pos < 0) return FALSE;
    if (new_pos) *new_pos = (DWORD)(pos & 0xFFFFFFFF);
    return TRUE;
}

BOOL win32_get_file_time(HANDLE handle, void* ctime, void* atime, void* mtime) {
    ensure_handles();
    int fd = handle_lookup(handle);
    if (fd < 0) return FALSE;
    struct stat st;
    if (fstat(fd, &st) != 0) return FALSE;
    uint64_t* c = ctime, *a = atime, *m = mtime;
    if (c) *c = (uint64_t)(st.st_ctime + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK;
    if (a) *a = (uint64_t)(st.st_atime + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK;
    if (m) *m = (uint64_t)(st.st_mtime + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK;
    return TRUE;
}

// ---- Path functions ----

DWORD win32_get_full_path_name(const char* input, DWORD buf_len,
                              char* buf, char** file_part) {
    char resolved[PATH_MAX];
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(input, unix_path, sizeof(unix_path));
    if (realpath(unix_path, resolved)) {
        // Convert back to NT form only if under system root; else return as-is
        strncpy(resolved, unix_path, sizeof(resolved) - 1);
    } else {
        strncpy(resolved, unix_path, sizeof(resolved) - 1);
    }
    size_t len = strnlen(resolved, PATH_MAX - 1);
    if (buf && buf_len > 0) {
        strncpy(buf, resolved, len < buf_len ? len : (size_t)buf_len - 1);
        buf[len < buf_len ? len : (size_t)buf_len - 1] = '\0';
    }
    if (file_part) {
        char* slash = strrchr(buf, '/');
        if (slash) *file_part = slash + 1;
        else *file_part = buf;
    }
    return (DWORD)len;
}

DWORD win32_get_temp_path(DWORD len, char* buf) {
    const char* tmp = getenv("TMP");
    if (!tmp) tmp = "/tmp";
    size_t l = strlen(tmp);
    if (buf && len) {
        strncpy(buf, tmp, (size_t)len - 1);
        buf[len - 1] = '\0';
    }
    return (DWORD)l;
}

DWORD win32_get_temp_file_name(const char* path, const char* prefix,
                              DWORD unique, char* buf) {
    (void)path; (void)prefix; (void)unique;
    char tmpl[] = "/tmp/lsw-tmp-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) close(fd);
    strcpy(buf, tmpl);
    return (DWORD)strlen(tmpl);
}

// ---- Directories and attributes ----

BOOL win32_create_directory(const char* path, void* sa) {
    (void)sa;
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));
    if (mkdir(unix_path, 0755) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FALSE;
    }
    return TRUE;
}

BOOL win32_remove_directory(const char* path) {
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));
    if (rmdir(unix_path) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FALSE;
    }
    return TRUE;
}

BOOL win32_delete_file(const char* path) {
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));
    if (unlink(unix_path) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FALSE;
    }
    return TRUE;
}

BOOL win32_move_file(const char* from, const char* to) {
    char from_u[MAX_PATH * 4], to_u[MAX_PATH * 4];
    nt_to_unix_path(from, from_u, sizeof(from_u));
    nt_to_unix_path(to, to_u, sizeof(to_u));
    if (rename(from_u, to_u) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FALSE;
    }
    return TRUE;
}

BOOL win32_copy_file(const char* from, const char* to, BOOL failIfExists) {
    char from_u[MAX_PATH * 4], to_u[MAX_PATH * 4];
    nt_to_unix_path(from, from_u, sizeof(from_u));
    nt_to_unix_path(to, to_u, sizeof(to_u));

    int src = open(from_u, O_RDONLY);
    if (src < 0) { win32_set_last_error(errno_to_win32(errno)); return FALSE; }
    int dst = open(to_u, O_WRONLY | O_CREAT | (failIfExists ? O_EXCL : O_TRUNC), 0644);
    if (dst < 0) { close(src); win32_set_last_error(errno_to_win32(errno)); return FALSE; }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        if (write(dst, buf, (size_t)n) != n) break;
    }
    close(src);
    close(dst);
    return TRUE;
}

DWORD win32_get_file_attributes(const char* path) {
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));
    struct stat st;
    if (stat(unix_path, &st) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return 0xFFFFFFFF;
    }
    if (S_ISDIR(st.st_mode)) return FILE_ATTRIBUTE_DIRECTORY;
    return FILE_ATTRIBUTE_NORMAL;
}

DWORD GetFileAttributesW_impl(const wchar_t* wpath) {
    if (!wpath) { win32_set_last_error(87); return 0xFFFFFFFF; }
    char upath[2048];
    k32_utf16le_to_utf8(wpath, upath, sizeof(upath));
    for (char* s = upath; *s; s++) { if (*s == '\\') *s = '/'; }
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(upath, unix_path, sizeof(unix_path));
    struct stat st;
    if (stat(unix_path, &st) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return 0xFFFFFFFF;
    }
    if (S_ISDIR(st.st_mode)) return FILE_ATTRIBUTE_DIRECTORY;
    return FILE_ATTRIBUTE_NORMAL;
}

BOOL win32_set_file_attributes(const char* path, DWORD attrs) {
    (void)path; (void)attrs;
    return TRUE;
}

BOOL win32_set_current_directory(const char* path) {
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(path, unix_path, sizeof(unix_path));
    if (chdir(unix_path) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FALSE;
    }
    /* also update the Windows CWD */
    ensure_cwd_init();
    k32_utf8_to_utf16le(path, g_windows_cwd, MAX_PATH);
    return TRUE;
}

DWORD win32_get_current_directory(DWORD len, char* buf) {
    if (!getcwd(buf, len)) return 0;
    return (DWORD)strlen(buf);
}

// ---- Console ----

BOOL win32_alloc_console(void) { return TRUE; }
BOOL win32_free_console(void) { return TRUE; }
BOOL win32_set_console_title(const char* title) { (void)title; return TRUE; }
DWORD win32_get_console_title(char* buf, DWORD len) {
    if (buf && len) buf[0] = '\0';
    return 0;
}
BOOL win32_set_console_cursor_info(HANDLE c, DWORD size, BOOL visible) {
    (void)c; (void)size; (void)visible; return TRUE;
}
BOOL win32_get_console_cursor_info(HANDLE c, void* info) {
    (void)c; if (info) memset(info, 0, 16); return TRUE;
}
BOOL win32_read_console_input(HANDLE c, void* recs, DWORD count, DWORD* read) {
    (void)c; (void)recs;
    if (read) *read = 0;
    return TRUE;
}
BOOL win32_write_console(HANDLE c, void* buf, DWORD len,
                        DWORD* written, void* reserved) {
    (void)c; (void)reserved;
    const uint16_t* wbuf = (const uint16_t*)buf;
    for (DWORD i = 0; i < len; i++) {
        uint16_t ch = wbuf[i];
        if (ch < 0x80) {
            fputc((char)ch, stdout);
        } else {
            wchar_t wc = (wchar_t)ch;
            char mb[4];
            int n = wctomb(mb, wc);
            if (n > 0) fwrite(mb, 1, n, stdout);
        }
    }
    fflush(stdout);
    if (written) *written = len;
    return TRUE;
}
BOOL win32_set_console_mode(HANDLE c, DWORD mode) { (void)c; (void)mode; return TRUE; }
BOOL win32_get_console_mode(HANDLE c, DWORD* mode) {
    (void)c; if (mode) *mode = 7; return TRUE;
}
BOOL win32_get_console_screen_buffer_info(HANDLE c, void* info) {
    (void)c;
    if (info) {
        memset(info, 0, 22);
        ((short*)info)[4] = 80;
        ((short*)info)[5] = 25;
    }
    return TRUE;
}
BOOL win32_fill_console_output_character(HANDLE c, char ch, DWORD count,
                                        void* start, DWORD* written) {
    (void)c; (void)start; if (written) *written = count; return TRUE;
}
BOOL win32_fill_console_output_attribute(HANDLE c, WORD attr, DWORD count,
                                        void* start, DWORD* written) {
    (void)c; (void)attr; (void)start; if (written) *written = count; return TRUE;
}
BOOL win32_set_console_text_attribute(HANDLE c, WORD attrs) {
    (void)c; (void)attrs; return TRUE;
}

// ---- Time ----

void win32_sleep(DWORD ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

DWORD win32_get_tick_count(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void fill_systemtime(void* st, int local) {
    time_t now = time(NULL);
    struct tm* t = local ? localtime(&now) : gmtime(&now);
    short* p = (short*)st;
    p[0] = (short)(t->tm_year + 1900);
    p[1] = (short)(t->tm_mon + 1);
    p[2] = (short)t->tm_wday;
    p[3] = (short)t->tm_mday;
    p[4] = (short)t->tm_hour;
    p[5] = (short)t->tm_min;
    p[6] = (short)t->tm_sec;
    p[7] = 0;
}

void win32_get_system_time(void* st) { fill_systemtime(st, 0); }
void win32_get_local_time(void* st) { fill_systemtime(st, 1); }

void win32_get_system_time_as_file_time(void* ft) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t t = (uint64_t)ts.tv_sec + SEC_TO_UNIX_EPOCH;
    t = t * WINDOWS_TICK + (uint64_t)ts.tv_nsec / 100;
    memcpy(ft, &t, 8);
}

BOOL win32_query_performance_counter(LONGLONG* counter) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (counter) *counter = (LONGLONG)((ts.tv_sec * (uint64_t)1000000000) + ts.tv_nsec);
    return TRUE;
}

BOOL win32_query_performance_frequency(LONGLONG* freq) {
    if (freq) *freq = 1000000000LL;
    return TRUE;
}

// ---- Synchronization ----

void win32_initialize_critical_section(void* cs) {
    pthread_mutex_init((pthread_mutex_t*)cs, NULL);
}
void win32_enter_critical_section(void* cs) {
    pthread_mutex_lock((pthread_mutex_t*)cs);
}
void win32_leave_critical_section(void* cs) {
    pthread_mutex_unlock((pthread_mutex_t*)cs);
}
void win32_delete_critical_section(void* cs) {
    pthread_mutex_destroy((pthread_mutex_t*)cs);
}

HANDLE win32_create_mutex(void* sa, BOOL initial, const char* name) {
    (void)sa; (void)initial; (void)name;
    static DWORD counter = 0x12000;
    return (HANDLE)(uintptr_t)(++counter);
}
BOOL win32_release_mutex(HANDLE m) { (void)m; return TRUE; }

HANDLE win32_create_event(void* sa, BOOL manual, BOOL initial, const char* name) {
    (void)sa; (void)manual; (void)initial; (void)name;
    static DWORD counter = 0x14000;
    return (HANDLE)(uintptr_t)(++counter);
}
BOOL win32_set_event(HANDLE e) { (void)e; return TRUE; }
BOOL win32_reset_event(HANDLE e) { (void)e; return TRUE; }

HANDLE win32_create_semaphore(void* sa, LONG initial, LONG max, const char* name) {
    (void)sa; (void)initial; (void)max; (void)name;
    static DWORD counter = 0x13000;
    return (HANDLE)(uintptr_t)(++counter);
}
BOOL win32_release_semaphore(HANDLE s, LONG count, LONG* prev) {
    (void)s; (void)count; if (prev) *prev = 0; return TRUE;
}

DWORD win32_wait_for_single_object(HANDLE h, DWORD ms) {
    (void)h;
    if (ms != INFINITE) win32_sleep(ms);
    return 0;
}
DWORD win32_wait_for_multiple_objects(DWORD count, const HANDLE* handles,
                                     BOOL wait_all, DWORD ms) {
    (void)count; (void)handles; (void)wait_all;
    if (ms != INFINITE) win32_sleep(ms);
    return 0;
}

// ---- Threading ----

DWORD win32_sleep_ex(DWORD ms, BOOL alertable) {
    (void)alertable;
    win32_sleep(ms);
    return 0;
}

DWORD win32_get_current_thread_id(void) {
    return (DWORD)(uintptr_t)(pthread_self());
}

DWORD win32_get_current_process_id(void) {
    static DWORD pid = 0;
    if (!pid) pid = (DWORD)getpid();
    return pid;
}

HANDLE win32_create_thread(void* sa, SIZE_T stack, void* start, void* param,
                          DWORD flags, DWORD* tid) {
    (void)sa; (void)stack; (void)flags;
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (pthread_create(&t, &attr, (void* (*)(void*))start, param) != 0) {
        win32_set_last_error(8);
        return (HANDLE)(uintptr_t)0;
    }
    if (tid) *tid = (DWORD)(uintptr_t)t;
    return (HANDLE)(uintptr_t)t;
}

DWORD win32_suspend_thread(HANDLE t) { (void)t; return 0; }
DWORD win32_resume_thread(HANDLE t) { (void)t; return 0; }
BOOL win32_terminate_thread(HANDLE t, DWORD code) { (void)t; (void)code; return TRUE; }
DWORD win32_get_thread_id(HANDLE t) { return (DWORD)(uintptr_t)t; }
BOOL win32_get_exit_code_thread(HANDLE t, DWORD* code) {
    (void)t; if (code) *code = 0; return TRUE;
}
BOOL win32_get_exit_code_process(HANDLE p, DWORD* code) {
    (void)p; if (code) *code = 0; return TRUE;
}

// TLS support
#define TLS_SLOTS 64
static void* g_tls_slots[TLS_SLOTS];
static DWORD g_tls_next = 0;

DWORD win32_tls_alloc(void) {
    if (g_tls_next >= TLS_SLOTS) return 0xFFFFFFFF;
    return g_tls_next++;
}
BOOL win32_tls_free(DWORD index) {
    if (index >= TLS_SLOTS) return FALSE;
    g_tls_slots[index] = NULL;
    return TRUE;
}
void* win32_tls_get_value(DWORD index) {
    if (index >= TLS_SLOTS) return NULL;
    return g_tls_slots[index];
}
BOOL win32_tls_set_value(DWORD index, void* value) {
    if (index >= TLS_SLOTS) return FALSE;
    g_tls_slots[index] = value;
    return TRUE;
}

// ---- Processes ----

BOOL win32_get_startup_info(void* si) {
    (void)si;
    return TRUE;
}

void win32_exit_process(DWORD code) {
    exit(code);
}

void win32_exit_thread(DWORD code) {
    (void)code;
    pthread_exit(NULL);
}

// ---- Misc ----

BOOL win32_is_debugger_present(void) { return FALSE; }
void win32_output_debug_string(const char* str) {
    NTLL_LOG_DEBUG("%s", str ? str : "");
}

void win32_get_system_info(void* info) {
    // SYSTEM_INFO - 64-byte structure
    memset(info, 0, 64);
    ((WORD*)info)[0] = 0;     // wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64
    ((WORD*)info)[1] = 4096;  // wPageSize
    ((DWORD*)((BYTE*)info + 8))[0] = 0;  // lpMinimumApplicationAddress
    ((DWORD*)((BYTE*)info + 12))[0] = 0; // lpMaximumApplicationAddress
    ((DWORD*)((BYTE*)info + 16))[0] = (DWORD)(uintptr_t)0x7FFFFFFFFFFFULL;
    ((DWORD*)((BYTE*)info + 24))[0] = 0; // dwActiveProcessorMask
    ((DWORD*)((BYTE*)info + 32))[0] = (DWORD)sysconf(_SC_NPROCESSORS_ONLN);
    ((DWORD*)((BYTE*)info + 36))[0] = (DWORD)sysconf(_SC_NPROCESSORS_ONLN);
    ((DWORD*)((BYTE*)info + 40))[0] = 2;  // dwProcessorType = PROCESSOR_AMD_X8664
    ((DWORD*)((BYTE*)info + 44))[0] = 4096;
    ((WORD*)info)[24] = 0;
}

DWORD win32_get_environment_variable(const char* name, char* buf, DWORD size) {
    const char* val = getenv(name);
    if (!val) { win32_set_last_error(203); return 0; }
    size_t len = strlen(val);
    if (buf && size > len) {
        strcpy(buf, val);
        return (DWORD)len;
    }
    win32_set_last_error(ERROR_FILE_NOT_FOUND);
    return 0;
}

DWORD GetEnvironmentVariableW(const wchar_t* wname, wchar_t* buf, DWORD size) {
    if (!wname) { win32_set_last_error(87); return 0; }
    char name[256];
    k32_utf16le_to_utf8(wname, name, sizeof(name));

    /* Windows path overrides for key environment variables */
    const char* rootfs = nt_get_system_root();
    const char* val = NULL;
    char override[1024] = {0};

    if (strcasecmp(name, "PATH") == 0) {
        snprintf(override, sizeof(override),
                 "%s/drive_c/Windows/System32;%s/drive_c/Windows;"
                 "%s/drive_c/Windows/System32/WindowsPowerShell/v1.0;"
                 "%s/drive_c", rootfs, rootfs, rootfs, rootfs);
        val = override;
    } else if (strcasecmp(name, "PROMPT") == 0) {
        val = "$P$G";
    } else if (strcasecmp(name, "COMSPEC") == 0) {
        snprintf(override, sizeof(override), "%s/drive_c/Windows/System32/cmd.exe", rootfs);
        val = override;
    } else if (strcasecmp(name, "TEMP") == 0 || strcasecmp(name, "TMP") == 0) {
        snprintf(override, sizeof(override), "%s/drive_c/Windows/Temp", rootfs);
        val = override;
    } else if (strcasecmp(name, "SYSTEMROOT") == 0 || strcasecmp(name, "WINDIR") == 0) {
        snprintf(override, sizeof(override), "%s", rootfs);
        val = override;
    } else if (strcasecmp(name, "SYSTEMDRIVE") == 0) {
        val = "C:";
    } else if (strcasecmp(name, "HOMEDRIVE") == 0) {
        val = "C:";
    } else if (strcasecmp(name, "HOMEPATH") == 0) {
        snprintf(override, sizeof(override), "\\Users\\%s", getenv("USER") ? getenv("USER") : "user");
        val = override;
    } else if (strcasecmp(name, "USERPROFILE") == 0) {
        snprintf(override, sizeof(override), "%s/drive_c/Users/%s",
                 rootfs, getenv("USER") ? getenv("USER") : "user");
        val = override;
    } else {
        val = getenv(name);
    }

    if (!val) { win32_set_last_error(203); return 0; }
    DWORD needed = (DWORD)strlen(val);
    if (buf && size > needed) {
        k32_utf8_to_utf16le(val, buf, (size_t)size);
        return needed;
    }
    win32_set_last_error(ERROR_FILE_NOT_FOUND);
    return needed;
}

BOOL win32_set_environment_variable(const char* name, const char* value) {
    return setenv(name, value ? value : "", 1) == 0;
}

DWORD win32_get_command_line(void) {
    static char cl[4096] = {0};
    if (!cl[0]) {
        char* p = getenv("_");
        if (p) snprintf(cl, sizeof(cl), "%s", p);
    }
    return (DWORD)(uintptr_t)cl;
}

DWORD win32_get_module_handle(const char* name) {
    (void)name;
    return (DWORD)(uintptr_t)1;
}

void* win32_get_proc_address(HMODULE h, const char* name) {
    (void)h;
    return ntll_dispatch(NULL, name);
}// kernel32 extensions — appended for real cmd.exe support

// ── Heap ───────────────────────────────────────────────────────

static HANDLE g_process_heap = (HANDLE)1;

HANDLE GetProcessHeap(void) {
    if (!g_process_heap) {
        g_process_heap = (HANDLE)1;  // sentinel
    }
    return g_process_heap;
}

void* HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    (void)heap; (void)flags;
    return calloc(1, size);
}

BOOL HeapFree(HANDLE heap, DWORD flags, void* p) {
    (void)heap; (void)flags;
    free(p);
    return TRUE;
}

void* HeapReAlloc(HANDLE heap, DWORD flags, void* p, SIZE_T size) {
    (void)heap; (void)flags;
    return realloc(p, size);
}

SIZE_T HeapSize(HANDLE heap, DWORD flags, void* p) {
    (void)heap; (void)flags; (void)p;
    return 0;
}

BOOL HeapSetInformation(HANDLE h, int cls, void* info, SIZE_T len) {
    (void)h; (void)cls; (void)info; (void)len;
    return TRUE;
}

void* GlobalAlloc(UINT flags, SIZE_T size) { (void)flags; return calloc(1, size); }
void* GlobalFree(void* p) { free(p); return NULL; }
void* LocalAlloc(UINT flags, SIZE_T size) { (void)flags; return calloc(1, size); }
void* LocalFree(void* p) { free(p); return NULL; }

// ── Virtual memory ─────────────────────────────────────────────

void* VirtualAlloc(void* addr, SIZE_T size, DWORD type, DWORD protect) {
    (void)addr; (void)type; (void)protect;
    return calloc(1, size);
}

BOOL VirtualFree(void* addr, SIZE_T size, DWORD type) {
    (void)size; (void)type;
    free(addr);
    return TRUE;
}

BOOL VirtualQuery(void* addr, void* buf, SIZE_T len) {
    (void)addr;
    if (len >= 48) memset(buf, 0, len);
    return TRUE;
}

// ── SRW Locks ──────────────────────────────────────────────────

void AcquireSRWLockExclusive(SRWLOCK* l) { pthread_mutex_lock((pthread_mutex_t*)l); }
void AcquireSRWLockShared(SRWLOCK* l) { pthread_mutex_lock((pthread_mutex_t*)l); }
void ReleaseSRWLockExclusive(SRWLOCK* l) { pthread_mutex_unlock((pthread_mutex_t*)l); }
void ReleaseSRWLockShared(SRWLOCK* l) { pthread_mutex_unlock((pthread_mutex_t*)l); }
BOOL TryAcquireSRWLockExclusive(SRWLOCK* l) {
    return pthread_mutex_trylock((pthread_mutex_t*)l) == 0;
}

// ── Critical section (Ex variant) ─────────────────────────────

BOOL InitializeCriticalSectionEx(void* cs, DWORD spin, DWORD flags) {
    (void)spin; (void)flags;
    win32_initialize_critical_section(cs);
    return TRUE;
}

// ── Single-list / InitOnce ─────────────────────────────────────

#include <stdatomic.h>

void InitializeSListHead(void* head) { memset(head, 0, 64); }

/* Simple InitOnce implementation: state is in the INIT_ONCE value (0/1/2).
 * Context pointers are stored in a small static table. */
#define ONCE_TABLE_SIZE 32
static struct { void* once; void* ctx; } g_once_table[ONCE_TABLE_SIZE];
static int g_once_count = 0;

static void once_store_ctx(void* once, void* ctx) {
    for (int i = 0; i < g_once_count; i++) {
        if (g_once_table[i].once == once) { g_once_table[i].ctx = ctx; return; }
    }
    if (g_once_count < ONCE_TABLE_SIZE) {
        g_once_table[g_once_count].once = once;
        g_once_table[g_once_count].ctx = ctx;
        g_once_count++;
    }
}
static void* once_get_ctx(void* once) {
    for (int i = 0; i < g_once_count; i++) {
        if (g_once_table[i].once == once) return g_once_table[i].ctx;
    }
    return NULL;
}

BOOL InitOnceBeginInitialize(void* once, DWORD flags, BOOL* pending, void** ctx) {
    if (!once || !pending) return FALSE;
    volatile LONG* state = (volatile LONG*)once;
    LONG cur = *state;
    (void)flags;
    if (cur == 0) {
        *state = 1;
        *pending = TRUE;
        if (ctx) *ctx = NULL;
    } else if (cur == 1) {
        *pending = TRUE;
        if (ctx) *ctx = NULL;
    } else {
        *pending = FALSE;
        if (ctx) *ctx = once_get_ctx(once);
    }
    return TRUE;
}
BOOL InitOnceComplete(void* once, DWORD flags, void* ctx) {
    if (!once) return FALSE;
    volatile LONG* state = (volatile LONG*)once;
    (void)flags;
    once_store_ctx(once, ctx);
    *state = 2;
    return TRUE;
}

// ── Process ────────────────────────────────────────────────────

HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)-1; }

BOOL CreateProcessW(const void* app, void* cmd, void* pa, void* ta,
                    BOOL inherit, DWORD flags, void* env, void* cwd,
                    void* si, void* pi) {
    (void)pa; (void)ta; (void)inherit; (void)flags; (void)env;
    (void)si; (void)pi;
    /* Extract the executable name from the command line or app parameter */
    char exe_path[2048] = {0};
    const wchar_t* wapp = (const wchar_t*)app;
    if (wapp) {
        k32_utf16le_to_utf8(wapp, exe_path, sizeof(exe_path));
    } else if (cmd) {
        const wchar_t* wcmd = (const wchar_t*)cmd;
        char cmd_utf8[2048];
        k32_utf16le_to_utf8(wcmd, cmd_utf8, sizeof(cmd_utf8));
        /* skip leading spaces and quotes */
        const char* p = cmd_utf8;
        while (*p == ' ') p++;
        if (*p == '"') {
            p++;
            const char* q = strchr(p, '"');
            if (q) { size_t n = (size_t)(q - p); if (n >= sizeof(exe_path)) n = sizeof(exe_path)-1; memcpy(exe_path, p, n); exe_path[n] = 0; }
            else snprintf(exe_path, sizeof(exe_path), "%s", p);
        } else {
            const char* q = strchr(p, ' ');
            if (q) { size_t n = (size_t)(q - p); if (n >= sizeof(exe_path)) n = sizeof(exe_path)-1; memcpy(exe_path, p, n); exe_path[n] = 0; }
            else snprintf(exe_path, sizeof(exe_path), "%s", p);
        }
    }
    if (!exe_path[0]) return FALSE;

    /* Convert NT path to Unix path */
    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(exe_path, unix_path, sizeof(unix_path));

    /* Build the command line as UTF-8 */
    char cmdline_utf8[4096] = {0};
    if (cmd) {
        k32_utf16le_to_utf8(cmd, cmdline_utf8, sizeof(cmdline_utf8));
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* child process */
        if (cwd) {
            char cwd_utf8[2048];
            k32_utf16le_to_utf8(cwd, cwd_utf8, sizeof(cwd_utf8));
            char cwd_unix[MAX_PATH * 4];
            nt_to_unix_path(cwd_utf8, cwd_unix, sizeof(cwd_unix));
            chdir(cwd_unix);
        }
        /* Use /proc/self/exe (the runtime) to re-exec */
        char runtime_path[1024];
        ssize_t rl = readlink("/proc/self/exe", runtime_path, sizeof(runtime_path) - 1);
        if (rl > 0) {
            runtime_path[rl] = 0;
            /* Build argv for the child: runtime <exe_path> <args...> */
            execlp(runtime_path, runtime_path, unix_path, (char*)NULL);
        }
        /* fallback: try exec directly */
        execlp(unix_path, unix_path, (char*)NULL);
        _exit(127);
    } else if (pid > 0) {
        /* parent: return success with fake process info */
        if (pi) {
            uint64_t* pih = (uint64_t*)pi;
            pih[0] = (uintptr_t)(HANDLE)(uintptr_t)pid; /* hProcess */
            pih[1] = (uintptr_t)(HANDLE)(uintptr_t)pid; /* hThread */
        }
        return TRUE;
    }
    return FALSE;
}

BOOL CreateProcessAsUserW(HANDLE tok, const void* app, void* cmd,
                          void* pa, void* ta, BOOL inherit, DWORD flags,
                          void* env, void* cwd, void* si, void* pi) {
    (void)tok; (void)app; (void)cmd; (void)pa; (void)ta;
    (void)inherit; (void)flags; (void)env; (void)cwd; (void)si; (void)pi;
    return FALSE;
}

BOOL TerminateProcess(HANDLE h, UINT code) {
    (void)h; (void)code;
    win32_exit_process(code);
    return TRUE;
}

DWORD GetModuleFileNameA(HMODULE mod, char* buf, DWORD sz) {
    const char* path = getenv("LSW_MODULE_PATH");
    if (!path) path = "C:\\Windows\\System32\\cmd.exe";
    if (buf && sz > 0) {
        size_t n = strlen(path);
        if (n >= sz) n = sz - 1;
        memcpy(buf, path, n);
        buf[n] = '\0';
    }
    return strlen(path);
}

DWORD GetModuleFileNameW(HMODULE mod, wchar_t* buf, DWORD sz) {
    (void)mod;
    const char* path = getenv("LSW_MODULE_PATH");
    if (!path) path = "C:\\Windows\\System32\\cmd.exe";
    if (buf && sz > 0) {
        int n = k32_utf8_to_utf16le(path, buf, (size_t)sz);
        if (n >= (int)sz) { buf[sz - 1] = 0; n = (int)sz - 1; }
        return (DWORD)n;
    }
    return (DWORD)strlen(path);
}

BOOL GetModuleHandleExW(DWORD flags, const wchar_t* name, HMODULE* mod) {
    (void)flags; (void)name;
    *mod = (HMODULE)1;
    return TRUE;
}

HMODULE LoadLibraryExW(const wchar_t* name, HANDLE file, DWORD flags) {
    (void)file; (void)flags;
    return (HMODULE)(name ? (uintptr_t)win32_get_module_handle("") : 1);
}

DWORD GetVersion(void) { return 0x00000A28; }  // 10.0

HANDLE OpenThread(DWORD access, BOOL inherit, DWORD tid) {
    (void)access; (void)inherit; (void)tid;
    return (HANDLE)(uintptr_t)tid;
}

BOOL GetThreadGroupAffinity(void* h, void* affinity) {
    (void)h;
    if (affinity) memset(affinity, 0, 16);
    return TRUE;
}

// ── Threadpool ─────────────────────────────────────────────────

void CreateThreadpoolTimer(void** cb, void* env, void* pool) {
    (void)cb; (void)env; (void)pool;
}
void CloseThreadpoolTimer(void* cb) { (void)cb; }
void SetThreadpoolTimer(void* cb, void* due, ULONG period, ULONG window) {
    (void)cb; (void)due; (void)period; (void)window;
}
void WaitForThreadpoolTimerCallbacks(void* cb, BOOL cancel) {
    (void)cb; (void)cancel;
}

// ── Proc thread attribute list ─────────────────────────────────

BOOL InitializeProcThreadAttributeList(void* list, DWORD count, DWORD flags, SIZE_T* sz) {
    (void)list; (void)count; (void)flags;
    if (sz) *sz = 128;
    return TRUE;
}
void DeleteProcThreadAttributeList(void* list) { (void)list; }
BOOL UpdateProcThreadAttribute(void* list, DWORD flags, DWORD attr,
                               void* val, SIZE_T sz, void* prev, void* csz) {
    (void)list; (void)flags; (void)attr; (void)val;
    (void)sz; (void)prev; (void)csz;
    return TRUE;
}

// ── Misc process ───────────────────────────────────────────────

BOOL ReadProcessMemory(HANDLE h, void* base, void* buf, SIZE_T sz, SIZE_T* rd) {
    (void)h; (void)base; (void)buf; (void)sz;
    if (rd) *rd = 0;
    return FALSE;
}

void SetUnhandledExceptionFilter(void* f) { (void)f; }
long UnhandledExceptionFilter(void* r) { (void)r; return 0; }
UINT SetErrorMode(UINT mode) { (void)mode; return 0; }

BOOL DuplicateHandle(HANDLE src, HANDLE hsrc, HANDLE dst, HANDLE* hdst,
                     DWORD access, BOOL inherit, DWORD opts) {
    (void)src; (void)hsrc; (void)dst; (void)access;
    (void)inherit; (void)opts;
    *hdst = hsrc;
    return TRUE;
}

// ── Console ────────────────────────────────────────────────────

static HANDLE g_std_handles[3] = {0};
static int std_handles_initialized = 0;

HANDLE GetStdHandle(DWORD n) {
    /* Windows STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12 */
    int idx = -1;
    if (n == (DWORD)-10) idx = 0;
    else if (n == (DWORD)-11) idx = 1;
    else if (n == (DWORD)-12) idx = 2;
    else if (n < 3) idx = (int)n;
    else return INVALID_HANDLE_VALUE;
    if (!std_handles_initialized) {
        ensure_handles();
        g_std_handles[0] = win32_handle_alloc(STDIN_FILENO);
        g_std_handles[1] = win32_handle_alloc(STDOUT_FILENO);
        g_std_handles[2] = win32_handle_alloc(STDERR_FILENO);
        std_handles_initialized = 1;
    }
    return g_std_handles[idx];
}

void win32_init_peb_standard_handles(void) {
    if (std_handles_initialized) return;
    ensure_handles();
    g_std_handles[0] = win32_handle_alloc(STDIN_FILENO);
    g_std_handles[1] = win32_handle_alloc(STDOUT_FILENO);
    g_std_handles[2] = win32_handle_alloc(STDERR_FILENO);
    std_handles_initialized = 1;
    if (g_procparams) {
        /* ConsoleHandle = stdin handle, ConsoleFlags = 1 (attached console) */
        uintptr_t* con = (uintptr_t*)((char*)g_procparams + 0x10);
        uint32_t* conflags = (uint32_t*)((char*)g_procparams + 0x18);
        *con = (uintptr_t)g_std_handles[0];
        *conflags = 1;
        uintptr_t* std_in  = (uintptr_t*)((char*)g_procparams + 0x20);
        uintptr_t* std_out = (uintptr_t*)((char*)g_procparams + 0x28);
        uintptr_t* std_err = (uintptr_t*)((char*)g_procparams + 0x30);
        *std_in  = (uintptr_t)g_std_handles[0];
        *std_out = (uintptr_t)g_std_handles[1];
        *std_err = (uintptr_t)g_std_handles[2];
    }
}

BOOL ReadConsoleW(HANDLE h, void* buf, DWORD toread, DWORD* read, void* sr) {
    (void)h; (void)sr;
    uint16_t* wbuf = (uint16_t*)buf;
    DWORD count = 0;
    if (toread > 0) {
        while (count < toread) {
            wint_t c = fgetwc(stdin);
            if (c == WEOF) break;
            wbuf[count++] = (uint16_t)c;
            if (c == L'\n') break;
        }
    }
    if (read) *read = count;
    return count > 0;
}

DWORD GetConsoleOutputCP(void) { return 65001; }
HWND GetConsoleWindow(void) { return (HWND)(uintptr_t)0x1234; }

BOOL SetConsoleCursorPosition(HANDLE h, DWORD pos) {
    (void)h;
    int x = pos & 0xFFFF;
    int y = pos >> 16;
    printf("\033[%d;%dH", y + 1, x + 1);
    return TRUE;
}

BOOL ScrollConsoleScreenBufferW(HANDLE h, void* rect, void* clip, COORD dst, void* fill) {
    (void)h; (void)rect; (void)clip; (void)dst; (void)fill;
    return TRUE;
}

BOOL FlushConsoleInputBuffer(HANDLE h) { (void)h; return TRUE; }

BOOL SetConsoleCtrlHandler(void* handler, BOOL add) {
    (void)handler; (void)add;
    return TRUE;
}

// ── File: Find* ────────────────────────────────────────────────

typedef struct { DIR* d; char pattern[512]; char base[1024]; int first; } FIND_CTX;

HANDLE FindFirstFileW(const wchar_t* wpattern, void* data) {
    if (!wpattern || !data) return INVALID_HANDLE_VALUE;
    char upath[2048];
    k32_utf16le_to_utf8(wpattern, upath, sizeof(upath));
    /* convert backslashes to forward slashes */
    for (char* p = upath; *p; p++) { if (*p == '\\') *p = '/'; }
    /* extract directory and pattern */
    char* sl = strrchr(upath, '/');
    char dirpath[2048] = ".";
    char match[512] = "*";
    if (sl) {
        size_t dlen = (size_t)(sl - upath);
        if (dlen == 0) dlen = 1;
        memcpy(dirpath, upath, dlen);
        dirpath[dlen] = '\0';
        snprintf(match, sizeof(match), "%s", sl + 1);
    }
    DIR* d = opendir(dirpath);
    if (!d) return INVALID_HANDLE_VALUE;
    FIND_CTX* ctx = (FIND_CTX*)data;
    ctx->d = d;
    ctx->first = 1;
    snprintf(ctx->pattern, sizeof(ctx->pattern), "%s", match);
    snprintf(ctx->base, sizeof(ctx->base), "%s", dirpath);
    /* find first match */
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (match_wildcard(match, e->d_name)) {
            uint16_t* wname = (uint16_t*)((char*)data + 44);
            k32_utf8_to_utf16le(e->d_name, wname, 260);
            /* fill file attributes */
            DWORD* attrs = (DWORD*)((char*)data);
            struct stat st;
            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, e->d_name);
            *attrs = 0x80;
            if (stat(fullpath, &st) == 0) {
                if (S_ISDIR(st.st_mode)) *attrs = FILE_ATTRIBUTE_DIRECTORY;
            }
            /* fill file size */
            uint64_t* fsize = (uint64_t*)((char*)data + 32);
            *fsize = (S_ISREG(st.st_mode)) ? (uint64_t)st.st_size : 0;
            return (HANDLE)(uintptr_t)1;
        }
    }
    closedir(d);
    return INVALID_HANDLE_VALUE;
}

BOOL FindNextFileW(HANDLE h, void* data) {
    (void)h;
    FIND_CTX* ctx = (FIND_CTX*)data;
    if (!ctx || !ctx->d) return FALSE;
    struct dirent* e;
    while ((e = readdir(ctx->d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (match_wildcard(ctx->pattern, e->d_name)) {
            uint16_t* wname = (uint16_t*)((char*)data + 44);
            k32_utf8_to_utf16le(e->d_name, wname, 260);
            DWORD* attrs = (DWORD*)((char*)data);
            struct stat st;
            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", ctx->base, e->d_name);
            *attrs = 0x80;
            if (stat(fullpath, &st) == 0) {
                if (S_ISDIR(st.st_mode)) *attrs = FILE_ATTRIBUTE_DIRECTORY;
            }
            uint64_t* fsize = (uint64_t*)((char*)data + 32);
            *fsize = (S_ISREG(st.st_mode)) ? (uint64_t)st.st_size : 0;
            return TRUE;
        }
    }
    closedir(ctx->d);
    ctx->d = NULL;
    return FALSE;
}

BOOL FindClose(HANDLE h) { (void)h; return TRUE; }
HANDLE FindFirstFileExW(const wchar_t* a, int b, void* c) { (void)b; return FindFirstFileW(a, c); }
BOOL FindFirstStreamWStub(const wchar_t* a, int b, void* c, DWORD d) {
    (void)a; (void)b; (void)c; (void)d; return FALSE;
}
BOOL FindNextStreamWStub(HANDLE a, void* b) { (void)a; (void)b; return FALSE; }

// ── File: attributes / info ────────────────────────────────────

#define FILE_TYPE_UNKNOWN       0x0000
#define FILE_TYPE_DISK          0x0001
#define FILE_TYPE_CHAR          0x0002
#define FILE_TYPE_PIPE          0x0003
#define FILE_TYPE_REMOTE        0x8000

// CRT standard fds 0/1/2 map directly to Linux stdin/stdout/stderr; the
// console emulation presents them as the process console (FILE_TYPE_CHAR).
DWORD GetFileType(HANDLE h) {
    uintptr_t hval = (uintptr_t)h;
    if (hval < 3) return FILE_TYPE_CHAR;
    ensure_handles();
    int fd = handle_lookup(h);
    if (fd < 0) {
        win32_set_last_error(6);
        return FILE_TYPE_UNKNOWN;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        win32_set_last_error(errno_to_win32(errno));
        return FILE_TYPE_UNKNOWN;
    }
    if (S_ISFIFO(st.st_mode)) return FILE_TYPE_PIPE;
    if (S_ISCHR(st.st_mode)) return FILE_TYPE_CHAR;
    return FILE_TYPE_DISK;
}

BOOL GetFileInformationByHandleEx(HANDLE h, int cls, void* buf, DWORD sz) {
    (void)h; (void)cls; (void)sz;
    memset(buf, 0, 48);
    return TRUE;
}

BOOL GetFileAttributesExW(const wchar_t* p, int cls, void* data) {
    (void)cls;
    if (!p || !data) return FALSE;
    char upath[2048];
    k32_utf16le_to_utf8(p, upath, sizeof(upath));
    for (char* s = upath; *s; s++) { if (*s == '\\') *s = '/'; }
    struct stat st;
    if (stat(upath, &st) != 0) return FALSE;
    memset(data, 0, 40);
    ((DWORD*)data)[0] = S_ISDIR(st.st_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    return TRUE;
}

BOOL GetFileSecurityW(const wchar_t* p, DWORD cls, void* sd, DWORD sz, DWORD* needed) {
    (void)p; (void)cls; (void)sz;
    if (sd) memset(sd, 0, 64);
    if (needed) *needed = 64;
    return TRUE;
}

DWORD SearchPathW(const wchar_t* dir, const wchar_t* file, const wchar_t* ext,
                  DWORD bufsz, wchar_t* buf, wchar_t** fpart) {
    if (!file) { if (buf && bufsz > 0) buf[0] = 0; return 0; }
    char ufile[2048];
    k32_utf16le_to_utf8(file, ufile, sizeof(ufile));
    const char* rootfs = nt_get_system_root();
    /* Search directories: explicit dir, System32, drive_c root */
    const char* search_dirs[] = {
        NULL, /* explicit dir if provided */
        NULL, /* resolved explicit dir */
    };
    char dir_utf8[2048] = {0};
    char dir_unix[MAX_PATH * 4] = {0};
    if (dir) {
        k32_utf16le_to_utf8(dir, dir_utf8, sizeof(dir_utf8));
        nt_to_unix_path(dir_utf8, dir_unix, sizeof(dir_unix));
        search_dirs[0] = dir_unix;
    }
    static char sys32_path[1024];
    static char drive_c_path[1024];
    snprintf(sys32_path, sizeof(sys32_path), "%s/Windows/System32", rootfs);
    snprintf(drive_c_path, sizeof(drive_c_path), "%s/drive_c", rootfs);
    search_dirs[0] = dir ? dir_unix : sys32_path;
    search_dirs[1] = drive_c_path;

    char found[MAX_PATH * 4] = {0};
    for (int i = 0; i < 2; i++) {
        if (!search_dirs[i]) continue;
        char candidate[MAX_PATH * 4];
        snprintf(candidate, sizeof(candidate), "%s/%s", search_dirs[i], ufile);
        if (access(candidate, R_OK) == 0) {
            snprintf(found, sizeof(found), "%s", candidate);
            break;
        }
        /* also try with .exe extension */
        if (ext) {
            char uext[64];
            k32_utf16le_to_utf8(ext, uext, sizeof(uext));
            snprintf(candidate, sizeof(candidate), "%s/%s%s", search_dirs[i], ufile, uext);
            if (access(candidate, R_OK) == 0) {
                snprintf(found, sizeof(found), "%s", candidate);
                break;
            }
        }
    }
    if (!found[0]) {
        /* just return the file as-is */
        snprintf(found, sizeof(found), "%s", ufile);
    }
    /* Convert back to NT path */
    char nt_result[MAX_PATH];
    unix_to_nt_path(found, nt_result, sizeof(nt_result));
    if (buf && bufsz > 0) {
        int n = k32_utf8_to_utf16le(nt_result, buf, (size_t)bufsz);
        if (fpart) {
            /* find last backslash in result for file part */
            wchar_t* last = buf;
            wchar_t* p = buf;
            while (*p) { if (*p == L'\\') last = p + 1; p++; }
            *fpart = last;
        }
        return (DWORD)n;
    }
    return (DWORD)strlen(nt_result);
}

BOOL GetVolumeInformationW(const wchar_t* root, wchar_t* label, DWORD lsz,
                           DWORD* serial, DWORD* maxcomp, DWORD* flags,
                           wchar_t* fsname, DWORD fsnsz) {
    (void)root; (void)serial; (void)maxcomp; (void)flags;
    if (label && lsz > 0) label[0] = 0;
    if (fsname && fsnsz > 0) k32_utf8_to_utf16le("NTFS", fsname, (size_t)fsnsz);
    return TRUE;
}

BOOL GetVolumePathNameW(const wchar_t* file, wchar_t* vol, DWORD sz) {
    (void)file;
    if (vol && sz > 0) k32_utf8_to_utf16le("C:\\", vol, (size_t)sz);
    return TRUE;
}

DWORD GetDriveTypeW(const wchar_t* root) {
    (void)root;
    return 3;  // DRIVE_FIXED
}

BOOL GetDiskFreeSpaceExW(const wchar_t* dir, unsigned long long* avail,
                         unsigned long long* total, unsigned long long* free) {
    (void)dir;
    if (avail) *avail = 100ULL * 1024 * 1024 * 1024;
    if (total) *total = 256ULL * 1024 * 1024 * 1024;
    if (free) *free = 100ULL * 1024 * 1024 * 1024;
    return TRUE;
}

BOOL SetEndOfFile(HANDLE h) { (void)h; return TRUE; }

BOOL SetFileTime(HANDLE h, void* c, void* a, void* w) {
    (void)h; (void)c; (void)a; (void)w;
    return TRUE;
}

// ── File: link / move ──────────────────────────────────────────

BOOL MoveFileExW(const wchar_t* a, const wchar_t* b, DWORD flags) {
    (void)flags;
    char ua[2048], ub[2048];
    k32_utf16le_to_utf8(a, ua, sizeof(ua));
    k32_utf16le_to_utf8(b, ub, sizeof(ub));
    for (char* p = ua; *p; p++) if (*p == '\\') *p = '/';
    for (char* p = ub; *p; p++) if (*p == '\\') *p = '/';
    return rename(ua, ub) == 0;
}

BOOL MoveFileWithProgressW(const wchar_t* a, const wchar_t* b, void* prog, void* data, DWORD flags) {
    (void)prog; (void)data;
    return MoveFileExW(a, b, flags);
}

BOOL CopyFileW(const wchar_t* a, const wchar_t* b, BOOL fail) {
    (void)fail;
    char ua[2048], ub[2048];
    k32_utf16le_to_utf8(a, ua, sizeof(ua));
    k32_utf16le_to_utf8(b, ub, sizeof(ub));
    for (char* p = ua; *p; p++) if (*p == '\\') *p = '/';
    for (char* p = ub; *p; p++) if (*p == '\\') *p = '/';
    int in = open(ua, O_RDONLY);
    if (in < 0) return FALSE;
    int out = open(ub, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) { close(in); return FALSE; }
    char buf[8192]; ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) write(out, buf, (size_t)n);
    close(in); close(out);
    return TRUE;
}

BOOL CopyFileExW(const wchar_t* a, const wchar_t* b, void* prog,
                 void* data, void* cancel, DWORD flags) {
    (void)prog; (void)data; (void)cancel; (void)flags;
    return CopyFileW(a, b, FALSE);
}

void SetConsoleInputExeNameW(const wchar_t* name) {
    (void)name;
}

BOOL CreateHardLinkW(const wchar_t* a, const wchar_t* b, void* sa) {
    (void)sa;
    char ua[2048], ub[2048];
    k32_utf16le_to_utf8(a, ua, sizeof(ua));
    k32_utf16le_to_utf8(b, ub, sizeof(ub));
    for (char* p = ua; *p; p++) if (*p == '\\') *p = '/';
    for (char* p = ub; *p; p++) if (*p == '\\') *p = '/';
    return link(ub, ua) == 0;
}

BOOL CreateSymbolicLinkW(const wchar_t* a, const wchar_t* b, DWORD flags) {
    (void)flags;
    char ua[2048], ub[2048];
    k32_utf16le_to_utf8(a, ua, sizeof(ua));
    k32_utf16le_to_utf8(b, ub, sizeof(ub));
    for (char* p = ua; *p; p++) if (*p == '\\') *p = '/';
    for (char* p = ub; *p; p++) if (*p == '\\') *p = '/';
    return symlink(ub, ua) == 0;
}

// ── Path / env ─────────────────────────────────────────────────

DWORD GetFullPathNameW(const wchar_t* file, DWORD len, wchar_t* buf, wchar_t** part) {
    char ufile[2048], ubuf[4096];
    if (file) k32_utf16le_to_utf8(file, ufile, sizeof(ufile));
    else ufile[0] = 0;

    /* Handle bare drive letter ("C") or drive letter with colon ("C:", "C:file") */
    if (ufile[0] >= 'A' && ufile[0] <= 'Z' && (ufile[1] == '\0' || (ufile[1] == ':' && ufile[2] == '\0'))) {
        if (buf) {
            if (len < 4) { win32_set_last_error(122); return 4; }
            uint16_t* wb = (uint16_t*)buf;
            wb[0] = (uint16_t)ufile[0];
            wb[1] = 0x003A;
            wb[2] = 0x005C;
            wb[3] = 0;
            if (part) *part = buf + 3;
        }
        return 3;
    }

    char unix_path[MAX_PATH * 4];
    nt_to_unix_path(ufile, unix_path, sizeof(unix_path));
    if (buf) {
        const char* drive_c = "/var/lib/lsw/distros/windows-11/rootfs/drive_c";
        if (unix_path[0] != '/') {
            char abs_path[4096];
            snprintf(abs_path, sizeof(abs_path), "%s/%s", drive_c, unix_path);
            if (realpath(abs_path, ubuf)) {
                const char* rel = ubuf + strlen(drive_c);
                if (*rel == '/') rel++;
                char nt_result[MAX_PATH];
                snprintf(nt_result, sizeof(nt_result), "C:\\%s", rel);
                int n = k32_utf8_to_utf16le(nt_result, buf, (size_t)len);
                if (part) *part = buf;
                return (DWORD)n;
            }
        }
        if (realpath(unix_path, ubuf)) {
            char nt_result[MAX_PATH];
            unix_to_nt_path(ubuf, nt_result, sizeof(nt_result));
            int n = k32_utf8_to_utf16le(nt_result, buf, (size_t)len);
            if (part) *part = buf;
            return (DWORD)n;
        }
        int n = k32_utf8_to_utf16le(ufile, buf, (size_t)len);
        if (part) *part = buf;
        return (DWORD)n;
    }
    return (DWORD)k32_utf16le_to_utf8(file, NULL, 0);
}

static DWORD expand_single_variable(const char* var, char* out, size_t outsz) {
    const char* v = getenv(var);
    if (!v) { out[0] = 0; return 0; }
    snprintf(out, outsz, "%s", v);
    return (DWORD)strlen(out);
}

DWORD ExpandEnvironmentStringsA(const char* src, char* dst, DWORD len) {
    char tmp[4096] = {0};
    const char* p = src;
    char* o = tmp;
    size_t orem = sizeof(tmp) - 1;
    while (*p && orem > 0) {
        if (*p == '%') {
            const char* q = strchr(p + 1, '%');
            if (q && q > p + 1) {
                char var[512];
                size_t vlen = (size_t)(q - p - 1);
                if (vlen >= sizeof(var)) vlen = sizeof(var) - 1;
                memcpy(var, p + 1, vlen); var[vlen] = 0;
                char val[2048];
                DWORD r = expand_single_variable(var, val, sizeof(val));
                if (r) {
                    if (r >= orem) r = (DWORD)orem - 1;
                    memcpy(o, val, r); o += r; orem -= r;
                }
                p = q + 1;
                continue;
            }
        }
        *o++ = *p++; orem--;
    }
    *o = 0;
    if (dst && len > 0) snprintf(dst, len, "%s", tmp);
    return (DWORD)strlen(dst ? tmp : src);
}

DWORD ExpandEnvironmentStringsW(const wchar_t* src, wchar_t* dst, DWORD len) {
    char usrc[4096], udst[4096];
    k32_utf16le_to_utf8(src, usrc, sizeof(usrc));
    DWORD r = ExpandEnvironmentStringsA(usrc, udst, (DWORD)sizeof(udst));
    if (dst) k32_utf8_to_utf16le(udst, dst, (size_t)len);
    return r;
}

wchar_t* GetEnvironmentStringsW(void) {
    // Return a block of null-terminated, double-null terminated strings
    static wchar_t wblock[16384];
    extern char** environ;
    wchar_t* p = wblock;
    for (char** e = environ; *e; e++) {
        k32_utf8_to_utf16le(*e, p, 2048);
        size_t slen = 0;
        const uint16_t* up = (const uint16_t*)p;
        while (up[slen]) slen++;
        p += slen + 1;
    }
    *p = L'\0';
    return wblock;
}

BOOL FreeEnvironmentStringsW(wchar_t* e) { (void)e; return TRUE; }
BOOL SetEnvironmentStringsW(wchar_t* e) { (void)e; return FALSE; }

DWORD GetWindowsDirectoryW(wchar_t* buf, DWORD len) {
    if (buf && len > 0) k32_utf8_to_utf16le("C:\\Windows", buf, (size_t)len);
    return 9;
}

BOOL NeedCurrentDirectoryForExePathW(const wchar_t* name) {
    (void)name;
    return TRUE;
}

wchar_t* GetCommandLineW(void) {
    if (g_cmdline[0]) return g_cmdline;
    static wchar_t wcmd[4096] = L"cmd.exe";
    return wcmd;
}

// ── FormatMessageW ─────────────────────────────────────────────

DWORD FormatMessageW(DWORD flags, void* src, DWORD msgid, DWORD lang,
                     wchar_t* buf, DWORD len, void* args) {
    (void)flags; (void)src; (void)msgid; (void)lang; (void)args;
    if (buf && len > 0) buf[0] = L'\0';
    return 0;
}

// ── Time ───────────────────────────────────────────────────────

BOOL CompareFileTime(const FILETIME* a, const FILETIME* b) {
    if (!a || !b) return 0;
    if (a->dwLowDateTime < b->dwLowDateTime) return (DWORD)-1;
    if (a->dwLowDateTime > b->dwLowDateTime) return 1;
    return 0;
}

BOOL FileTimeToLocalFileTime(const FILETIME* ft, FILETIME* lft) {
    if (!ft || !lft) return FALSE;
    *lft = *ft;
    return TRUE;
}

BOOL FileTimeToSystemTime(const FILETIME* ft, void* st) {
    (void)ft;
    if (st) memset(st, 0, 16);
    return TRUE;
}

BOOL SystemTimeToFileTime(void* st, FILETIME* ft) {
    (void)st;
    if (ft) { ft->dwLowDateTime = 0; ft->dwHighDateTime = 0; }
    return TRUE;
}

// ── Locale ─────────────────────────────────────────────────────

int CompareStringOrdinal(const wchar_t* a, int al, const wchar_t* b, int bl, BOOL ignore) {
    (void)ignore;
    const uint16_t* ua = (const uint16_t*)a;
    const uint16_t* ub = (const uint16_t*)b;
    int cmp = 0;
    int len = al < bl ? al : bl;
    for (int i = 0; i < len; i++) {
        if (ua[i] != ub[i]) { cmp = (int)ua[i] - (int)ub[i]; break; }
    }
    if (cmp == 0) {
        if (al < bl) cmp = -1;
        else if (al > bl) cmp = 1;
    }
    if (cmp < 0) return 1;
    if (cmp > 0) return 2;
    return 1;  // CSTR_EQUAL
}

BOOL GetLocaleInfoW(int loc, int cls, wchar_t* buf, int len) {
    (void)loc; (void)cls;
    if (buf && len > 0) buf[0] = L'\0';
    return TRUE;
}

DWORD GetUserDefaultLCID(void) { return 0x0409; }  // en-US
DWORD GetThreadLocale(void) { return 0x0409; }
DWORD SetThreadLocale(DWORD loc) { (void)loc; return 0x0409; }

BOOL GetTimeFormatW(int loc, DWORD fmt, void* st, const wchar_t* pat,
                    wchar_t* buf, int len) {
    (void)loc; (void)fmt; (void)st; (void)pat;
    if (buf && len > 0) k32_utf8_to_utf16le("00:00:00", buf, (size_t)len);
    return TRUE;
}

BOOL GetDateFormatW(int loc, DWORD fmt, void* st, const wchar_t* pat,
                    wchar_t* buf, int len) {
    (void)loc; (void)fmt; (void)st; (void)pat;
    if (buf && len > 0) k32_utf8_to_utf16le("01/01/2025", buf, (size_t)len);
    return TRUE;
}

BOOL SetLocalTime(void* t) { (void)t; return TRUE; }

// ── System info ────────────────────────────────────────────────

BOOL GetNumaHighestNodeNumber(ULONG* n) { if (n) *n = 0; return TRUE; }
BOOL GetNumaNodeProcessorMaskEx(void* node, void* mask) {
    (void)node;
    if (mask) memset(mask, 0, 16);
    return TRUE;
}

BOOL GetCPInfo(int cp, void* info) {
    (void)cp;
    if (info) memset(info, 0, 16);
    return TRUE;
}

UINT GetACP(void) { return 65001; }  // UTF-8

// ── Stub: WNet / Shell / Branding / Misc ───────────────────────

DWORD WNetAddConnection2WStub(void* a, void* b, void* c, DWORD d) { (void)a; (void)b; (void)c; (void)d; return 12002; }
DWORD WNetCancelConnection2WStub(void* a, DWORD b, DWORD c) { (void)a; (void)b; (void)c; return 12002; }
DWORD WNetGetConnectionWStub(void* a, void* b, DWORD* c) { (void)a; (void)b; (void)c; return 12002; }
void* BrandingFormatString(void* a) { (void)a; return NULL; }
void CmdBatNotificationStub(void* a) { (void)a; }
void DoSHChangeNotify(DWORD a, DWORD b, void* c, void* d) { (void)a; (void)b; (void)c; (void)d; }
BOOL FindFirstStreamWStub2(const wchar_t* a, int b, void* c, DWORD d) { (void)a; (void)b; (void)c; (void)d; return FALSE; }
BOOL FindNextStreamWStub2(HANDLE a, void* b) { (void)a; (void)b; return FALSE; }
void GetVDMCurrentDirectoriesStub(void* a, void* b) { (void)a; (void)b; }
void* LookupAccountSidWStub(void* a, void* b, void* c, DWORD* d, void* e, DWORD* f, void* g) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; return NULL;
}
BOOL QueryFullProcessImageNameWStub(HANDLE a, DWORD b, wchar_t* c, DWORD* d) {
    (void)a; (void)b; (void)d;
    if (c) k32_utf8_to_utf16le("cmd.exe", c, 260);
    return TRUE;
}
void SaferWorker(void* a, void* b, void* c, DWORD d, void* e) { (void)a; (void)b; (void)c; (void)d; (void)e; }
BOOL ShellExecuteExW(void* info) { (void)info; return FALSE; }
void ShellExecuteWorker(void* a, void* b, void* c, void* d, void* e, int f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
}
BOOL MessageBeepStub(UINT type) { (void)type; return TRUE; }
void OutputDebugStringW(const wchar_t* s) { (void)s; }
void DebugBreak(void) { }
BOOL DeviceIoControl(HANDLE h, DWORD op, void* in, DWORD insz,
                     void* out, DWORD outsz, DWORD* ret, void* ovp) {
    (void)h; (void)op; (void)in; (void)insz;
    (void)out; (void)outsz; (void)ret; (void)ovp;
    return FALSE;
}

// Eventing stubs
DWORD EventRegister(void* a, void* b, void* c, void* d) { (void)a; (void)b; (void)c; (void)d; return 0; }
DWORD EventSetInformation(void* a, DWORD b, void* c, DWORD d) { (void)a; (void)b; (void)c; (void)d; return 0; }
DWORD EventUnregister(void* a) { (void)a; return 0; }
DWORD EventWriteTransfer(void* a, void* b, void* c, DWORD d, void* e) { (void)a; (void)b; (void)c; (void)d; (void)e; return 0; }

// WinRT stubs
HRESULT RoInitialize(int mode) { (void)mode; return 0; }
void RoUninitialize(void) { }

// RaiseFailFastException - called by WIL error handling, just abort
void RaiseFailFastException(void* er, void* rs, DWORD flags) {
    (void)er; (void)rs; (void)flags;
    fprintf(stderr, "[ntll] RaiseFailFastException called - aborting\n");
    abort();
}

// API set / delay load
BOOL ApiSetQueryApiSetPresence(void* ns, BOOL present) { (void)ns; (void)present; return TRUE; }
void* DelayLoadFailureHook(void* a, void* b) { (void)a; (void)b; return NULL; }
void* ResolveDelayLoadedAPI(void* base, void* desc, void* hook, void* target, UINT ordinal, UINT flags) {
    (void)base; (void)desc; (void)hook; (void)ordinal; (void)flags;
    return target ? target : NULL;
}

// ── Real cmd.exe gap fillers ────────────────────────────────────────

// MultiByteToWideChar / WideCharToMultiByte
int MultiByteToWideChar(UINT cp, DWORD flags, const char* src, int srclen,
                        wchar_t* dst, int dstlen) {
    (void)cp; (void)flags;
    if (!src) return 0;
    if (srclen < 0) srclen = (int)strlen(src);
    int n = 0;
    for (int i = 0; i < srclen && (dst == NULL || n < dstlen); i++) {
        if (dst) dst[n] = (wchar_t)(unsigned char)src[i];
        n++;
    }
    if (dst) dst[n] = 0;
    return n;
}
int WideCharToMultiByte(UINT cp, DWORD flags, const wchar_t* src, int srclen,
                        char* dst, int dstlen, const char* defch, BOOL* used) {
    (void)cp; (void)flags; (void)defch; (void)used;
    if (!src) return 0;
    if (srclen < 0) srclen = (int)wcslen(src);
    int n = 0;
    for (int i = 0; i < srclen && (dst == NULL || n < dstlen); i++) {
        if (dst) dst[n] = (char)(src[i] & 0xff);
        n++;
    }
    if (dst) dst[n] = 0;
    return n;
}

// lstrcmpW / lstrcmpiW
int lstrcmpW(const wchar_t* a, const wchar_t* b) {
    const uint16_t* ua = (const uint16_t*)a;
    const uint16_t* ub = (const uint16_t*)b;
    while (*ua && *ua == *ub) { ua++; ub++; }
    return (int)*ua - (int)*ub;
}
int lstrcmpiW(const wchar_t* a, const wchar_t* b) {
    const uint16_t* ua = (const uint16_t*)a;
    const uint16_t* ub = (const uint16_t*)b;
    while (*ua && towlower((wint_t)*ua) == towlower((wint_t)*ub)) { ua++; ub++; }
    return (int)towlower((wint_t)*ua) - (int)towlower((wint_t)*ub);
}

// OpenSemaphoreW / WaitForSingleObjectEx
HANDLE OpenSemaphoreW(DWORD access, BOOL inherit, const wchar_t* name) {
    (void)access; (void)inherit; (void)name;
    return win32_create_semaphore(NULL, 0, 1, NULL);
}
DWORD WaitForSingleObjectEx(HANDLE h, DWORD ms, BOOL alertable) {
    (void)alertable;
    return win32_wait_for_single_object(h, ms);
}

// GetSecurityDescriptorOwner / RevertToSelf stubs
BOOL GetSecurityDescriptorOwner(void* sd, void** owner, BOOL* def) {
    (void)sd; if (owner) *owner = NULL; if (def) *def = TRUE; return TRUE;
}
HANDLE RevertToSelf(void) { return (HANDLE)1; }

// SetThreadUILanguage: returns previous thread locale; store/return a fake
UINT SetThreadUILanguage(UINT lang) {
    (void)lang;
    return 0x409; /* en-US */
}

// Registry wrappers over ntll/registry.c
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#ifndef ERROR_FILE_NOT_FOUND
#define ERROR_FILE_NOT_FOUND 2
#endif
#ifndef ERROR_NO_MORE_ITEMS
#define ERROR_NO_MORE_ITEMS 259
#endif
#ifndef REG_SZ
#define REG_SZ 1
#endif
static void reg_unicode(const wchar_t* name, UNICODE_STRING* u) {
    const uint16_t* un = (const uint16_t*)name;
    size_t len = 0;
    while (un[len]) len++;
    u->Length = (uint16_t)(len * sizeof(uint16_t));
    u->MaximumLength = u->Length + sizeof(uint16_t);
    u->Buffer = (wchar_t*)name;
}
BOOL RegCloseKey(HKEY key) { (void)key; return TRUE; }
LONG RegOpenKeyExW(HKEY root, const wchar_t* subkey, DWORD opts,
                   DWORD access, HKEY* out) {
    (void)opts;
    UNICODE_STRING name;
    reg_unicode(subkey ? subkey : L"", &name);
    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = (HANDLE)(uintptr_t)root;
    oa.ObjectName = &name;
    *out = 0;
    HANDLE h = 0;
    NTSTATUS st = nt_open_key((PHANDLE)&h, access, &oa);
    *out = (HKEY)(uintptr_t)h;
    if (st == STATUS_OBJECT_NAME_NOT_FOUND) return ERROR_FILE_NOT_FOUND;
    return st ? (LONG)(st | 0x10000000) : (LONG)ERROR_SUCCESS;
}
LONG RegCreateKeyExW(HKEY root, const wchar_t* subkey, DWORD rsv, wchar_t* cls,
                     DWORD opts, DWORD access, void* sec, HKEY* out, DWORD* disp) {
    (void)rsv; (void)cls; (void)sec;
    UNICODE_STRING name;
    reg_unicode(subkey ? subkey : L"", &name);
    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = (HANDLE)(uintptr_t)root;
    oa.ObjectName = &name;
    *out = 0;
    HANDLE h = 0;
    NTSTATUS st = nt_create_key((PHANDLE)&h, access, &oa, 0, NULL, opts, disp);
    *out = (HKEY)(uintptr_t)h;
    return st ? (LONG)(st | 0x10000000) : (LONG)ERROR_SUCCESS;
}
LONG RegSetValueExW(HKEY key, const wchar_t* name, DWORD rsv, DWORD type,
                    const BYTE* data, DWORD size) {
    (void)rsv;
    UNICODE_STRING un;
    reg_unicode(name ? name : L"", &un);
    NTSTATUS st = nt_set_value_key(key, &un, 0, type, (PVOID)data, size);
    return st ? (LONG)(st | 0x10000000) : (LONG)0;
}
LONG RegQueryValueExW(HKEY key, const wchar_t* name, DWORD* rsv, DWORD* type,
                      BYTE* data, DWORD* size) {
    (void)rsv;
    UNICODE_STRING un;
    reg_unicode(name ? name : L"", &un);
    ULONG ret = 0;
    NTSTATUS st = nt_query_value_key(key, &un, 0, data, size ? *size : 0, &ret);
    if (type) *type = REG_SZ;
    if (size) *size = ret;
    if (st == STATUS_OBJECT_NAME_NOT_FOUND) return ERROR_FILE_NOT_FOUND;
    return st ? (LONG)(st | 0x10000000) : (LONG)ERROR_SUCCESS;
}
LONG RegDeleteValueW(HKEY key, const wchar_t* name) {
    (void)key; (void)name; return (LONG)ERROR_SUCCESS;
}
LONG RegDeleteKeyExW(HKEY root, const wchar_t* subkey, DWORD access, DWORD rsv) {
    (void)root; (void)subkey; (void)access; (void)rsv; return (LONG)ERROR_SUCCESS;
}
LONG RegEnumKeyExW(HKEY key, DWORD index, wchar_t* name, DWORD* namelen,
                   DWORD* cls, wchar_t* clsname, DWORD* clslen, FILETIME* ft) {
    (void)key; (void)index; (void)name; (void)cls; (void)clsname;
    if (namelen) *namelen = 0; if (clslen) *clslen = 0;
    if (ft) memset(ft, 0, sizeof(*ft));
    return ERROR_NO_MORE_ITEMS;
}
LONG RegGetValueW(HKEY key, const wchar_t* subkey, const wchar_t* name,
                  DWORD flags, DWORD* type, BYTE* data, DWORD* size) {
    (void)flags; (void)subkey;
    UNICODE_STRING un;
    reg_unicode(name ? name : L"", &un);
    ULONG ret = 0;
    NTSTATUS st = nt_query_value_key(key, &un, 0, data, size ? *size : 0, &ret);
    if (type) *type = REG_SZ;
    if (size) *size = ret;
    if (st == STATUS_OBJECT_NAME_NOT_FOUND) return ERROR_FILE_NOT_FOUND;
    return st ? (LONG)(st | 0x10000000) : (LONG)ERROR_SUCCESS;
}
