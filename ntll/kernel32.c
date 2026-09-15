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

#include "ntll.h"

#define WINDOWS_TICK ((uint64_t)10000000)
#define SEC_TO_UNIX_EPOCH ((uint64_t)11644473600LL)
#define ERROR_FILE_NOT_FOUND 0x02

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

static HANDLE handle_alloc(int linux_fd) {
    pthread_mutex_lock(&g_handle_lock);
    for (int i = 0; i < MAX_WIN_HANDLES; i++) {
        if (g_handle_table[i] == -1) {
            g_handle_table[i] = linux_fd;
            pthread_mutex_unlock(&g_handle_lock);
            return (HANDLE)(0x100 | (HANDLE)i);
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return (HANDLE)INVALID_HANDLE_VALUE;
}

static int handle_lookup(HANDLE h) {
    int slot = (int)(h & 0xFFF);
    if (slot < 0 || slot >= MAX_WIN_HANDLES) return -1;
    return g_handle_table[slot];
}

static void handle_free(HANDLE h) {
    int slot = (int)(h & 0xFFF);
    if (slot >= 0 && slot < MAX_WIN_HANDLES) g_handle_table[slot] = -1;
}

static int initialized = 0;
static void ensure_handles(void) {
    if (!initialized) {
        handle_table_init();
        initialized = 1;
    }
}

// Path conversion helpers (also exposed in ntll.h)
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
    } else if (strncmp(nt_path, "C:", 2) == 0) {
        snprintf(buffer, sizeof(buffer), "%s/drive_c/%s", system_root, nt_path + 3);
    } else {
        snprintf(buffer, sizeof(buffer), "%s", nt_path);
    }

    for (char* p = buffer; *p; p++) {
        if (*p == '\\') *p = '/';
    }

    if (max_len <= 0) return -1;
    strncpy(unix_path, buffer, (size_t)max_len - 1);
    unix_path[max_len - 1] = '\0';
    return 0;
}

int unix_to_nt_path(const char* unix_path, char* nt_path, int max_len) {
    const char* system_root = nt_get_system_root();
    size_t sr_len = strlen(system_root);

    if (strncmp(unix_path, system_root, sr_len) == 0 &&
        unix_path[sr_len] == '/') {
        if (strncmp(unix_path + sr_len + 1, "drive_c", 7) == 0) {
            snprintf(nt_path, (size_t)max_len, "C:\\%s", unix_path + sr_len + 9);
        } else if (strncmp(unix_path + sr_len + 1, "drive_d", 7) == 0) {
            snprintf(nt_path, (size_t)max_len, "D:\\%s", unix_path + sr_len + 9);
        } else {
            snprintf(nt_path, (size_t)max_len, "\\%s", unix_path + sr_len + 1);
        }
    } else if (unix_path[0] == '/') {
        /* host mounts (D: -> /, ...) */
        char m[1024];
        int mapped = 0;
        for (char d = 'a'; d <= 'z' && !mapped; d++) {
            if (nt_mount_lookup(d, m, sizeof(m)) != 0) continue;
            size_t ml = strlen(m);
            int root_mount = (ml == 1 && m[0] == '/');
            if (strncmp(unix_path, m, ml) == 0 &&
                (root_mount || unix_path[ml] == '/' || unix_path[ml] == '\0')) {
                const char* rest = root_mount ? unix_path + ml : (unix_path[ml] ? unix_path + ml + 1 : "");
                snprintf(nt_path, (size_t)max_len, "%c:\\%s", (char)(d - 'a' + 'A'), rest);
                mapped = 1;
            }
        }
        if (!mapped) {
            snprintf(nt_path, (size_t)max_len, "%s", unix_path);
        }
    } else {
        snprintf(nt_path, (size_t)max_len, "%s", unix_path);
    }

    for (char* p = nt_path; *p; p++) {
        if (*p == '/') *p = '\\';
    }
    return 0;
}

const char* nt_get_system_root(void)  { return "/var/lib/lsw/root"; }
const char* nt_get_windows_dir(void)  { return "/var/lib/lsw/root/Windows"; }
const char* nt_get_system32_dir(void) { return "/var/lib/lsw/root/Windows/System32"; }

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
    return handle_alloc(fd);
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
    if (S_ISDIR(st.st_mode)) return 0x10; // FILE_ATTRIBUTE_DIRECTORY
    return 0x80; // FILE_ATTRIBUTE_NORMAL
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
    fwrite(buf, 1, len, stdout);
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
}