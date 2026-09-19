// ucrtbase.c - UCRT (Universal C Runtime) stubs for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Provides the api-ms-win-crt-* function surface so that real Windows
// executables can resolve their CRT imports.  Most functions are thin
// wrappers around the POSIX/libc equivalents.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <setjmp.h>
#include <ctype.h>
#include <wctype.h>
#include <sys/stat.h>

#include "ntll.h"

extern char** environ;

// ────────────────────────────────────────────────────────────────
// stdio
// ────────────────────────────────────────────────────────────────

FILE* _o___acrt_iob_func(int fd) {
    if (fd < 0 || fd > 2) return NULL;
    return (fd == 0) ? stdin : (fd == 1) ? stdout : stderr;
}

// Minimal printf/scanf emulation over the MS x64 varargs area.
// Windows callers pass a pointer to the first stack argument slot; we
// reinterpret it as an array of uintptr_t slots (the next 4 integer
// register-spilled args were pushed on the stack by the Windows ABI
// homing area before any stack slots, so integers accessed through the
// pointer are the first implicit-stack ones; register-homed values are
// handled by reading the slots that the caller spilled).

static int utf16le_to_utf8(const void* wide_, char* narrow, size_t max_out) {
    const uint16_t* wide = (const uint16_t*)wide_;
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
static int utf8_to_utf16le(const char* narrow, void* wide_, size_t max_out) {
    uint16_t* wide = (uint16_t*)wide_;
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

static int mini_vsnprintf_ex(char* buf, size_t bufsz, const char* fmt, const uintptr_t* a, int wide_args) {
    if (!a) { if (buf && bufsz > 0) buf[0] = 0; return 0; }
    size_t o = 0;
    int ai = 0;
    const char* p = fmt;
    char tmp[64];
    while (*p) {
        if (*p != '%') {
            if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = *p;
            else o++;
            p++;
            continue;
        }
        p++;
        if (*p == '%') {
            if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = '%';
            else o++;
            p++;
            continue;
        }
        int width = 0, prec = -1;
        while (*p >= '0' && *p <= '9') { width = width * 10 + (*p - '0'); p++; }
        if (*p == '.') { p++; prec = 0; while (*p >= '0' && *p <= '9') { prec = prec * 10 + (*p - '0'); p++; } }
        char conv = *p ? *p++ : 0;
        uintptr_t v = a[ai++];
        size_t slot = 0;
        if (conv == 's' || conv == 'S' || conv == 'l') {
            const char* s;
            int is_wide = (conv == 'S') || wide_args;
            if (conv == 'l') {
                char next = *p;
                if (next == 's' || next == 'S') { p++; is_wide = 1; }
                else { is_wide = 1; }
            }
            if (is_wide) {
                static char cache[4096]; utf16le_to_utf8((const void*)v, cache, sizeof(cache));
                s = cache;
            } else {
                s = (const char*)v;
                if (!s) s = "(null)";
            }
            int n = 0;
            if (prec >= 0) n = (int)strnlen(s, (size_t)prec); else n = (int)strlen(s);
            for (int i = 0; i < n; i++) {
                if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = s[i];
                else o++;
            }
            continue;
        }
        if (conv == 'c') {
            if (wide_args) {
                uint16_t wc = (uint16_t)(v & 0xFFFF);
                if (wc < 0x80) {
                    if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = (char)wc;
                    else o++;
                }
            } else {
                char c = (char)(v & 0xFF);
                if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = c;
                else o++;
            }
            continue;
        }
        switch (conv) {
            case 'd': case 'i': case 'u':
                if (conv != 'u' && (long long)(intptr_t)v < 0)
                    v = (uintptr_t)-(long long)(intptr_t)v;
                if (conv != 'u' && (long long)(intptr_t)v < 0) {
                    /* impossible path */
                }
                if (conv == 'u' || (long long)(intptr_t)v >= 0)
                    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
                else
                    snprintf(tmp, sizeof(tmp), "-%llu", (unsigned long long)(uintptr_t)-(long long)(intptr_t)v);
                break;
            case 'x': snprintf(tmp, sizeof(tmp), "%llx", (unsigned long long)v); break;
            case 'X': snprintf(tmp, sizeof(tmp), "%llX", (unsigned long long)v); break;
            case 'o': snprintf(tmp, sizeof(tmp), "%llo", (unsigned long long)v); break;
            case 'p': snprintf(tmp, sizeof(tmp), "%llx", (unsigned long long)v); break;
            default: tmp[0] = conv; tmp[1] = 0; break;
        }
        (void)width; (void)prec; (void)slot;
        for (char* q = tmp; *q; q++) {
            if (buf && bufsz > 0 && o + 1 < bufsz) buf[o++] = *q;
            else o++;
        }
    }
    if (buf && bufsz > 0) buf[o < bufsz ? o : bufsz - 1] = 0;
    return (int)o;
}
static int mini_vsnprintf(char* buf, size_t bufsz, const char* fmt, const uintptr_t* a) {
    return mini_vsnprintf_ex(buf, bufsz, fmt, a, 0);
}

static int mini_vswprintf(wchar_t* buf, size_t len, const wchar_t* fmt, const uintptr_t* a) {
    char fbuf[4096], obuf[8192];
    if (!fmt || !fmt[0]) { if (buf && len > 0) buf[0] = 0; return 0; }
    int conv = utf16le_to_utf8((const void*)fmt, fbuf, sizeof(fbuf));
    if (conv < 0) return -1;
    int n = mini_vsnprintf_ex(obuf, sizeof(obuf), fbuf, a, 1);
    if (n < 0) return n;
    if (buf && len > 0) utf8_to_utf16le(obuf, (void*)buf, len);
    return n;
}

int _o___stdio_common_vfprintf(unsigned long long opts, FILE* f,
                               const char* fmt, void* locale, void* args) {
    (void)opts; (void)locale;
    char buf[8192];
    int n = mini_vsnprintf(buf, sizeof(buf), fmt ? fmt : "", (const uintptr_t*)args);
    if (n >= 0 && f) fwrite(buf, 1, (size_t)n, f);
    return n;
}

int _o___stdio_common_vswprintf(unsigned long long opts, wchar_t* buf,
                                size_t len, const wchar_t* fmt, void* locale, void* args) {
    (void)opts; (void)locale;
    if (!fmt) fmt = L"";
    int n = mini_vswprintf(buf, len, fmt, (const uintptr_t*)args);
    return n;
}

int _o___stdio_common_vswprintf_s(unsigned long long opts, wchar_t* buf,
                                  size_t len, const wchar_t* fmt, void* locale, void* args) {
    (void)opts; (void)locale;
    return mini_vswprintf(buf, len, fmt ? fmt : L"", (const uintptr_t*)args);
}

int _o___stdio_common_vswscanf(unsigned long long opts, const wchar_t* buf,
                               size_t len, const wchar_t* fmt, void* locale, void* args) {
    (void)opts; (void)buf; (void)len; (void)fmt; (void)locale; (void)args;
    return 0;
}

int _o_feof(FILE* f) { return feof(f); }
int _o_ferror(FILE* f) { return ferror(f); }
int _o_fflush(FILE* f) { return fflush(f); }
char* _o_fgets(char* s, int n, FILE* f) {
    char* r = fgets(s, n, f);
    return r;
}

int _o__acrt_iob_func(int fd) { return fd; }

// ────────────────────────────────────────────────────────────────
// heap / alloc
// ────────────────────────────────────────────────────────────────

void* _o_malloc(size_t n) { return malloc(n); }
void* _o_calloc(size_t n, size_t s) { return calloc(n, s); }
void* _o_realloc(void* p, size_t n) { return realloc(p, n); }
void  _o_free(void* p) { free(p); }
int _o__callnewh(size_t n) { (void)n; return 0; }

// ────────────────────────────────────────────────────────────────
// string / wchar
// ────────────────────────────────────────────────────────────────

// NOTE: Windows wide strings are UTF-16 (2-byte units). glibc's wchar_t is
// 4 bytes, so glibc allocas can never index cmd's buffers. We scan the
// buffers as 16-bit units directly; this is the fix for the wcsrchr=NULL
// SIGSEGV (dispatch slot 0x3c340) that crashed cmd's dir path colon.

#define U16_MAX 0xFFFF

static size_t u16_len(const uint16_t* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

uint16_t* u16_wcsrchr(const uint16_t* s, uint16_t c) {
    if (!s) return NULL;
    uint16_t* last = NULL;
    for (size_t i = 0; s[i]; i++)
        if (s[i] == c) last = (uint16_t*)&s[i];
    if (c == 0) return (uint16_t*)&s[u16_len(s)];
    return last;
}

uint16_t* u16_wcschr(const uint16_t* s, uint16_t c) {
    if (!s) return NULL;
    for (size_t i = 0; s[i]; i++)
        if (s[i] == c) return (uint16_t*)&s[i];
    if (c == 0) return (uint16_t*)&s[u16_len(s)];
    return NULL;
}

uint16_t* u16_wcsstr(const uint16_t* h, const uint16_t* n) {
    if (!h || !n) return NULL;
    if (!n[0]) return (uint16_t*)h;
    for (size_t i = 0; h[i]; i++) {
        size_t j = 0;
        while (n[j] && h[i+j] == n[j]) j++;
        if (!n[j]) return (uint16_t*)&h[i];
    }
    return NULL;
}

int u16_wcscmp(const uint16_t* a, const uint16_t* b) {
    if (a == b) return 0;
    size_t i = 0;
    while (a[i] && a[i] == b[i]) i++;
    return (int)a[i] - (int)b[i];
}

int u16_wcsncmp(const uint16_t* a, const uint16_t* b, size_t n) {
    if (a == b) return 0;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        if (!a[i]) break;
    }
    return 0;
}

size_t u16_wcsspn(const uint16_t* s, const uint16_t* set) {
    size_t n = 0;
    while (s[n]) {
        int in = 0;
        for (size_t j = 0; set[j]; j++) if (set[j] == s[n]) { in = 1; break; }
        if (!in) break;
        n++;
    }
    return n;
}

int _o__wcsicmp(const wchar_t* a, const wchar_t* b) {
    for (size_t i = 0; ; i++) {
        uint16_t ca = (uint16_t)towlower((wint_t)((const uint16_t*)a)[i]);
        uint16_t cb = (uint16_t)towlower((wint_t)((const uint16_t*)b)[i]);
        if (ca != cb) return (int)ca - (int)cb;
        if (!ca) return 0;
    }
}
int _o__wcsnicmp(const wchar_t* a, const wchar_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint16_t ca = (uint16_t)towlower((wint_t)((const uint16_t*)a)[i]);
        uint16_t cb = (uint16_t)towlower((wint_t)((const uint16_t*)b)[i]);
        if (ca != cb) return (int)ca - (int)cb;
        if (!ca) break;
    }
    return 0;
}
wchar_t* _o__wcslwr(wchar_t* s) {
    uint16_t* p = (uint16_t*)s;
    while (*p) { *p = (uint16_t)towlower((wint_t)*p); p++; }
    return s;
}
wchar_t* _o__wcsupr(wchar_t* s) {
    uint16_t* p = (uint16_t*)s;
    while (*p) { *p = (uint16_t)towupper((wint_t)*p); p++; }
    return s;
}
long _o__wtol(const wchar_t* s) { return wcstol(s, NULL, 10); }

// ────────────────────────────────────────────────────────────────
// UTF-16 wide strings
//
// cmd.exe (and every PE) speaks UTF-16: strings are arrays of uint16_t
// (2 bytes).  glibc's wchar_t is 4 bytes, so glibc wcs* functions scan
// the buffer in the wrong unit size and never match — e.g. glibc
// wcsrchr(utf16buf, L'\\') returns NULL (whence the NULL store in
// ntll RVA 0xd6e8 / cmd's dir loop).  All wide CRT imports below are
// bound to these UTF-16 implementations instead.
// ────────────────────────────────────────────────────────────────

typedef uint16_t u16;

u16* lsw_u16_wcschr(const u16* s, u16 c) {
    if (!s) return NULL;
    while (*s) { if (*s == c) return (u16*)s; s++; }
    return c == 0 ? (u16*)s : NULL;
}
u16* lsw_u16_wcsrchr(const u16* s, u16 c) {
    if (!s) return NULL;
    const u16* last = c == 0 ? (u16*)s : NULL;
    while (*s) { if (*s == c) last = s; s++; }
    if (c == 0) return (u16*)s;
    return (u16*)last;
}
u16* lsw_u16_wcsstr(const u16* h, const u16* n) {
    if (!h || !n) return NULL;
    if (!*n) return (u16*)h;
    for (const u16* p = h; *p; p++) {
        const u16* a = p; const u16* b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return (u16*)p;
        if (!*a) break;
    }
    return NULL;
}
int lsw_u16_wcscmp(const u16* a, const u16* b) {
    if (!a || !b) return (a==b)?0:(a?1:-1);
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}
int lsw_u16_wcsncmp(const u16* a, const u16* b, size_t n) {
    if (!a || !b) return (a==b)?0:(a?1:-1);
    while (n-- && *a && *a == *b) { a++; b++; }
    return n==(size_t)-1 ? 0 : (int)*a - (int)*b;
}
size_t lsw_u16_wcsspn(const u16* s, const u16* set) {
    if (!s || !set) return 0;
    size_t i = 0;
    while (s[i]) {
        const u16* p = set; int found = 0;
        while (*p) { if (*p == s[i]) { found = 1; break; } p++; }
        if (!found) break;
        i++;
    }
    return i;
}
int lsw_u16_wcsicmp(const u16* a, const u16* b) {
    if (!a || !b) return (a==b)?0:(a?1:-1);
    while (*a && towlower((wint_t)*a) == towlower((wint_t)*b)) { a++; b++; }
    return (int)towlower((wint_t)*a) - (int)towlower((wint_t)*b);
}
int lsw_u16_wcsnicmp(const u16* a, const u16* b, size_t n) {
    if (!a || !b) return (a==b)?0:(a?1:-1);
    while (n-- && *a && towlower((wint_t)*a) == towlower((wint_t)*b)) { a++; b++; }
    return n==(size_t)-1 ? 0 : (int)towlower((wint_t)*a) - (int)towlower((wint_t)*b);
}
size_t lsw_u16_wcslen(const u16* s) {
    const u16* p = s; while (p && *p) p++; return (size_t)(p - s);
}

size_t _o__wcsftime(char* s, size_t n, const char* fmt, const struct tm* t) {
    (void)s; (void)n; (void)fmt; (void)t; return 0;
}

int _o__setmode(int fd, int mode) {
    (void)mode;
    return fd >= 0 ? 0 : -1;
}

long _o__tell(int fd) {
    return (long)lseek(fd, 0, SEEK_CUR);
}

int _o__getch(void) {
    return getchar();
}

int _o__get_osfhandle(int fd) { return fd; }
int _o__open_osfhandle(intptr_t h, int flags) {
    (void)flags;
    return (int)h;
}

int _o__dup(int fd) { return dup(fd); }
int _o__dup2(int a, int b) { return dup2(a, b); }
int _o__close(int fd) { return close(fd); }

FILE* _o__wpopen(const wchar_t* cmd, const wchar_t* mode) {
    (void)cmd; (void)mode; return NULL;
}

int _o__pclose(FILE* f) { (void)f; return -1; }

int _o__pipe(int fds[2], unsigned int size, int text_mode) {
    (void)size; (void)text_mode;
    return pipe(fds);
}

// ────────────────────────────────────────────────────────────────
// locale / environment
// ────────────────────────────────────────────────────────────────

char* _o_setlocale(int cat, const char* locale) { return setlocale(cat, locale); }
int _o__configthreadlocale(int flag) { (void)flag; return 0; }
int _o__configure_narrow_argv(int mode) {
    fprintf(stderr, "[trace] _o__configure_narrow_argv mode=%d\n", mode);
    return 0;
}
int _o__initialize_narrow_environment(void) {
    fprintf(stderr, "[trace] _o__initialize_narrow_environment\n");
    return 0;
}

char** _o__get_initial_narrow_environment(void) { return environ; }

char*** _o___p__environ(void) { return &environ; }
char* _o__get_home_dir(void) {
    const char* h = getenv("HOME");
    return h ? (char*)h : "/";
}

int* _o___p___argc(void) {
    static int fake_argc = 1;
    fprintf(stderr, "[trace] _o___p___argc returning argc=%d\n", fake_argc);
    return &fake_argc;
}

char*** _o___p___argv(void) {
    static char* argv0[] = { "cmd.exe", NULL };
    static char** fake_argv[2] = { argv0, NULL };
    fprintf(stderr, "[trace] _o___p___argv returning argv[0]='%s'\n", fake_argv[0] ? fake_argv[0][0] : "(null)");
    return fake_argv;
}

char* _o___p__commode(void) {
    static char commode = '\0';
    return &commode;
}

// ────────────────────────────────────────────────────────────────
// exit / atexit
// ────────────────────────────────────────────────────────────────

void _o__cexit(void) { }
void _o__c_exit(void) { }
void _c_exit(void) { }
void _o_exit(int c) {
    fprintf(stderr, "[exit] _o_exit(%d) caller=%p\n", c, __builtin_return_address(0));
    exit(c);
}
void _o__exit(int c) { _exit(c); }
int  _o__crt_atexit(void (*func)(void)) { return atexit(func); }
void _o_terminate(void) { abort(); }
void _o__purecall(void) { abort(); }
void _o__invalid_parameter_noinfo(void) { }
int  _o__seh_filter_exe(int c, void* e) { (void)c; (void)e; return 0; }

// ────────────────────────────────────────────────────────────────
// error
// ────────────────────────────────────────────────────────────────

int* _o__errno(void) { return &errno; }

// ────────────────────────────────────────────────────────────────
// conversions
// ────────────────────────────────────────────────────────────────

long _o_wcstol(const wchar_t* s, wchar_t** e, int b) { return wcstol(s, e, b); }
unsigned long _o_wcstoul(const wchar_t* s, wchar_t** e, int b) { return wcstoul(s, e, b); }

char* _o__ultoa(unsigned long v, char* b, int r) {
    snprintf(b, 33, "%lu", v); (void)r; return b;
}
char* _o__ultoa_s(unsigned long v, char* b, size_t sz, int r) {
    (void)r;
    snprintf(b, sz, "%lu", v);
    return b;
}

// ────────────────────────────────────────────────────────────────
// misc CRT
// ────────────────────────────────────────────────────────────────

void _o_qsort(void* base, size_t n, size_t s,
              int (*cmp)(const void*, const void*)) { qsort(base, n, s, cmp); }
int _o_rand(void) { return rand(); }
void _o_srand(unsigned int s) { srand(s); }
int _o__set_app_type(int t) {
    fprintf(stderr, "[trace] _o__set_app_type type=%d\n", t);
    (void)t; return 0;
}
void _o__set_fmode(int m) { (void)m; }
void _o__set_new_mode(int m) { (void)m; }

// ────────────────────────────────────────────────────────────────
// onexit / init
// ────────────────────────────────────────────────────────────────

void _o__initialize_onexit_table(void* t) { (void)t; }
int _o__register_onexit_function(void* t, void* f) { (void)t; (void)f; return 0; }
int _register_thread_local_exe_atexit_callback(void* a) { (void)a; return 0; }

// CRT init - called before main; safe no-ops
void _initterm(void** s, void** e) {
    fprintf(stderr, "[trace] _initterm s=%p e=%p count=%d\n", (void*)s, (void*)e, (int)(e - s));
    if (s && e) {
        for (void** p = s; p < e; p++) {
            if (*p && *p != (void*)0xcc) {
                fprintf(stderr, "[trace] _initterm calling %p\n", *p);
                void (*fn)(void) = (void(*)(void))*p;
                fn();
            }
        }
    }
}
int  _initterm_e(void** s, void** e) {
    fprintf(stderr, "[trace] _initterm_e s=%p e=%p count=%d\n", (void*)s, (void*)e, (int)(e - s));
    if (s && e) {
        for (void** p = s; p < e; p++) {
            if (*p && *p != (void*)0xcc) {
                fprintf(stderr, "[trace] _initterm_e calling %p\n", *p);
                int (*fn)(void) = (int(*)(void))*p;
                int r = fn();
                if (r != 0) return r;
            }
        }
    }
    return 0;
}

// ────────────────────────────────────────────────────────────────
// SEH / exception
// ────────────────────────────────────────────────────────────────

typedef void* EXCEPTION_RECORD;
typedef void* DISPATCHER_CONTEXT;
typedef int EXCEPTION_DISPOSITION;
#define ExceptionContinueSearch 0

// Windows SEH - provide minimal stubs
EXCEPTION_DISPOSITION __C_specific_handler(
    EXCEPTION_RECORD* rec, void* frame, CONTEXT* ctx, DISPATCHER_CONTEXT* disp) {
    (void)rec; (void)frame; (void)ctx; (void)disp;
    return ExceptionContinueSearch;
}

EXCEPTION_RECORD** __current_exception(void) {
    static EXCEPTION_RECORD* s_rec = NULL;
    return &s_rec;
}

CONTEXT** __current_exception_context(void) {
    static CONTEXT* s_ctx = NULL;
    return &s_ctx;
}

int __CxxFrameHandler3(void* r, void* h, void* c, void* d) {
    (void)r; (void)h; (void)c; (void)d;
    return 0;
}

void _CxxThrowException(void* obj, void* t) {
    (void)obj; (void)t;
}

void _local_unwind(void* f, void* d) { (void)f; (void)d; }

/* ms_abi implementations of __intrinsic_setjmp/longjmp that bypass
   trampolines and glibc entirely, using MSVC's _JUMP_BUFFER layout:
     0x00 Frame (rsp), 0x08 Rbx, 0x10 Rsp(rsp+8), 0x18 Rbp,
     0x20 Rsi, 0x28 Rdi, 0x30 R12, 0x38 R13, 0x40 R14, 0x48 R15, 0x50 Rip */
__attribute__((ms_abi, naked)) int ms_setjmp(void* j) {
    __asm__ __volatile__(
        "movq %%rsp, 0x00(%%rcx)\n\t"   /* Frame */
        "movq %%rbx, 0x08(%%rcx)\n\t"
        "leaq 8(%%rsp), %%rax\n\t"
        "movq %%rax, 0x10(%%rcx)\n\t"   /* Rsp = caller rsp after call ret */
        "movq %%rbp, 0x18(%%rcx)\n\t"
        "movq %%rsi, 0x20(%%rcx)\n\t"
        "movq %%rdi, 0x28(%%rcx)\n\t"
        "movq %%r12, 0x30(%%rcx)\n\t"
        "movq %%r13, 0x38(%%rcx)\n\t"
        "movq %%r14, 0x40(%%rcx)\n\t"
        "movq %%r15, 0x48(%%rcx)\n\t"
        "movq (%%rsp), %%rax\n\t"
        "movq %%rax, 0x50(%%rcx)\n\t"   /* Rip = return address */
        "xorl %%eax, %%eax\n\t"         /* return 0 */
        "ret\n\t"
        : : : "memory");
    __builtin_unreachable();
}

__attribute__((ms_abi, naked, noreturn)) void ms_longjmp(void* j, int v) {
    __asm__ __volatile__(
        "movl %%edx, %%eax\n\t"         /* eax = v */
        "testl %%eax, %%eax\n\t"
        "jnz 1f\n\t"
        "movl $1, %%eax\n\t"            /* longjmp must return non-zero */
        "1:\n\t"
        "movq 0x08(%%rcx), %%rbx\n\t"
        "movq 0x10(%%rcx), %%rsp\n\t"   /* Rsp */
        "movq 0x18(%%rcx), %%rbp\n\t"
        "movq 0x20(%%rcx), %%rsi\n\t"
        "movq 0x28(%%rcx), %%rdi\n\t"
        "movq 0x30(%%rcx), %%r12\n\t"
        "movq 0x38(%%rcx), %%r13\n\t"
        "movq 0x40(%%rcx), %%r14\n\t"
        "movq 0x48(%%rcx), %%r15\n\t"
        "jmp *0x50(%%rcx)\n\t"          /* jump to saved Rip */
        : : : "memory");
    __builtin_unreachable();
}

// ────────────────────────────────────────────────────────────────
// CRT wchar / ctype
// ────────────────────────────────────────────────────────────────

wint_t _o_iswalpha(wint_t c) { return iswalpha(c); }
wint_t _o_iswdigit(wint_t c) { return iswdigit(c); }
wint_t _o_iswspace(wint_t c) { return iswspace(c); }
wint_t _o_iswxdigit(wint_t c) { return iswxdigit(c); }
wint_t _o_towlower(wint_t c) { return towlower(c); }
wint_t _o_towupper(wint_t c) { return towupper(c); }

// ────────────────────────────────────────────────────────────────
// CRT exception support
// ────────────────────────────────────────────────────────────────

void _o___std_exception_copy(void* src, void* dst) {
    if (src && dst) memcpy(dst, src, 16);
}
void _o___std_exception_destroy(void* obj) { (void)obj; }

// ────────────────────────────────────────────────────────────────
// time
// ────────────────────────────────────────────────────────────────

time_t _time32(time_t* t) {
    time_t now = time(NULL);
    if (t) *t = now;
    return now;
}

// ────────────────────────────────────────────────────────────────
// printf / scan format dispatch
// ────────────────────────────────────────────────────────────────

int _o___stdio_common_vsprintf(unsigned long long opts, char* buf, size_t sz,
                               const char* fmt, void* locale, void* args) {
    (void)opts; (void)locale;
    if (!buf || sz == 0) return mini_vsnprintf(NULL, 0, fmt ? fmt : "", (const uintptr_t*)args);
    return mini_vsnprintf(buf, sz, fmt ? fmt : "", (const uintptr_t*)args);
}

int _o___stdio_common_vsscanf(unsigned long long opts, const char* buf,
                              size_t sz, const char* fmt, void* locale, void* args) {
    (void)opts; (void)buf; (void)sz; (void)fmt; (void)locale; (void)args;
    return 0;
}

// ────────────────────────────────────────────────────────────────
// UTF-16 wide-string layer for Windows CRT imports
// ────────────────────────────────────────────────────────────────
// Windows wchar_t = 2 bytes (UTF-16). glibc wchar_t = 4 bytes.
// glibc wcs* mis-scans Windows wide strings; cmd crashes at
// RVA 0xd6e8 (mov %bx,(%rax)) because wcsrchr returns NULL.
// These implementations operate on 16-bit units.

size_t lsw_utf16_wcslen(const unsigned short* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

unsigned short* lsw_utf16_wcschr(const unsigned short* s, unsigned short c) {
    while (*s) { if (*s == c) return (unsigned short*)s; s++; }
    return c == 0 ? (unsigned short*)s : NULL;
}

unsigned short* lsw_utf16_wcsrchr(const unsigned short* s, unsigned short c) {
    const unsigned short* last = NULL;
    if (!c) { while (*s) s++; return (unsigned short*)s; }
    while (*s) { if (*s == c) last = s; s++; }
    return (unsigned short*)last;
}

unsigned short* lsw_utf16_wcsstr(const unsigned short* h, const unsigned short* n) {
    if (!n || !*n) return (unsigned short*)h;
    for (const unsigned short* p = h; *p; p++) {
        const unsigned short* a = p; const unsigned short* b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return (unsigned short*)p;
        if (!*a) break;
    }
    return NULL;
}

int lsw_utf16_wcscmp(const unsigned short* a, const unsigned short* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}

int lsw_utf16_wcsncmp(const unsigned short* a, const unsigned short* b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (int)*a - (int)*b : 0;
}

size_t lsw_utf16_wcsspn(const unsigned short* s, const unsigned short* set) {
    size_t n = 0;
    while (s[n]) {
        int found = 0;
        for (const unsigned short* p = set; *p; p++) {
            if (*p == s[n]) { found = 1; break; }
        }
        if (!found) break;
        n++;
    }
    return n;
}
