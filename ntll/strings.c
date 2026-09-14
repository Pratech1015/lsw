// strings.c - string and codepage utilities for LSW/NTLL
// Copyright (c) 2026 LSW Contributors

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <time.h>

#include "ntll.h"

// Initialize a UNICODE_STRING from a wide C string
void nt_init_unicode_string(PUNICODE_STRING dst, const wchar_t* src) {
    if (!dst) return;
    if (!src) {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = NULL;
        return;
    }
    size_t len = wcslen(src);
    dst->Buffer = (wchar_t*)dst; // placeholder - caller manages memory
    dst->Length = (uint16_t)(len * sizeof(wchar_t));
    dst->MaximumLength = (uint16_t)((len + 1) * sizeof(wchar_t));
}

void nt_init_ansi_string(PANSI_STRING dst, const char* src) {
    if (!dst) return;
    if (!src) {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = NULL;
        return;
    }
    size_t len = strlen(src);
    dst->Length = (uint16_t)len;
    dst->MaximumLength = (uint16_t)(len + 1);
}

void nt_free_unicode_string(PUNICODE_STRING str) {
    (void)str;
}

void nt_free_ansi_string(PANSI_STRING str) {
    (void)str;
}

// Wide to narrow conversion (UTF-8 output)
int nt_wide_to_narrow(const wchar_t* wide, char* narrow, int max_len) {
    if (!wide || !narrow || max_len <= 0) return -1;
    size_t out = wcstombs(narrow, wide, (size_t)max_len - 1);
    if (out == (size_t)-1) {
        narrow[0] = '\0';
        return -1;
    }
    narrow[out] = '\0';
    return (int)out;
}

// Narrow to wide conversion
int nt_narrow_to_wide(const char* narrow, wchar_t* wide, int max_len) {
    if (!narrow || !wide || max_len <= 0) return -1;
    size_t out = mbstowcs(wide, narrow, (size_t)max_len - 1);
    if (out == (size_t)-1) {
        wide[0] = L'\0';
        return -1;
    }
    wide[out] = L'\0';
    return (int)out;
}

// ANSI <-> Unicode helpers
int nt_unicode_to_ansi(PUNICODE_STRING unicode, PANSI_STRING ansi) {
    if (!unicode || !ansi) return -1;
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    if (unicode->Buffer) {
        nt_wide_to_narrow(unicode->Buffer, buf, sizeof(buf));
    }
    ANSI_STRING tmp;
    tmp.Buffer = buf;
    tmp.Length = (uint16_t)strlen(buf);
    tmp.MaximumLength = (uint16_t)(tmp.Length + 1);
    *ansi = tmp;
    return 0;
}

int nt_ansi_to_unicode(PANSI_STRING ansi, PUNICODE_STRING unicode) {
    if (!ansi || !unicode) return -1;
    static wchar_t wbuf[4096];
    wbuf[0] = L'\0';
    if (ansi->Buffer) {
        nt_narrow_to_wide(ansi->Buffer, wbuf, 4096);
    }
    UNICODE_STRING tmp;
    tmp.Buffer = wbuf;
    tmp.Length = (uint16_t)(wcslen(wbuf) * sizeof(wchar_t));
    tmp.MaximumLength = (uint16_t)(tmp.Length + sizeof(wchar_t));
    *unicode = tmp;
    return 0;
}

// Filetime conversions
uint64_t nt_get_system_time_as_filetime(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t t = (uint64_t)ts.tv_sec + 11644473600LL;
    return t * 10000000 + (uint64_t)ts.tv_nsec / 100;
}

uint64_t nt_get_tick_count(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void nt_sleep(uint32_t milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

// Version information (Windows 11 defaults)
static NTLL_OS_VERSION g_os_version = {
    .major = 10,
    .minor = 0,
    .build = 22631,
    .platform_id = 2,
    .version_string = "Windows 11 Pro",
    .build_string = "22631.3155",
};

const NTLL_OS_VERSION* nt_get_os_version(void) {
    return &g_os_version;
}

void nt_set_os_version(DWORD major, DWORD minor, DWORD build) {
    g_os_version.major = major;
    g_os_version.minor = minor;
    g_os_version.build = build;
    snprintf(g_os_version.build_string, sizeof(g_os_version.build_string),
             "%u.%u,%u", (unsigned)major, (unsigned)minor, (unsigned)build);
}