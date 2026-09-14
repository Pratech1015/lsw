// ntdll.c - ntdll.dll implementations for LSW/NTLL
// Copyright (c) 2026 LSW Contributors

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntll.h"

// Heap management (bump allocator backed by virtual memory)
void* RtlAllocateHeap(HANDLE heap, DWORD flags, SIZE_T size) {
    (void)heap; (void)flags;
    return ntll_heap_alloc(size);
}

BOOL RtlFreeHeap(HANDLE heap, DWORD flags, void* mem) {
    (void)heap; (void)flags;
    ntll_heap_free(mem);
    return TRUE;
}

HANDLE GetProcessHeap(void) {
    static HANDLE heap = (HANDLE)0x100;
    return heap;
}

void* LocalAlloc(DWORD flags, SIZE_T size) {
    (void)flags;
    return malloc(size);
}

void* LocalFree(void* mem) {
    free(mem);
    return NULL;
}

void* LocalAllocEx(void* heap, DWORD flags, SIZE_T size) {
    (void)heap; (void)flags;
    return malloc(size);
}

// Character classification helpers used by CRT str... functions
BOOL IsProcessorFeaturePresent(DWORD feature) {
    (void)feature;
    return FALSE;
}

// Rtl functions used by CRT
void RtlZeroMemory(void* dest, SIZE_T len) {
    memset(dest, 0, len);
}

void RtlCopyMemory(void* dest, const void* src, SIZE_T len) {
    memcpy(dest, src, len);
}

void RtlMoveMemory(void* dest, const void* src, SIZE_T len) {
    memmove(dest, src, len);
}

int RtlCompareMemory(const void* a, const void* b, SIZE_T len) {
    return (int)memcmp(a, b, len);
}

void RtlFillMemory(void* dest, SIZE_T len, BYTE fill) {
    memset(dest, fill, len);
}

HANDLE GetCurrentProcess(void) {
    return (HANDLE)(uintptr_t)win32_get_current_process_id();
}

HANDLE GetCurrentThread(void) {
    return (HANDLE)(uintptr_t)win32_get_current_thread_id();
}

DWORD GetProcessId(HANDLE process) {
    (void)process;
    return win32_get_current_process_id();
}

// Requestor privilege enable/disable (mostly no-op)
BOOL EnableDisablePrivilege(HANDLE token, const char* name, BOOL enable) {
    (void)token; (void)name; (void)enable;
    return TRUE;
}

// Versioning from GetVersionEx
BOOL GetVersionExA(void* lpvi) {
    // OSVERSIONINFOEXA
    char* p = (char*)lpvi;
    DWORD dwOSVersionInfoSize = *(DWORD*)p;
    memset(p, 0, (size_t)dwOSVersionInfoSize);
    const NTLL_OS_VERSION* v = nt_get_os_version();
    ((DWORD*)(p + 4))[0] = v->major;   // dwMajorVersion
    ((DWORD*)(p + 8))[0] = v->minor;   // dwMinorVersion
    ((DWORD*)(p + 12))[0] = v->build;  // dwBuildNumber
    ((DWORD*)(p + 16))[0] = v->platform_id;
    snprintf(p + 20, 128, "Service Pack 0"); // szCSDVersion
    return TRUE;
}

// GetVersionExW - same layout
BOOL GetVersionExW(void* lpvi) {
    return GetVersionExA(lpvi);
}

// Hex dump helper (useful for debugging)
void ntll_hexdump(const void* data, size_t len) {
    const unsigned char* p = data;
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(stderr, "  %04zx: ", i);
        fprintf(stderr, "%02x ", p[i]);
        if (i % 16 == 15) fprintf(stderr, "\n");
    }
    if (len % 16) fprintf(stderr, "\n");
}