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

void* LocalAllocEx(void* heap, DWORD flags, SIZE_T size) {
    (void)heap; (void)flags;
    return malloc(size);
}

LONG RtlDisownModuleHeapAllocation(HANDLE heap, void* address) {
    (void)heap; (void)address;
    return 0; /* STATUS_SUCCESS */
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
}// ntdll extensions — Nt*/Rtl* for real cmd.exe support

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <wchar.h>
#include <pthread.h>

#include "ntll.h"

// ── Nt* syscalls ───────────────────────────────────────────────

NTSTATUS NtCancelSynchronousIoFile(HANDLE h, void* apc, void* iosb) {
    (void)h; (void)apc;
    if (iosb) memset(iosb, 0, sizeof(IO_STATUS_BLOCK));
    return 0xC0000004;  // STATUS_NOT_SUPPORTED
}

NTSTATUS NtFsControlFile(HANDLE h, void* ev, void* apc, void* iosb,
                         DWORD ctrl, void* in, DWORD insz, void* out, DWORD outsz) {
    (void)h; (void)ev; (void)apc; (void)ctrl;
    (void)in; (void)insz; (void)out; (void)outsz;
    if (iosb) memset(iosb, 0, sizeof(IO_STATUS_BLOCK));
    return 0xC0000004;
}

NTSTATUS NtOpenFile(PHANDLE handle, DWORD access, void* obj, void* iosb,
                    DWORD sharing, DWORD attrs) {
    (void)access; (void)obj; (void)sharing; (void)attrs;
    if (iosb) memset(iosb, 0, sizeof(IO_STATUS_BLOCK));
    *handle = (HANDLE)(uintptr_t)-1;
    return 0xC0000004;
}

NTSTATUS NtOpenProcessToken(HANDLE proc, DWORD access, PHANDLE tok) {
    (void)proc; (void)access;
    static int fake_token = 0;
    *tok = (HANDLE)&fake_token;
    return 0;
}

NTSTATUS NtOpenThreadToken(HANDLE thread, DWORD access, BOOL self, PHANDLE tok) {
    (void)thread; (void)access; (void)self;
    static int fake_token2 = 0;
    *tok = (HANDLE)&fake_token2;
    return 0;
}

NTSTATUS NtQueryInformationToken(HANDLE tok, int cls, void* buf,
                                 DWORD len, DWORD* retlen) {
    (void)tok; (void)cls;
    if (buf && len >= 4) memset(buf, 0, len);
    if (retlen) *retlen = 4;
    return 0;
}

NTSTATUS NtQueryVolumeInformationFile(HANDLE h, void* iosb, void* info,
                                      DWORD len, int cls) {
    (void)h; (void)cls;
    if (iosb) memset(iosb, 0, sizeof(IO_STATUS_BLOCK));
    if (info && len >= 16) memset(info, 0, len);
    return 0;
}

NTSTATUS NtSetInformationFile(HANDLE h, void* iosb, void* info,
                              DWORD len, int cls) {
    (void)h; (void)info; (void)len; (void)cls;
    if (iosb) memset(iosb, 0, sizeof(IO_STATUS_BLOCK));
    return 0;
}

NTSTATUS NtSetInformationProcess(HANDLE h, int cls, void* info, DWORD len) {
    (void)h; (void)cls; (void)info; (void)len;
    return 0;
}

NTSTATUS NtQueryInformationProcess(HANDLE h, int cls, void* buf,
                                   DWORD len, DWORD* retlen) {
    (void)h; (void)cls;
    if (buf && len >= 4) memset(buf, 0, len);
    if (retlen) *retlen = 4;
    return 0;
}

// ── Rtl* helpers ───────────────────────────────────────────────

void RtlCaptureContext(CONTEXT* ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(CONTEXT));
    /* Capture the actual register state so SEH unwind has valid data */
    __asm__ __volatile__ (
        "mov %%rax, %0\n\t"  "mov %%rbx, %1\n\t"
        "mov %%rcx, %2\n\t"  "mov %%rdx, %3\n\t"
        "mov %%rsi, %4\n\t"  "mov %%rdi, %5\n\t"
        "mov %%rbp, %6\n\t"  "mov %%rsp, %7\n\t"
        : "=m"(ctx->Rax), "=m"(ctx->Rbx), "=m"(ctx->Rcx), "=m"(ctx->Rdx),
          "=m"(ctx->Rsi), "=m"(ctx->Rdi), "=m"(ctx->Rbp), "=m"(ctx->Rsp)
        : : "memory");
    /* RIP = return address of caller */
    ctx->Rip = (ULONG_PTR)__builtin_return_address(0);
}

void RtlVirtualUnwind(DWORD type, ULONGLONG base, ULONGLONG pc,
                      void* ctx) {
    (void)type; (void)base; (void)pc; (void)ctx;
}

void* RtlLookupFunctionEntry(ULONGLONG pc, ULONGLONG* base, void* unwind) {
    (void)pc; (void)base; (void)unwind;
    return NULL;
}

DWORD64 RtlFindLeastSignificantBit(ULONGLONG v) {
    if (v == 0) return 64;
    DWORD64 r = 0;
    while ((v & 1) == 0) { v >>= 1; r++; }
    return r;
}

ULONG RtlNtStatusToDosError(NTSTATUS st) {
    if ((int)st >= 0) return (ULONG)st;
    return 1;  // ERROR_INVALID_FUNCTION
}

void RtlCreateUnicodeStringFromAsciiz(void* dst, const char* src) {
    UNICODE_STRING* us = (UNICODE_STRING*)dst;
    if (!src) { us->Length = 0; us->Buffer = NULL; return; }
    size_t len = strlen(src);
    us->Buffer = (wchar_t*)calloc(len + 1, sizeof(wchar_t));
    mbstowcs(us->Buffer, src, len);
    us->Length = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
}

NTSTATUS RtlDosPathNameToNtPathName_U(const wchar_t* dos, void* nt,
                                       void* part, void* rel) {
    (void)part; (void)rel;
    // Minimal: just copy the path as-is (forward slash)
    UNICODE_STRING* us = (UNICODE_STRING*)nt;
    if (!dos) { us->Length = 0; us->Buffer = NULL; return 0; }
    size_t len = wcslen(dos);
    us->Buffer = (wchar_t*)calloc(len + 1, sizeof(wchar_t));
    wcscpy(us->Buffer, dos);
    us->Length = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    return 0;
}

NTSTATUS RtlDosPathNameToRelativeNtPathName_U_WithStatus(const wchar_t* dos,
                                                          void* nt,
                                                          void* part, void* rel) {
    return RtlDosPathNameToNtPathName_U(dos, nt, part, rel);
}

void RtlFreeUnicodeString(void* us_ptr) {
    UNICODE_STRING* us = (UNICODE_STRING*)us_ptr;
    if (us && us->Buffer) { free(us->Buffer); us->Buffer = NULL; }
}

void RtlReleaseRelativeName(void* rel) { (void)rel; }

// Feature configuration (stub - not supported)
typedef struct _FEATURE_CONFIGURATION { ULONG dummy; } FEATURE_CONFIGURATION;
typedef struct _FEATURE_CONFIGURATION_CHANGE_REGISTRATION { ULONG dummy; } FEATURE_CONFIGURATION_CHANGE_REGISTRATION;

NTSTATUS RtlRegisterFeatureConfigurationChangeNotification(
    const FEATURE_CONFIGURATION_CHANGE_REGISTRATION* reg, void* token, void* callback, void* context, uint64_t* handle) {
    (void)reg; (void)token; (void)callback; (void)context;
    if (handle) *handle = 0;
    return 0;
}

NTSTATUS RtlQueryFeatureConfiguration(
    ULONG sub_group_count, void* sub_group, ULONG feature_count, void* features, ULONG* return_count) {
    (void)sub_group_count; (void)sub_group; (void)feature_count; (void)features;
    if (return_count) *return_count = 0;
    return 0;
}

BOOL RtlDllShutdownInProgress(void) { return FALSE; }

// WIL (Windows Implementation Libraries) error notification stub
void WilFailureNotifyWatchers(void* params) { (void)params; }
void LogStagedFeatureUsage(void* a, void* b, void* c) { (void)a; (void)b; (void)c; }
