#ifndef NTLL_WIN32_TYPES_H
#define NTLL_WIN32_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

typedef unsigned int  UINT;
typedef wint_t        WINT_T;

typedef int8_t      INT8;
typedef uint8_t     UINT8;
typedef int16_t     INT16;
typedef int16_t     SHORT;
typedef uint16_t    UINT16;
typedef uint16_t    USHORT;
typedef int32_t     INT32;
typedef uint32_t    UINT32;
typedef int64_t     INT64;
typedef uint64_t    UINT64;

typedef int32_t     LONG;
typedef uint32_t    ULONG;
typedef int64_t     LONGLONG;
typedef uint64_t    ULONGLONG;

/* 64-bit alias types */
typedef uint64_t    DWORD64;
typedef int64_t     LONG64;
typedef ULONGLONG   DWORDLONG;

typedef int32_t     BOOL;
typedef uint32_t    DWORD;
typedef uint16_t    WORD;
typedef uint8_t     BYTE;
typedef uint8_t     BOOLEAN;

typedef void*       PVOID;
typedef void*       LPVOID;
typedef const void* LPCVOID;
typedef char*       LPSTR;
typedef const char* LPCSTR;
typedef wchar_t*    LPWSTR;
typedef const wchar_t* LPCWSTR;

typedef void*       HANDLE;
typedef HANDLE*     PHANDLE;
typedef void*       HINSTANCE;
typedef void*       HMODULE;
typedef void*       HWND;
typedef void*       HDC;
typedef void*       HKEY;
typedef void*       HGDIOBJ;
typedef void*       HBRUSH;
typedef void*       HFONT;
typedef void*       HPEN;
typedef void*       HBITMAP;
typedef void*       HICON;
typedef void*       HCURSOR;
typedef DWORD       HRESULT;

typedef LONG*       PLONG;
typedef ULONG*      PULONG;
typedef ULONG*      PULONG_PTR;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    };
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef uintptr_t   ULONG_PTR;
typedef intptr_t    LONG_PTR;
typedef ULONG_PTR   SIZE_T;
typedef LONG_PTR    SSIZE_T;
typedef SIZE_T*     PSIZE_T;

typedef struct _COORD {
    SHORT X;
    SHORT Y;
} COORD;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME;

typedef struct _SRWLOCK {
    PVOID Ptr;
} SRWLOCK;

typedef struct _RTL_CRITICAL_SECTION {
    PVOID DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION;

typedef struct _CONTEXT {
    ULONG_PTR Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp;
    ULONG_PTR R8, R9, R10, R11, R12, R13, R14, R15;
    ULONG_PTR Rip;
    ULONG_PTR RFlags;
} CONTEXT;

typedef unsigned short WCHAR;
typedef WCHAR* BSTR;

#define TRUE  1
#define FALSE 0
#define NULL_PTR ((void*)0)

#define CALLBACK    __attribute__((ms_abi))
#define WINAPI      __attribute__((ms_abi))
#define APIENTRY    __attribute__((ms_abi))
#define WINBASEAPI  __attribute__((ms_abi))

#define __stdcall   __attribute__((ms_abi))
#define __cdecl     __attribute__((ms_abi))
#define __fastcall  __attribute__((ms_regcall))

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)
#endif

#ifndef INFINITE
#define INFINITE 0xFFFFFFFF
#endif

#endif
