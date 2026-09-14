#ifndef NTLL_WIN32_TYPES_H
#define NTLL_WIN32_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef int8_t      INT8;
typedef uint8_t     UINT8;
typedef int16_t     INT16;
typedef uint16_t    UINT16;
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

typedef DWORD       HANDLE;
typedef HANDLE*     PHANDLE;
typedef DWORD       HINSTANCE;
typedef DWORD       HMODULE;
typedef DWORD       HWND;
typedef DWORD       HDC;
typedef DWORD       HKEY;
typedef DWORD       HGDIOBJ;
typedef DWORD       HBRUSH;
typedef DWORD       HFONT;
typedef DWORD       HPEN;
typedef DWORD       HBITMAP;
typedef DWORD       HICON;
typedef DWORD       HCURSOR;
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
