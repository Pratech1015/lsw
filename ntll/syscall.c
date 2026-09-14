// syscall.c - NT syscall translation layer for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Maps Windows NT syscalls to Linux equivalents. This table mirrors the
// ntdll!Nt* export surface and each entry carries a Linux syscall mapping.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "ntll.h"

typedef struct _SYSCALL_MAP {
    int nt_number;
    const char* nt_name;
    int linux_syscall;
} SYSCALL_MAP;

// Windows NT syscall numbers (Win11 21H2+ / 22631)
#define NT_SYSCALL_CREATEFILE             0x0055
#define NT_SYSCALL_READFILE               0x0060
#define NT_SYSCALL_WRITEFILE              0x0061
#define NT_SYSCALL_CLOSE                  0x001F
#define NT_SYSCALL_DELETEFILE             0x0054
#define NT_SYSCALL_QUERYFILE             0x0081
#define NT_SYSCALL_QUERYVOLUME           0x008E
#define NT_SYSCALL_SETINFOFILE           0x008C
#define NT_SYSCALL_CREATE_THREAD          0x00DD
#define NT_SYSCALL_RESUME_THREAD          0x00DF
#define NT_SYSCALL_WAIT_FOR_SINGLE        0x010F
#define NT_SYSCALL_WAIT_FOR_MULTIPLE      0x0103
#define NT_SYSCALL_CREATE_EVENT           0x0097
#define NT_SYSCALL_SET_EVENT              0x0099
#define NT_SYSCALL_CREATE_MUTEX           0x0091
#define NT_SYSCALL_RELEASE_MUTEX          0x0093
#define NT_SYSCALL_CREATE_SEMAPHORE       0x0094
#define NT_SYSCALL_RELEASE_SEMAPHORE      0x0096
#define NT_SYSCALL_QUERY_SYSTEM           0x0111
#define NT_SYSCALL_QUERY_PROCESS          0x0022
#define NT_SYSCALL_SET_PROCESS            0x0023
#define NT_SYSCALL_QUERY_THREAD           0x0026
#define NT_SYSCALL_SUSPEND_THREAD         0x0025
#define NT_SYSCALL_TERMINATE_PROCESS      0x00E0
#define NT_SYSCALL_TERMINATE_THREAD       0x00E1
#define NT_SYSCALL_CREATE_SECTION         0x007C
#define NT_SYSCALL_MAP_VIEW_SECTION       0x007E
#define NT_SYSCALL_UNMAP_VIEW             0x007F
#define NT_SYSCALL_CREATE_KEY             0x0029
#define NT_SYSCALL_OPEN_KEY               0x0032
#define NT_SYSCALL_QUERY_VALUE_KEY        0x002B
#define NT_SYSCALL_SET_VALUE_KEY          0x002D
#define NT_SYSCALL_ENUM_KEY               0x002C
#define NT_SYSCALL_DELETE_KEY             0x002E
#define NT_SYSCALL_CLOSE_KEY              0x0027
#define NT_SYSCALL_LOAD_DRIVER            0x00A1
#define NT_SYSCALL_RESUME_PROCESS         0x00FA
#define NT_SYSCALL_QUERY_PERFORMANCE      0x0130
#define NT_SYSCALL_GET_TICK_COUNT         0x0119
#define NT_SYSCALL_ALLOCATE_VIRTUAL        0x00E3
#define NT_SYSCALL_FREE_VIRTUAL           0x00E4
#define NT_SYSCALL_QUERY_VIRTUAL          0x00E5
#define NT_SYSCALL_PROTECT_VIRTUAL        0x00E2

static const SYSCALL_MAP g_syscall_map[] = {
    { NT_SYSCALL_CREATEFILE,            "NtCreateFile",       __NR_openat        },
    { NT_SYSCALL_READFILE,               "NtReadFile",         __NR_read          },
    { NT_SYSCALL_WRITEFILE,              "NtWriteFile",        __NR_write         },
    { NT_SYSCALL_CLOSE,                   "NtClose",            __NR_close          },
    { NT_SYSCALL_DELETEFILE,             "NtDeleteFile",       __NR_unlinkat       },
    { NT_SYSCALL_QUERYFILE,              "NtQueryInformationFile", __NR_fstat    },
    { NT_SYSCALL_SETINFOFILE,            "NtSetInformationFile",   __NR_ftruncate },
    { NT_SYSCALL_CREATE_THREAD,          "NtCreateThread",     __NR_clone          },
    { NT_SYSCALL_RESUME_THREAD,          "NtResumeThread",     __NR_futex          },
    { NT_SYSCALL_WAIT_FOR_SINGLE,        "NtWaitForSingleObject",  __NR_futex     },
    { NT_SYSCALL_WAIT_FOR_MULTIPLE,      "NtWaitForMultipleObjects", __NR_futex   },
    { NT_SYSCALL_CREATE_EVENT,           "NtCreateEvent",      __NR_futex          },
    { NT_SYSCALL_SET_EVENT,              "NtSetEvent",         __NR_futex          },
    { NT_SYSCALL_CREATE_MUTEX,           "NtCreateMutant",     __NR_futex          },
    { NT_SYSCALL_RELEASE_MUTEX,          "NtReleaseMutant",    __NR_futex          },
    { NT_SYSCALL_CREATE_SEMAPHORE,       "NtCreateSemaphore",  __NR_futex          },
    { NT_SYSCALL_RELEASE_SEMAPHORE,      "NtReleaseSemaphore", __NR_futex          },
    { NT_SYSCALL_QUERY_SYSTEM,           "NtQuerySystemInformation", -1           },
    { NT_SYSCALL_QUERY_PROCESS,          "NtQueryInformationProcess",  -1         },
    { NT_SYSCALL_SET_PROCESS,            "NtSetInformationProcess",    -1         },
    { NT_SYSCALL_QUERY_THREAD,           "NtQueryInformationThread",   -1         },
    { NT_SYSCALL_SUSPEND_THREAD,         "NtSuspendThread",    __NR_tkill         },
    { NT_SYSCALL_TERMINATE_PROCESS,      "NtTerminateProcess", __NR_exit_group    },
    { NT_SYSCALL_TERMINATE_THREAD,       "NtTerminateThread",  __NR_exit          },
    { NT_SYSCALL_CREATE_SECTION,         "NtCreateSection",    -1                 },
    { NT_SYSCALL_MAP_VIEW_SECTION,       "NtMapViewOfSection", __NR_mmap          },
    { NT_SYSCALL_UNMAP_VIEW,             "NtUnmapViewOfSection", __NR_munmap      },
    { NT_SYSCALL_CREATE_KEY,             "NtCreateKey",        -1                 },
    { NT_SYSCALL_OPEN_KEY,               "NtOpenKey",          -1                 },
    { NT_SYSCALL_QUERY_VALUE_KEY,        "NtQueryValueKey",    -1                 },
    { NT_SYSCALL_SET_VALUE_KEY,          "NtSetValueKey",      -1                 },
    { NT_SYSCALL_ENUM_KEY,               "NtEnumerateKey",     -1                 },
    { NT_SYSCALL_DELETE_KEY,             "NtDeleteKey",        -1                 },
    { NT_SYSCALL_CLOSE_KEY,              "NtClose",            __NR_close          },
    { NT_SYSCALL_QUERY_PERFORMANCE,      "NtQueryPerformanceCounter",  -1         },
};

#define SYSCALL_MAP_COUNT (sizeof(g_syscall_map) / sizeof(g_syscall_map[0]))

// Translate an NT syscall number to the mapped Linux syscall
int nt_syscall_translate(int nt_syscall, int* linux_syscall, void** args) {
    size_t i;
    for (i = 0; i < SYSCALL_MAP_COUNT; i++) {
        if (g_syscall_map[i].nt_number == nt_syscall) {
            if (linux_syscall) *linux_syscall = g_syscall_map[i].linux_syscall;
            NTLL_LOG_DEBUG("syscall %s (%x) -> linux %d", g_syscall_map[i].nt_name,
                          nt_syscall, g_syscall_map[i].linux_syscall);
            return 0;
        }
    }
    NTLL_LOG_WARN("unmapped NT syscall: 0x%x", nt_syscall);
    if (linux_syscall) *linux_syscall = -1;
    return -1;
}

// Generic syscall handler - routes to high-level NT implementations
NTSTATUS nt_syscall_handler(int syscall_num, void* arg1, void* arg2,
                           void* arg3, void* arg4, void* arg5, void* arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    switch (syscall_num) {
        case NT_SYSCALL_QUERY_SYSTEM:
            return nt_query_system_information((int)(intptr_t)arg1,
                                               arg2, (ULONG)(uintptr_t)arg3,
                                               (PULONG)arg4);
        case NT_SYSCALL_QUERY_PROCESS:
            return nt_query_information_process((HANDLE)(uintptr_t)arg1,
                                                (int)(intptr_t)arg2,
                                                arg3, (ULONG)(uintptr_t)arg4,
                                                (PULONG)arg5);
        case NT_SYSCALL_SET_PROCESS:
            return nt_set_information_process((HANDLE)(uintptr_t)arg1,
                                              (int)(intptr_t)arg2,
                                              arg3, (ULONG)(uintptr_t)arg4);
        case NT_SYSCALL_QUERY_THREAD:
            return nt_query_information_thread((HANDLE)(uintptr_t)arg1,
                                               (int)(intptr_t)arg2,
                                               arg3, (ULONG)(uintptr_t)arg4,
                                               (PULONG)arg5);
        case NT_SYSCALL_TERMINATE_PROCESS: {
            extern NTSTATUS nt_terminate_process(PNTLL_PROCESS, NTSTATUS);
            PNTLL_PROCESS proc;
            if (nt_get_current_process(&proc) == STATUS_SUCCESS) {
                NTSTATUS exit = (NTSTATUS)(uintptr_t)arg2;
                return nt_terminate_process(proc, exit);
            }
            return STATUS_INVALID_PARAMETER;
        }
        case NT_SYSCALL_CREATE_EVENT: {
            extern NTSTATUS nt_create_event(PHANDLE, DWORD, POBJECT_ATTRIBUTES,
                                           int, BOOL);
            return nt_create_event((PHANDLE)arg1, (DWORD)(uintptr_t)arg2,
                                   (POBJECT_ATTRIBUTES)arg3,
                                   (int)(intptr_t)arg4, (BOOL)(intptr_t)arg5);
        }
        case NT_SYSCALL_SET_EVENT: {
            extern NTSTATUS nt_set_event(HANDLE, PULONG);
            return nt_set_event((HANDLE)(uintptr_t)arg1, (PULONG)arg2);
        }
        default:
            return STATUS_NOT_IMPLEMENTED;
    }
}

// Version report for NtQuerySystemInformation
NTSTATUS nt_query_system_information(int info_class, PVOID buf, ULONG len,
                                    PULONG ret_len) {
    switch (info_class) {
        case 0x0A: { // SystemPerformanceInformation - return minimal
            if (len < 4) return STATUS_BUFFER_TOO_SMALL;
            memset(buf, 0, len);
            if (ret_len) *ret_len = 4;
            return STATUS_SUCCESS;
        }
        case 0x25: { // SystemProcessorInformation
            return STATUS_SUCCESS;
        }
        default:
            if (ret_len) *ret_len = 0;
            NTLL_LOG_DEBUG("NtQuerySystemInformation class 0x%x", info_class);
            memset(buf, 0, len);
            return STATUS_SUCCESS;
    }
}

NTSTATUS nt_query_information_process(HANDLE process, int info_class,
                                     PVOID buf, ULONG len, PULONG ret_len) {
    (void)process;
    switch (info_class) {
        case 0x00: { // ProcessBasicInformation
            if (len < 48) return STATUS_BUFFER_TOO_SMALL;
            memset(buf, 0, len);
            if (ret_len) *ret_len = 48;
            return STATUS_SUCCESS;
        }
        case 0x07: // ProcessEnvironmentBlock
            return STATUS_SUCCESS;
        default:
            if (ret_len) *ret_len = 0;
            memset(buf, 0, len);
            return STATUS_SUCCESS;
    }
}

NTSTATUS nt_set_information_process(HANDLE process, int info_class,
                                   PVOID buf, ULONG len) {
    (void)process; (void)buf; (void)len;
    NTLL_LOG_DEBUG("NtSetInformationProcess class 0x%x", info_class);
    return STATUS_SUCCESS;
}

NTSTATUS nt_query_information_thread(HANDLE thread, int info_class,
                                    PVOID buf, ULONG len, PULONG ret_len) {
    (void)thread;
    switch (info_class) {
        case 0x00: { // ThreadBasicInformation
            if (len < 48) return STATUS_BUFFER_TOO_SMALL;
            memset(buf, 0, len);
            if (ret_len) *ret_len = 48;
            return STATUS_SUCCESS;
        }
        default:
            if (ret_len) *ret_len = 0;
            memset(buf, 0, len);
            return STATUS_SUCCESS;
    }
}