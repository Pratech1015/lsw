// dispatch.c - PE import dispatch table for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Maps function names that PE imports request to the NTLL implementations.
// This is the connective tissue between the PE loader's import resolution
// and the Win32/NT API surface.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>

#include "ntll.h"

typedef void* (*api_func)(void);

typedef struct _API_ENTRY {
    const char* dll;
    const char* name;
    void* func;
} API_ENTRY;

// Forward declarations of all kernel32 implementations
DWORD win32_get_last_error(void);
void win32_set_last_error(DWORD);
HANDLE win32_create_file(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
BOOL win32_read_file(HANDLE, void*, DWORD, DWORD*, void*);
BOOL win32_write_file(HANDLE, void*, DWORD, DWORD*, void*);
BOOL win32_close_handle(HANDLE);
DWORD win32_get_file_size(HANDLE, DWORD*);
BOOL win32_flush_file_buffers(HANDLE);
BOOL win32_set_file_pointer(HANDLE, LONG, LONG*, DWORD, DWORD*);
BOOL win32_get_file_time(HANDLE, void*, void*, void*);
DWORD win32_get_full_path_name(const char*, DWORD, char*, char**);
DWORD win32_get_temp_path(DWORD, char*);
DWORD win32_get_temp_file_name(const char*, const char*, DWORD, char*);
BOOL win32_create_directory(const char*, void*);
BOOL win32_remove_directory(const char*);
BOOL win32_delete_file(const char*);
BOOL win32_move_file(const char*, const char*);
BOOL win32_copy_file(const char*, const char*, BOOL);
DWORD win32_get_file_attributes(const char*);
BOOL win32_set_file_attributes(const char*, DWORD);
BOOL win32_set_current_directory(const char*);
DWORD win32_get_current_directory(DWORD, char*);
BOOL win32_alloc_console(void);
BOOL win32_free_console(void);
BOOL win32_set_console_title(const char*);
DWORD win32_get_console_title(char*, DWORD);
BOOL win32_set_console_cursor_info(HANDLE, DWORD, BOOL);
BOOL win32_get_console_cursor_info(HANDLE, void*);
BOOL win32_read_console_input(HANDLE, void*, DWORD, DWORD*);
BOOL win32_write_console(HANDLE, void*, DWORD, DWORD*, void*);
BOOL win32_set_console_mode(HANDLE, DWORD);
BOOL win32_get_console_mode(HANDLE, DWORD*);
BOOL win32_get_console_screen_buffer_info(HANDLE, void*);
BOOL win32_fill_console_output_character(HANDLE, char, DWORD, void*, DWORD*);
BOOL win32_fill_console_output_attribute(HANDLE, WORD, DWORD, void*, DWORD*);
BOOL win32_set_console_text_attribute(HANDLE, WORD);
void win32_sleep(DWORD);
DWORD win32_get_tick_count(void);
void win32_get_system_time(void*);
void win32_get_local_time(void*);
void win32_get_system_time_as_file_time(void*);
BOOL win32_query_performance_counter(LONGLONG*);
BOOL win32_query_performance_frequency(LONGLONG*);
void win32_initialize_critical_section(void*);
void win32_enter_critical_section(void*);
void win32_leave_critical_section(void*);
void win32_delete_critical_section(void*);
HANDLE win32_create_mutex(void*, BOOL, const char*);
BOOL win32_release_mutex(HANDLE);
HANDLE win32_create_event(void*, BOOL, BOOL, const char*);
BOOL win32_set_event(HANDLE);
BOOL win32_reset_event(HANDLE);
HANDLE win32_create_semaphore(void*, LONG, LONG, const char*);
BOOL win32_release_semaphore(HANDLE, LONG, LONG*);
DWORD win32_wait_for_single_object(HANDLE, DWORD);
DWORD win32_wait_for_multiple_objects(DWORD, const HANDLE*, BOOL, DWORD);
DWORD win32_sleep_ex(DWORD, BOOL);
DWORD win32_get_current_thread_id(void);
DWORD win32_get_current_process_id(void);
HANDLE win32_create_thread(void*, SIZE_T, void*, void*, DWORD, DWORD*);
DWORD win32_suspend_thread(HANDLE);
DWORD win32_resume_thread(HANDLE);
BOOL win32_terminate_thread(HANDLE, DWORD);
DWORD win32_get_thread_id(HANDLE);
BOOL win32_get_exit_code_thread(HANDLE, DWORD*);
BOOL win32_get_exit_code_process(HANDLE, DWORD*);
DWORD win32_tls_alloc(void);
BOOL win32_tls_free(DWORD);
void* win32_tls_get_value(DWORD);
BOOL win32_tls_set_value(DWORD, void*);
BOOL win32_get_startup_info(void*);
void win32_exit_process(DWORD);
void win32_exit_thread(DWORD);
BOOL win32_is_debugger_present(void);
void win32_output_debug_string(const char*);
void win32_get_system_info(void*);
DWORD win32_get_environment_variable(const char*, char*, DWORD);
BOOL win32_set_environment_variable(const char*, const char*);
DWORD win32_get_module_handle(const char*);
void* win32_get_proc_address(HMODULE, const char*);

// ntdll forwards
NTSTATUS nt_create_thread(PHANDLE, DWORD, POBJECT_ATTRIBUTES, HANDLE, PVOID,
                          PVOID, BOOL, DWORD, PULONG_PTR, PCLIENT_ID);
NTSTATUS nt_resume_thread(HANDLE, PULONG);
NTSTATUS nt_wait_for_single_object(HANDLE, BOOL, PLARGE_INTEGER);
NTSTATUS nt_close(HANDLE);
NTSTATUS nt_create_event(PHANDLE, DWORD, POBJECT_ATTRIBUTES, int, BOOL);
NTSTATUS nt_set_event(HANDLE, PULONG);
NTSTATUS nt_query_system_information(int, PVOID, ULONG, PULONG);
NTSTATUS nt_query_information_process(HANDLE, int, PVOID, ULONG, PULONG);
NTSTATUS nt_set_information_process(HANDLE, int, PVOID, ULONG);
NTSTATUS nt_query_information_thread(HANDLE, int, PVOID, ULONG, PULONG);
NTSTATUS nt_terminate_process(PNTLL_PROCESS, NTSTATUS);
NTSTATUS nt_create_process(const char*, const char*, const char*, PNTLL_PROCESS*);

static const API_ENTRY g_kernel32_exports[] = {
    { "kernel32.dll", "GetLastError", (void*)win32_get_last_error },
    { "kernel32.dll", "SetLastError", (void*)win32_set_last_error },
    { "kernel32.dll", "CreateFileA", (void*)win32_create_file },
    { "kernel32.dll", "CreateFileW", (void*)win32_create_file },
    { "kernel32.dll", "ReadFile", (void*)win32_read_file },
    { "kernel32.dll", "WriteFile", (void*)win32_write_file },
    { "kernel32.dll", "CloseHandle", (void*)win32_close_handle },
    { "kernel32.dll", "GetFileSize", (void*)win32_get_file_size },
    { "kernel32.dll", "GetFileSizeEx", (void*)win32_get_file_size },
    { "kernel32.dll", "FlushFileBuffers", (void*)win32_flush_file_buffers },
    { "kernel32.dll", "SetFilePointer", (void*)win32_set_file_pointer },
    { "kernel32.dll", "SetFilePointerEx", (void*)win32_set_file_pointer },
    { "kernel32.dll", "GetFileTime", (void*)win32_get_file_time },
    { "kernel32.dll", "GetFullPathNameA", (void*)win32_get_full_path_name },
    { "kernel32.dll", "GetFullPathNameW", (void*)win32_get_full_path_name },
    { "kernel32.dll", "GetTempPathA", (void*)win32_get_temp_path },
    { "kernel32.dll", "GetTempPathW", (void*)win32_get_temp_path },
    { "kernel32.dll", "GetTempFileNameA", (void*)win32_get_temp_file_name },
    { "kernel32.dll", "GetTempFileNameW", (void*)win32_get_temp_file_name },
    { "kernel32.dll", "CreateDirectoryA", (void*)win32_create_directory },
    { "kernel32.dll", "CreateDirectoryW", (void*)win32_create_directory },
    { "kernel32.dll", "CreateDirectoryExA", (void*)win32_create_directory },
    { "kernel32.dll", "RemoveDirectoryA", (void*)win32_remove_directory },
    { "kernel32.dll", "RemoveDirectoryW", (void*)win32_remove_directory },
    { "kernel32.dll", "DeleteFileA", (void*)win32_delete_file },
    { "kernel32.dll", "DeleteFileW", (void*)win32_delete_file },
    { "kernel32.dll", "MoveFileA", (void*)win32_move_file },
    { "kernel32.dll", "MoveFileW", (void*)win32_move_file },
    { "kernel32.dll", "MoveFileExA", (void*)win32_move_file },
    { "kernel32.dll", "MoveFileExW", (void*)win32_move_file },
    { "kernel32.dll", "CopyFileA", (void*)win32_copy_file },
    { "kernel32.dll", "CopyFileW", (void*)win32_copy_file },
    { "kernel32.dll", "GetFileAttributesA", (void*)win32_get_file_attributes },
    { "kernel32.dll", "GetFileAttributesW", (void*)win32_get_file_attributes },
    { "kernel32.dll", "SetFileAttributesA", (void*)win32_set_file_attributes },
    { "kernel32.dll", "SetFileAttributesW", (void*)win32_set_file_attributes },
    { "kernel32.dll", "SetCurrentDirectoryA", (void*)win32_set_current_directory },
    { "kernel32.dll", "SetCurrentDirectoryW", (void*)win32_set_current_directory },
    { "kernel32.dll", "GetCurrentDirectoryA", (void*)win32_get_current_directory },
    { "kernel32.dll", "GetCurrentDirectoryW", (void*)win32_get_current_directory },

    { "kernel32.dll", "AllocConsole", (void*)win32_alloc_console },
    { "kernel32.dll", "FreeConsole", (void*)win32_free_console },
    { "kernel32.dll", "SetConsoleTitleA", (void*)win32_set_console_title },
    { "kernel32.dll", "SetConsoleTitleW", (void*)win32_set_console_title },
    { "kernel32.dll", "GetConsoleTitleA", (void*)win32_get_console_title },
    { "kernel32.dll", "GetConsoleTitleW", (void*)win32_get_console_title },
    { "kernel32.dll", "SetConsoleCursorInfo", (void*)win32_set_console_cursor_info },
    { "kernel32.dll", "GetConsoleCursorInfo", (void*)win32_get_console_cursor_info },
    { "kernel32.dll", "ReadConsoleInputA", (void*)win32_read_console_input },
    { "kernel32.dll", "ReadConsoleInputW", (void*)win32_read_console_input },
    { "kernel32.dll", "WriteConsoleA", (void*)win32_write_console },
    { "kernel32.dll", "WriteConsoleW", (void*)win32_write_console },
    { "kernel32.dll", "SetConsoleMode", (void*)win32_set_console_mode },
    { "kernel32.dll", "GetConsoleMode", (void*)win32_get_console_mode },
    { "kernel32.dll", "GetConsoleScreenBufferInfo", (void*)win32_get_console_screen_buffer_info },
    { "kernel32.dll", "FillConsoleOutputCharacterA", (void*)win32_fill_console_output_character },
    { "kernel32.dll", "FillConsoleOutputCharacterW", (void*)win32_fill_console_output_character },
    { "kernel32.dll", "FillConsoleOutputAttribute", (void*)win32_fill_console_output_attribute },
    { "kernel32.dll", "SetConsoleTextAttribute", (void*)win32_set_console_text_attribute },

    { "kernel32.dll", "Sleep", (void*)win32_sleep },
    { "kernel32.dll", "GetTickCount", (void*)win32_get_tick_count },
    { "kernel32.dll", "GetSystemTime", (void*)win32_get_system_time },
    { "kernel32.dll", "GetLocalTime", (void*)win32_get_local_time },
    { "kernel32.dll", "GetSystemTimeAsFileTime", (void*)win32_get_system_time_as_file_time },
    { "kernel32.dll", "QueryPerformanceCounter", (void*)win32_query_performance_counter },
    { "kernel32.dll", "QueryPerformanceFrequency", (void*)win32_query_performance_frequency },

    { "kernel32.dll", "InitializeCriticalSection", (void*)win32_initialize_critical_section },
    { "kernel32.dll", "EnterCriticalSection", (void*)win32_enter_critical_section },
    { "kernel32.dll", "LeaveCriticalSection", (void*)win32_leave_critical_section },
    { "kernel32.dll", "DeleteCriticalSection", (void*)win32_delete_critical_section },

    { "kernel32.dll", "CreateMutexA", (void*)win32_create_mutex },
    { "kernel32.dll", "CreateMutexW", (void*)win32_create_mutex },
    { "kernel32.dll", "ReleaseMutex", (void*)win32_release_mutex },
    { "kernel32.dll", "CreateEventA", (void*)win32_create_event },
    { "kernel32.dll", "CreateEventW", (void*)win32_create_event },
    { "kernel32.dll", "CreateEventExA", (void*)win32_create_event },
    { "kernel32.dll", "SetEvent", (void*)win32_set_event },
    { "kernel32.dll", "ResetEvent", (void*)win32_reset_event },
    { "kernel32.dll", "CreateSemaphoreA", (void*)win32_create_semaphore },
    { "kernel32.dll", "CreateSemaphoreW", (void*)win32_create_semaphore },
    { "kernel32.dll", "ReleaseSemaphore", (void*)win32_release_semaphore },
    { "kernel32.dll", "WaitForSingleObject", (void*)win32_wait_for_single_object },
    { "kernel32.dll", "WaitForMultipleObjects", (void*)win32_wait_for_multiple_objects },

    { "kernel32.dll", "SleepEx", (void*)win32_sleep_ex },
    { "kernel32.dll", "GetCurrentThreadId", (void*)win32_get_current_thread_id },
    { "kernel32.dll", "GetCurrentProcessId", (void*)win32_get_current_process_id },
    { "kernel32.dll", "CreateThread", (void*)win32_create_thread },
    { "kernel32.dll", "SuspendThread", (void*)win32_suspend_thread },
    { "kernel32.dll", "ResumeThread", (void*)win32_resume_thread },
    { "kernel32.dll", "TerminateThread", (void*)win32_terminate_thread },
    { "kernel32.dll", "GetThreadId", (void*)win32_get_thread_id },
    { "kernel32.dll", "GetExitCodeThread", (void*)win32_get_exit_code_thread },
    { "kernel32.dll", "GetExitCodeProcess", (void*)win32_get_exit_code_process },

    { "kernel32.dll", "TlsAlloc", (void*)win32_tls_alloc },
    { "kernel32.dll", "TlsFree", (void*)win32_tls_free },
    { "kernel32.dll", "TlsGetValue", (void*)win32_tls_get_value },
    { "kernel32.dll", "TlsSetValue", (void*)win32_tls_set_value },

    { "kernel32.dll", "GetStartupInfoA", (void*)win32_get_startup_info },
    { "kernel32.dll", "GetStartupInfoW", (void*)win32_get_startup_info },
    { "kernel32.dll", "ExitProcess", (void*)win32_exit_process },
    { "kernel32.dll", "ExitThread", (void*)win32_exit_thread },
    { "kernel32.dll", "IsDebuggerPresent", (void*)win32_is_debugger_present },
    { "kernel32.dll", "OutputDebugStringA", (void*)win32_output_debug_string },
    { "kernel32.dll", "OutputDebugStringW", (void*)win32_output_debug_string },
    { "kernel32.dll", "GetSystemInfo", (void*)win32_get_system_info },
    { "kernel32.dll", "GetNativeSystemInfo", (void*)win32_get_system_info },

    { "kernel32.dll", "GetEnvironmentVariableA", (void*)win32_get_environment_variable },
    { "kernel32.dll", "GetEnvironmentVariableW", (void*)win32_get_environment_variable },
    { "kernel32.dll", "SetEnvironmentVariableA", (void*)win32_set_environment_variable },
    { "kernel32.dll", "SetEnvironmentVariableW", (void*)win32_set_environment_variable },
    { "kernel32.dll", "GetModuleHandleA", (void*)win32_get_module_handle },
    { "kernel32.dll", "GetModuleHandleW", (void*)win32_get_module_handle },
    { "kernel32.dll", "GetModuleHandleExA", (void*)win32_get_module_handle },
    { "kernel32.dll", "GetProcAddress", (void*)win32_get_proc_address },

    // ntdll.dll exports
    { "ntdll.dll", "NtCreateThread", (void*)nt_create_thread },
    { "ntdll.dll", "NtCreateUserThread", (void*)nt_create_thread },
    { "ntdll.dll", "NtResumeThread", (void*)nt_resume_thread },
    { "ntdll.dll", "NtWaitForSingleObject", (void*)nt_wait_for_single_object },
    { "ntdll.dll", "NtClose", (void*)nt_close },
    { "ntdll.dll", "NtCreateEvent", (void*)nt_create_event },
    { "ntdll.dll", "NtSetEvent", (void*)nt_set_event },
    { "ntdll.dll", "NtQuerySystemInformation", (void*)nt_query_system_information },
    { "ntdll.dll", "NtQueryInformationProcess", (void*)nt_query_information_process },
    { "ntdll.dll", "NtSetInformationProcess", (void*)nt_set_information_process },
    { "ntdll.dll", "NtQueryInformationThread", (void*)nt_query_information_thread },
    { "ntdll.dll", "NtTerminateProcess", (void*)nt_terminate_process },
    { "ntdll.dll", "NtCreateProcess", (void*)nt_create_process },

    // kernelbase.dll aliases
    { "kernelbase.dll", "CreateFile", (void*)win32_create_file },
    { "kernelbase.dll", "CloseHandle", (void*)win32_close_handle },
    { "kernelbase.dll", "GetFileSize", (void*)win32_get_file_size },
    { "kernelbase.dll", "GetTickCount", (void*)win32_get_tick_count },
};

#define KERNEL32_EXPORT_COUNT (sizeof(g_kernel32_exports) / sizeof(g_kernel32_exports[0]))

// Look up an API by DLL name + function name
void* ntll_dispatch(PNTLL_MODULE module, const char* name) {
    (void)module;
    for (size_t i = 0; i < KERNEL32_EXPORT_COUNT; i++) {
        if (strcmp(g_kernel32_exports[i].name, name) == 0) {
            return g_kernel32_exports[i].func;
        }
    }
    NTLL_LOG_WARN("unresolved import: %s", name);
    return NULL;
}

// Load a system module (kernel32, ntdll, etc.) - returns a context object.
// For PE import resolution, all system modules resolve through ntll_dispatch.
PNTLL_MODULE ntll_load_system_module(const char* dll_name) {
    static NTLL_MODULE stub = {0};
    static int initialized = 0;

    (void)dll_name;
    if (!initialized) {
        strcpy(stub.name, dll_name);
        strcpy(stub.full_path, "(system)");
        stub.base_address = NULL;
        stub.size_of_image = 0;
        stub.entry_point = NULL;
        initialized = 1;
    }
    return &stub;
}

// Global init
int ntll_init(void) {
    static int done = 0;
    if (done) return 0;

    NTLL_LOG_INFO("NTLL runtime %s loading", NTLL_VERSION);

    PNTLL_PROCESS proc;
    nt_get_current_process(&proc);

    done = 1;
    return 0;
}

void ntll_cleanup(void) {
    NTLL_LOG_INFO("NTLL runtime shutdown");
}

// Logging backend
void ntll_log(int level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    const char* names[] = { "INFO", "WARN", "ERROR", "DEBUG" };
    fprintf(stderr, "[ntll:%s] ", names[level >= 0 && level <= 3 ? level : 0]);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}