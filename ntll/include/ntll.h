#ifndef NTLL_H
#define NTLL_H

#include "win32_types.h"
#include "pe.h"

#define NTLL_VERSION "1.0.0"

#define NT_SUCCESS(Status) (((int32_t)(Status)) >= 0)
#define NT_ERROR(Status)   (((int32_t)(Status)) < 0)

#define STATUS_SUCCESS                   ((int32_t)0x00000000)
#define STATUS_ACCESS_VIOLATION          ((int32_t)0xC0000005)
#define STATUS_BUFFER_TOO_SMALL          ((int32_t)0xC0000023)
#define STATUS_INVALID_HANDLE            ((int32_t)0xC0000008)
#define STATUS_INVALID_PARAMETER         ((int32_t)0xC000000D)
#define STATUS_NO_MEMORY                 ((int32_t)0xC0000017)
#define STATUS_OBJECT_NAME_NOT_FOUND     ((int32_t)0xC0000034)
#define STATUS_DLL_NOT_FOUND             ((int32_t)0xC0000135)
#define STATUS_ENTRYPOINT_NOT_FOUND      ((int32_t)0xC0000139)
#define STATUS_INTEGER_OVERFLOW          ((int32_t)0xC0000095)
#define STATUS_STACK_OVERFLOW            ((int32_t)0xC00000FD)
#define STATUS_NOT_IMPLEMENTED           ((int32_t)0xC0000002)
#define STATUS_UNSUCCESSFUL              ((int32_t)0xC0000001)

#define NT_NLS_CODEPAGE     437
#define NT_NLS_OEMCP        437

typedef uint32_t NTSTATUS;

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ANSI_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    char* Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    void* InLoadOrderModuleList;
    void* InMemoryOrderModuleList;
    void* InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    void* InLoadOrderLinks;
    void* InMemoryOrderLinks;
    void* InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    void* SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    BYTE Padding[4];
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    /* ... more fields ... */
} PEB, *PPEB;

typedef struct _TEB {
    void* Reserved1[12];
    PPEB ProcessEnvironmentBlock;
    /* ... more fields ... */
} TEB, *PTEB;

/* PE Loader context */
typedef struct _NTLL_MODULE {
    char name[MAX_PATH];
    wchar_t wide_name[MAX_PATH];
    char full_path[MAX_PATH];
    PVOID base_address;
    DWORD size_of_image;
    PVOID entry_point;
    IMAGE_NT_HEADERS64* nt_headers;
    IMAGE_SECTION_HEADER* sections;
    void* export_directory;
    void* import_directory;
    struct _NTLL_MODULE* next;
} NTLL_MODULE, *PNTLL_MODULE;

/* Process environment */
typedef struct _NTLL_PROCESS {
    DWORD pid;
    DWORD parent_pid;
    PTEB teb;
    PPEB peb;
    PNTLL_MODULE modules;
    HANDLE heap;
    DWORD thread_count;
    BOOL initialized;
    char* command_line;
    wchar_t* wide_command_line;
    char* current_directory;
    char** environment;
    int exit_code;
    BOOL Wow64;
    DWORD64 image_base;
    DWORD64 stack_base;
    DWORD64 stack_limit;
    DWORD64 tls_slots[64];
    int tls_count;
} NTLL_PROCESS, *PNTLL_PROCESS;

/* Thread environment */
typedef struct _NTLL_THREAD {
    DWORD tid;
    DWORD process_id;
    BOOL  running;
    PVOID start_address;
    LPVOID parameter;
    HANDLE thread_handle;
    DWORD exit_code;
    int   priority;
} NTLL_THREAD, *PNTLL_THREAD;

/* File handle */
typedef struct _NTLL_FILE_HANDLE {
    int linux_fd;
    DWORD access_mask;
    DWORD share_mode;
    DWORD creation_disposition;
    DWORD flags_and_attributes;
    char* unix_path;
    wchar_t* nt_path;
    BOOL is_directory;
    BOOL is_console;
    BOOL is_pipe;
    BOOL is_device;
    union {
        int pipe_fd;
        int console_fd;
    };
} NTLL_FILE_HANDLE, *PNTLL_FILE_HANDLE;

/* Virtual memory region */
typedef struct _NTLL_VM_REGION {
    PVOID base_address;
    SIZE_T region_size;
    DWORD protection;
    DWORD type;
    DWORD state;
    struct _NTLL_VM_REGION* next;
} NTLL_VM_REGION, *PNTLL_VM_REGION;

/* Console state */
typedef struct _NTLL_CONSOLE {
    int input_fd;
    int output_fd;
    int error_fd;
    DWORD input_mode;
    DWORD output_mode;
    DWORD codepage;
    DWORD oem_codepage;
    wchar_t title[MAX_PATH];
    BOOL attached;
    int cursor_size;
    BOOL cursor_visible;
    WORD attributes;
} NTLL_CONSOLE, *PNTLL_CONSOLE;

/* Registry key */
typedef struct _NTLL_REGISTRY_KEY {
    char* path;
    void* data;
    DWORD data_size;
    DWORD data_type;
    DWORD flags;
    struct _NTLL_REGISTRY_KEY* children;
    struct _NTLL_REGISTRY_KEY* next;
} NTLL_REGISTRY_KEY, *PNTLL_REGISTRY_KEY;

/* Forward declarations for API modules */
int ntll_init(void);
void ntll_cleanup(void);

/* PE Loader */
PNTLL_MODULE pe_load(const char* path);
PNTLL_MODULE pe_load_from_memory(const void* data, size_t size);
void pe_unload(PNTLL_MODULE module);
void* pe_get_export(PNTLL_MODULE module, const char* name);
void* pe_get_export_by_ordinal(PNTLL_MODULE module, WORD ordinal);
NTSTATUS pe_relocate(PNTLL_MODULE module, intptr_t delta);
NTSTATUS pe_resolve_imports(PNTLL_MODULE module);

/* Process management */
NTSTATUS nt_create_process(const char* image_path, const char* command_line,
                          const char* current_dir, PNTLL_PROCESS* process);
NTSTATUS nt_terminate_process(PNTLL_PROCESS process, NTSTATUS exit_status);
NTSTATUS nt_get_current_process(PNTLL_PROCESS* process);
NTSTATUS nt_get_current_thread(PNTLL_THREAD* thread);

/* Memory management */
PVOID nt_alloc_virtual_memory(SIZE_T size, DWORD protection);
NTSTATUS nt_free_virtual_memory(PVOID base, SIZE_T size);
NTSTATUS nt_protect_virtual_memory(PVOID base, SIZE_T size, DWORD new_protect,
                                  DWORD* old_protect);
PVOID nt_map_view_of_file(HANDLE file, SIZE_T size, DWORD protection);

/* Syscall translation */
int nt_syscall_translate(int nt_syscall, int* linux_syscall, void** args);
NTSTATUS nt_syscall_handler(int syscall_num, void* arg1, void* arg2,
                           void* arg3, void* arg4, void* arg5, void* arg6);

/* NT API implementations */
NTSTATUS nt_close(HANDLE handle);
NTSTATUS nt_create_file(PHANDLE handle, DWORD access, POBJECT_ATTRIBUTES obj,
                       PIO_STATUS_BLOCK ios, PLARGE_INTEGER alloc_size,
                       DWORD attribs, DWORD share, DWORD create,
                       DWORD flags, PVOID eabuf, ULONG ealen);
NTSTATUS nt_read_file(HANDLE handle, HANDLE event, void* apc,
                     PIO_STATUS_BLOCK ios, PVOID buf, ULONG len,
                     PLARGE_INTEGER offset, PULONG key);
NTSTATUS nt_write_file(HANDLE handle, HANDLE event, void* apc,
                      PIO_STATUS_BLOCK ios, PVOID buf, ULONG len,
                      PLARGE_INTEGER offset, PULONG key);
NTSTATUS nt_create_section(PHANDLE section, DWORD access,
                          POBJECT_ATTRIBUTES obj, PLARGE_INTEGER max_size,
                          DWORD protect, DWORD attribs, HANDLE file);
NTSTATUS nt_query_system_information(int info_class, PVOID buf, ULONG len,
                                    PULONG ret_len);
NTSTATUS nt_query_information_process(HANDLE process, int info_class,
                                     PVOID buf, ULONG len, PULONG ret_len);
NTSTATUS nt_set_information_process(HANDLE process, int info_class,
                                   PVOID buf, ULONG len);
NTSTATUS nt_query_information_thread(HANDLE thread, int info_class,
                                    PVOID buf, ULONG len, PULONG ret_len);
NTSTATUS nt_create_thread(PHANDLE thread, DWORD access,
                         POBJECT_ATTRIBUTES obj, HANDLE process,
                         PVOID start, PVOID param, BOOL suspend,
                         DWORD stack_size, PULONG_PTR tls,
                         PCLIENT_ID cid);
NTSTATUS nt_resume_thread(HANDLE thread, PULONG suspend_count);
NTSTATUS nt_wait_for_single_object(HANDLE handle, BOOL alertable,
                                  PLARGE_INTEGER timeout);
NTSTATUS nt_create_event(PHANDLE event, DWORD access,
                        POBJECT_ATTRIBUTES obj, int type, BOOL initial);
NTSTATUS nt_set_event(HANDLE event, PULONG previous);

/* Win32 API wrappers */
HMODULE win32_load_library(const char* name);
HMODULE win32_load_library_ex(const char* name, HANDLE file, DWORD flags);
void* win32_get_proc_address(HMODULE module, const char* name);
BOOL win32_free_library(HMODULE module);
DWORD win32_get_last_error(void);
void win32_set_last_error(DWORD error);
HANDLE win32_create_file(const char* path, DWORD access, DWORD share,
                        void* sa, DWORD create, DWORD flags, HANDLE templ);
BOOL win32_read_file(HANDLE handle, void* buf, DWORD len, DWORD* read,
                    void* overlapped);
BOOL win32_write_file(HANDLE handle, void* buf, DWORD len, DWORD* written,
                     void* overlapped);
DWORD win32_get_file_size(HANDLE handle, DWORD* high);
BOOL win32_get_file_time(HANDLE handle, void* ctime, void* atime, void* mtime);
BOOL win32_close_handle(HANDLE handle);
DWORD win32_get_full_path_name(const char* path, DWORD buf_len,
                              char* buf, char** file_part);
DWORD win32_get_temp_path(DWORD len, char* buf);
DWORD win32_get_temp_file_name(const char* path, const char* prefix,
                              DWORD unique, char* buf);
BOOL win32_create_directory(const char* path, void* sa);
BOOL win32_remove_directory(const char* path);
BOOL win32_delete_file(const char* path);
BOOL win32_move_file(const char* from, const char* to);
BOOL win32_copy_file(const char* from, const char* to, BOOL failIfExists);
DWORD win32_get_file_attributes(const char* path);
BOOL win32_set_file_attributes(const char* path, DWORD attrs);
BOOL win32_find_first_file(const char* pattern, void* find_data);
BOOL win32_find_next_file(HANDLE find, void* find_data);
BOOL win32_find_close(HANDLE find);

/* Console I/O */
BOOL win32_alloc_console(void);
BOOL win32_free_console(void);
BOOL win32_set_console_title(const char* title);
DWORD win32_get_console_title(char* buf, DWORD len);
BOOL win32_set_console_cursor_info(HANDLE console, DWORD size, BOOL visible);
BOOL win32_get_console_cursor_info(HANDLE console, void* info);
BOOL win32_read_console_input(HANDLE console, void* recs, DWORD count,
                             DWORD* read);
BOOL win32_write_console(HANDLE console, void* buf, DWORD len,
                        DWORD* written, void* reserved);
BOOL win32_set_console_mode(HANDLE console, DWORD mode);
BOOL win32_get_console_mode(HANDLE console, DWORD* mode);
BOOL win32_get_console_screen_buffer_info(HANDLE console, void* info);
BOOL win32_fill_console_output_character(HANDLE console, char ch, DWORD count,
                                        void* start, DWORD* written);
BOOL win32_fill_console_output_attribute(HANDLE console, WORD attr,
                                        DWORD count, void* start, DWORD* written);
BOOL win32_set_console_text_attribute(HANDLE console, WORD attrs);
BOOL win32_set_consoleCursorPosition(HANDLE console, void* pos);
void win32_sleep(DWORD ms);
DWORD win32_get_tick_count(void);
void win32_get_system_time(void* st);
void win32_get_local_time(void* st);
BOOL win32_query_performance_counter(LONGLONG* counter);
BOOL win32_query_performance_frequency(LONGLONG* freq);
HANDLE win32_create_mutex(void* sa, BOOL initial, const char* name);
BOOL win32_release_mutex(HANDLE mutex);
HANDLE win32_create_semaphore(void* sa, LONG initial, LONG max, const char* name);
BOOL win32_release_semaphore(HANDLE sem, LONG count, LONG* prev);
HANDLE win32_create_thread(void* sa, SIZE_T stack, void* start, void* param,
                          DWORD flags, DWORD* tid);
DWORD win32_suspend_thread(HANDLE thread);
DWORD win32_resume_thread(HANDLE thread);
BOOL win32_terminate_thread(HANDLE thread, DWORD code);
DWORD win32_get_thread_id(HANDLE thread);
DWORD win32_get_current_thread_id(void);
DWORD win32_get_current_process_id(void);
BOOL win32_get_exit_code_thread(HANDLE thread, DWORD* code);
BOOL win32_get_exit_code_process(HANDLE process, DWORD* code);
DWORD win32_wait_for_single_object(HANDLE handle, DWORD ms);
DWORD win32_wait_for_multiple_objects(DWORD count, const HANDLE* handles,
                                     BOOL wait_all, DWORD ms);
void win32_initialize_critical_section(void* cs);
void win32_enter_critical_section(void* cs);
void win32_leave_critical_section(void* cs);
void win32_delete_critical_section(void* cs);
DWORD win32_tls_alloc(void);
BOOL win32_tls_free(DWORD index);
void* win32_tls_get_value(DWORD index);
BOOL win32_tls_set_value(DWORD index, void* value);

/* Registry */
NTSTATUS nt_open_key(PHANDLE key, DWORD access, POBJECT_ATTRIBUTES obj);
NTSTATUS nt_create_key(PHANDLE key, DWORD access, POBJECT_ATTRIBUTES obj,
                      DWORD title_index, PUNICODE_STRING class_name,
                      DWORD options, PULONG disposition);
NTSTATUS nt_query_value_key(HANDLE key, PUNICODE_STRING name,
                           int info_class, PVOID buf, ULONG len, PULONG ret_len);
NTSTATUS nt_set_value_key(HANDLE key, PUNICODE_STRING name,
                         DWORD title_index, DWORD type, PVOID data, ULONG data_size);
NTSTATUS nt_delete_key(HANDLE key);
NTSTATUS nt_close_key(HANDLE key);
NTSTATUS nt_enum_key(HANDLE key, DWORD index, PVOID info, ULONG len,
                    PULONG ret_len);

/* String utilities */
void nt_init_unicode_string(PUNICODE_STRING dst, const wchar_t* src);
void nt_init_ansi_string(PANSI_STRING dst, const char* src);
void nt_free_unicode_string(PUNICODE_STRING str);
void nt_free_ansi_string(PANSI_STRING str);
int nt_unicode_to_ansi(PUNICODE_STRING unicode, PANSI_STRING ansi);
int nt_ansi_to_unicode(PANSI_STRING ansi, PUNICODE_STRING unicode);
int nt_wide_to_narrow(const wchar_t* wide, char* narrow, int max_len);
int nt_narrow_to_wide(const char* narrow, wchar_t* wide, int max_len);

/* Path conversion */
int nt_to_unix_path(const char* nt_path, char* unix_path, int max_len);
int unix_to_nt_path(const char* unix_path, char* nt_path, int max_len);
const char* nt_get_system_root(void);
const char* nt_get_windows_dir(void);
const char* nt_get_system32_dir(void);

/* Environment */
char** nt_get_environment(void);
void nt_set_environment_variable(const char* name, const char* value);
void nt_free_environment(char** env);
char* nt_get_environment_variable(const char* name);

/* Timing */
uint64_t nt_get_system_time_as_filetime(void);
uint64_t nt_get_tick_count(void);
void nt_sleep(uint32_t milliseconds);

/* Version information */
typedef struct _NTLL_OS_VERSION {
    DWORD major;
    DWORD minor;
    DWORD build;
    DWORD platform_id;
    char  version_string[128];
    char  build_string[64];
} NTLL_OS_VERSION;

const NTLL_OS_VERSION* nt_get_os_version(void);
void nt_set_os_version(DWORD major, DWORD minor, DWORD build);

/* Builtin Windows software + cmd.exe interpreter (implemented in cmd.c) */
int nt_builtin_cmd(int argc, char** argv);
int nt_builtin_exec(const char* program, int argc, char** argv);

/* Native reimplementations of bundled Windows System32 CLI tools (tools.c) */
int nt_tool_dispatch(const char* program, int argc, char** argv);

/* Host drive mounts from LSW_MOUNTS / lsw.conf [automount] (mounts.c) */
int nt_mount_lookup(char drive_letter, char* out, size_t sz);

/* Logging */
void ntll_log(int level, const char* format, ...);
#define NTLL_LOG_INFO(...) ntll_log(0, __VA_ARGS__)
#define NTLL_LOG_WARN(...) ntll_log(1, __VA_ARGS__)
#define NTLL_LOG_ERROR(...) ntll_log(2, __VA_ARGS__)
#define NTLL_LOG_DEBUG(...) ntll_log(3, __VA_ARGS__)

/* Module loading / dispatch (implemented in dispatch.c) */
void* ntll_dispatch(PNTLL_MODULE module, const char* name);
PNTLL_MODULE ntll_load_system_module(const char* dll_name);
int ntll_heap_alloc_extern(size_t size);
void* ntll_heap_alloc(size_t size);
void ntll_heap_free(void* ptr);
void ntll_hexdump(const void* data, size_t len);

#endif
