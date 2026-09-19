// dispatch.c - PE import dispatch table for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Maps function names that PE imports request to the NTLL implementations.
// All DLLs share one flat lookup table; the DLL name is documentary only.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ntll.h"

// UTF-16 wide-string stubs (ntll/ucrtbase.c) — Windows wchar_t = 2 bytes
size_t lsw_utf16_wcslen(const unsigned short*);
unsigned short* lsw_utf16_wcschr(const unsigned short*, unsigned short);
unsigned short* lsw_utf16_wcsrchr(const unsigned short*, unsigned short);
unsigned short* lsw_utf16_wcsstr(const unsigned short*, const unsigned short*);
int lsw_utf16_wcscmp(const unsigned short*, const unsigned short*);
int lsw_utf16_wcsncmp(const unsigned short*, const unsigned short*, size_t);
size_t lsw_utf16_wcsspn(const unsigned short*, const unsigned short*);

typedef struct _API_ENTRY {
    const char* dll;
    const char* name;
    void* func;
} API_ENTRY;

// Forward declarations — kernel32 (kernel32.c)
DWORD win32_get_last_error(void); void win32_set_last_error(DWORD);
HANDLE win32_create_file(const char*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE);
BOOL win32_read_file(HANDLE,void*,DWORD,DWORD*,void*);
BOOL win32_write_file(HANDLE,void*,DWORD,DWORD*,void*);
BOOL win32_close_handle(HANDLE);
DWORD win32_get_file_size(HANDLE,DWORD*);
BOOL win32_flush_file_buffers(HANDLE);
BOOL win32_set_file_pointer(HANDLE,LONG,LONG*,DWORD,DWORD*);
BOOL win32_get_file_time(HANDLE,void*,void*,void*);
DWORD win32_get_full_path_name(const char*,DWORD,char*,char**);
DWORD win32_get_temp_path(DWORD,char*);
DWORD win32_get_temp_file_name(const char*,const char*,DWORD,char*);
BOOL win32_create_directory(const char*,void*);
BOOL win32_remove_directory(const char*);
BOOL win32_delete_file(const char*);
BOOL win32_move_file(const char*,const char*);
BOOL win32_copy_file(const char*,const char*,BOOL);
DWORD win32_get_file_attributes(const char*);
BOOL win32_set_file_attributes(const char*,DWORD);
BOOL win32_set_current_directory(const char*);
DWORD win32_get_current_directory(DWORD,char*);
BOOL win32_alloc_console(void); BOOL win32_free_console(void);
BOOL win32_set_console_title(const char*);
DWORD win32_get_console_title(char*,DWORD);
BOOL win32_set_console_cursor_info(HANDLE,DWORD,BOOL);
BOOL win32_get_console_cursor_info(HANDLE,void*);
BOOL win32_read_console_input(HANDLE,void*,DWORD,DWORD*);
BOOL win32_write_console(HANDLE,void*,DWORD,DWORD*,void*);
BOOL win32_set_console_mode(HANDLE,DWORD);
BOOL win32_get_console_mode(HANDLE,DWORD*);
BOOL win32_get_console_screen_buffer_info(HANDLE,void*);
BOOL win32_fill_console_output_character(HANDLE,char,DWORD,void*,DWORD*);
BOOL win32_fill_console_output_attribute(HANDLE,WORD,DWORD,void*,DWORD*);
BOOL win32_set_console_text_attribute(HANDLE,WORD);
void win32_sleep(DWORD); DWORD win32_get_tick_count(void);
void win32_get_system_time(void*); void win32_get_local_time(void*);
void win32_get_system_time_as_file_time(void*);
BOOL win32_query_performance_counter(LONGLONG*);
BOOL win32_query_performance_frequency(LONGLONG*);
void win32_initialize_critical_section(void*);
void win32_enter_critical_section(void*);
void win32_leave_critical_section(void*);
void win32_delete_critical_section(void*);
HANDLE win32_create_mutex(void*,BOOL,const char*);
BOOL win32_release_mutex(HANDLE);
HANDLE win32_create_event(void*,BOOL,BOOL,const char*);
BOOL win32_set_event(HANDLE); BOOL win32_reset_event(HANDLE);
HANDLE win32_create_semaphore(void*,LONG,LONG,const char*);
BOOL win32_release_semaphore(HANDLE,LONG,LONG*);
DWORD win32_wait_for_single_object(HANDLE,DWORD);
DWORD win32_wait_for_multiple_objects(DWORD,const HANDLE*,BOOL,DWORD);
DWORD win32_sleep_ex(DWORD,BOOL);
DWORD win32_get_current_thread_id(void);
DWORD win32_get_current_process_id(void);
HANDLE win32_create_thread(void*,SIZE_T,void*,void*,DWORD,DWORD*);
DWORD win32_suspend_thread(HANDLE);
DWORD win32_resume_thread(HANDLE);
BOOL win32_terminate_thread(HANDLE,DWORD);
DWORD win32_get_thread_id(HANDLE);
BOOL win32_get_exit_code_thread(HANDLE,DWORD*);
BOOL win32_get_exit_code_process(HANDLE,DWORD*);
DWORD win32_tls_alloc(void); BOOL win32_tls_free(DWORD);
void* win32_tls_get_value(DWORD);
BOOL win32_tls_set_value(DWORD,void*);
BOOL win32_get_startup_info(void*);
void win32_exit_process(DWORD); void win32_exit_thread(DWORD);
BOOL win32_is_debugger_present(void);
void win32_output_debug_string(const char*);
void win32_get_system_info(void*);
DWORD win32_get_environment_variable(const char*,char*,DWORD);
BOOL win32_set_environment_variable(const char*,const char*);
DWORD win32_get_module_handle(const char*);
void* win32_get_proc_address(HMODULE,const char*);

// ntdll forwards
NTSTATUS nt_create_thread(PHANDLE,DWORD,POBJECT_ATTRIBUTES,HANDLE,PVOID,PVOID,BOOL,DWORD,PULONG_PTR,PCLIENT_ID);
NTSTATUS nt_resume_thread(HANDLE,PULONG);
NTSTATUS nt_wait_for_single_object(HANDLE,BOOL,PLARGE_INTEGER);
NTSTATUS nt_close(HANDLE);
NTSTATUS nt_create_event(PHANDLE,DWORD,POBJECT_ATTRIBUTES,int,BOOL);
NTSTATUS nt_set_event(HANDLE,PULONG);
NTSTATUS nt_query_system_information(int,PVOID,ULONG,PULONG);
    LONG RtlDisownModuleHeapAllocation(HANDLE, void*);
NTSTATUS nt_query_information_process(HANDLE,int,PVOID,ULONG,PULONG);
NTSTATUS nt_set_information_process(HANDLE,int,PVOID,ULONG);
NTSTATUS nt_query_information_thread(HANDLE,int,PVOID,ULONG,PULONG);
NTSTATUS nt_terminate_process(PNTLL_PROCESS,NTSTATUS);
NTSTATUS nt_create_process(const char*,const char*,const char*,PNTLL_PROCESS*);

// kernel32 extensions
HANDLE GetProcessHeap(void);
void* HeapAlloc(HANDLE,DWORD,SIZE_T); BOOL HeapFree(HANDLE,DWORD,void*);
void* HeapReAlloc(HANDLE,DWORD,void*,SIZE_T);
SIZE_T HeapSize(HANDLE,DWORD,void*);
BOOL HeapSetInformation(HANDLE,int,void*,SIZE_T);
void* GlobalAlloc(UINT,SIZE_T); void* GlobalFree(void*);
void* LocalAlloc(UINT,SIZE_T); void* LocalFree(void*);
void* VirtualAlloc(void*,SIZE_T,DWORD,DWORD);
BOOL VirtualFree(void*,SIZE_T,DWORD);
BOOL VirtualQuery(void*,void*,SIZE_T);
void AcquireSRWLockExclusive(SRWLOCK*); void AcquireSRWLockShared(SRWLOCK*);
void ReleaseSRWLockExclusive(SRWLOCK*); void ReleaseSRWLockShared(SRWLOCK*);
BOOL TryAcquireSRWLockExclusive(SRWLOCK*);
BOOL InitializeCriticalSectionEx(void*,DWORD,DWORD);
void InitializeSListHead(void*);
BOOL InitOnceBeginInitialize(void*,DWORD,BOOL*,void**);
BOOL InitOnceComplete(void*,DWORD,void*);
HANDLE GetCurrentProcess(void);
BOOL CreateProcessW(const void*,void*,void*,void*,BOOL,DWORD,void*,void*,void*,void*);
BOOL CreateProcessAsUserW(HANDLE,const void*,void*,void*,void*,BOOL,DWORD,void*,void*,void*,void*);
BOOL TerminateProcess(HANDLE,UINT);
DWORD GetModuleFileNameA(HMODULE,char*,DWORD);
DWORD GetModuleFileNameW(HMODULE,wchar_t*,DWORD);
BOOL GetModuleHandleExW(DWORD,const wchar_t*,HMODULE*);
HMODULE LoadLibraryExW(const wchar_t*, HANDLE, DWORD);
DWORD GetVersion(void);
HANDLE OpenThread(DWORD,BOOL,DWORD);
BOOL GetThreadGroupAffinity(void*,void*);
void CreateThreadpoolTimer(void**,void*,void*);
void CloseThreadpoolTimer(void*);
void SetThreadpoolTimer(void*,void*,ULONG,ULONG);
void WaitForThreadpoolTimerCallbacks(void*,BOOL);
BOOL InitializeProcThreadAttributeList(void*,DWORD,DWORD,SIZE_T*);
void DeleteProcThreadAttributeList(void*);
BOOL UpdateProcThreadAttribute(void*,DWORD,DWORD,void*,SIZE_T,void*,void*);
BOOL ReadProcessMemory(HANDLE,void*,void*,SIZE_T,SIZE_T*);
void SetUnhandledExceptionFilter(void*);
long UnhandledExceptionFilter(void*);
UINT SetErrorMode(UINT);
BOOL DuplicateHandle(HANDLE,HANDLE,HANDLE,HANDLE*,DWORD,BOOL,DWORD);
HANDLE GetStdHandle(DWORD);
BOOL ReadConsoleW(HANDLE,void*,DWORD,DWORD*,void*);
DWORD GetConsoleOutputCP(void); HWND GetConsoleWindow(void);
BOOL SetConsoleCursorPosition(HANDLE,DWORD);
BOOL ScrollConsoleScreenBufferW(HANDLE,void*,void*,COORD,void*);
BOOL FlushConsoleInputBuffer(HANDLE);
BOOL SetConsoleCtrlHandler(void*,BOOL);
HANDLE FindFirstFileW(const wchar_t*,void*);
BOOL FindNextFileW(HANDLE,void*); BOOL FindClose(HANDLE);
BOOL FindFirstFileExW(const wchar_t*,int,void*);
BOOL FindFirstStreamWStub(const wchar_t*,int,void*,DWORD);
BOOL FindNextStreamWStub(HANDLE,void*);
DWORD GetFileType(HANDLE);
BOOL GetFileInformationByHandleEx(HANDLE,int,void*,DWORD);
BOOL GetFileAttributesExW(const wchar_t*,int,void*);
BOOL GetFileSecurityW(const wchar_t*,DWORD,void*,DWORD,DWORD*);
DWORD SearchPathW(const wchar_t*,const wchar_t*,const wchar_t*,DWORD,wchar_t*,wchar_t**);
BOOL GetVolumeInformationW(const wchar_t*,wchar_t*,DWORD,DWORD*,DWORD*,DWORD*,wchar_t*,DWORD);
BOOL GetVolumePathNameW(const wchar_t*,wchar_t*,DWORD);
DWORD GetDriveTypeW(const wchar_t*);
BOOL GetDiskFreeSpaceExW(const wchar_t*,unsigned long long*,unsigned long long*,unsigned long long*);
BOOL SetEndOfFile(HANDLE); BOOL SetFileTime(HANDLE,void*,void*,void*);
BOOL MoveFileExW(const wchar_t*,const wchar_t*,DWORD);
BOOL MoveFileWithProgressW(const wchar_t*,const wchar_t*,void*,void*,DWORD);
BOOL CopyFileW(const wchar_t*,const wchar_t*,BOOL);
    BOOL CopyFileExW(const wchar_t*,const wchar_t*,void*,void*,void*,DWORD);
    void SetConsoleInputExeNameW(const wchar_t*);
BOOL CreateHardLinkW(const wchar_t*,const wchar_t*,void*);
BOOL CreateSymbolicLinkW(const wchar_t*,const wchar_t*,DWORD);
DWORD GetFullPathNameW(const wchar_t*,DWORD,wchar_t*,wchar_t**);
DWORD ExpandEnvironmentStringsW(const wchar_t*,wchar_t*,DWORD);
wchar_t* GetEnvironmentStringsW(void);
BOOL FreeEnvironmentStringsW(wchar_t*); BOOL SetEnvironmentStringsW(wchar_t*);
DWORD GetWindowsDirectoryW(wchar_t*,DWORD);
BOOL NeedCurrentDirectoryForExePathW(const wchar_t*);
wchar_t* GetCommandLineW(void);
DWORD FormatMessageW(DWORD,void*,DWORD,DWORD,wchar_t*,DWORD,void*);
BOOL CompareFileTime(const FILETIME*,const FILETIME*);
BOOL FileTimeToLocalFileTime(const FILETIME*,FILETIME*);
BOOL FileTimeToSystemTime(const FILETIME*,void*);
BOOL SystemTimeToFileTime(void*,FILETIME*);
int CompareStringOrdinal(const wchar_t*,int,const wchar_t*,int,BOOL);
BOOL GetLocaleInfoW(int,int,wchar_t*,int);
DWORD GetUserDefaultLCID(void); DWORD GetThreadLocale(void);
DWORD SetThreadLocale(DWORD);
BOOL GetTimeFormatW(int,DWORD,void*,const wchar_t*,wchar_t*,int);
BOOL GetDateFormatW(int,DWORD,void*,const wchar_t*,wchar_t*,int);
BOOL SetLocalTime(void*);
BOOL GetNumaHighestNodeNumber(ULONG*);
BOOL GetNumaNodeProcessorMaskEx(void*,void*);
BOOL GetCPInfo(int,void*); UINT GetACP(void);
DWORD WNetAddConnection2WStub(void*,void*,void*,DWORD);
DWORD WNetCancelConnection2WStub(void*,DWORD,DWORD);
DWORD WNetGetConnectionWStub(void*,void*,DWORD*);
void* BrandingFormatString(void*);
void CmdBatNotificationStub(void*);
void DoSHChangeNotify(DWORD,DWORD,void*,void*);
void* LookupAccountSidWStub(void*,void*,void*,DWORD*,void*,DWORD*,void*);
void GetVDMCurrentDirectoriesStub(void*,void*);
BOOL QueryFullProcessImageNameWStub(HANDLE,DWORD,wchar_t*,DWORD*);
void SaferWorker(void*,void*,void*,DWORD,void*);
BOOL ShellExecuteExW(void*);
void ShellExecuteWorker(void*,void*,void*,void*,void*,int);
int MultiByteToWideChar(UINT,DWORD,const char*,int,wchar_t*,int);
int WideCharToMultiByte(UINT,DWORD,const wchar_t*,int,char*,int,const char*,BOOL*);
int lstrcmpW(const wchar_t*,const wchar_t*); int lstrcmpiW(const wchar_t*,const wchar_t*);
HANDLE OpenSemaphoreW(DWORD,BOOL,const wchar_t*);
DWORD WaitForSingleObjectEx(HANDLE,DWORD,BOOL);
BOOL GetSecurityDescriptorOwner(void*,void**,BOOL*);
HANDLE RevertToSelf(void);
BOOL RegCloseKey(HKEY);
LONG RegOpenKeyExW(HKEY,const wchar_t*,DWORD,DWORD,HKEY*);
LONG RegCreateKeyExW(HKEY,const wchar_t*,DWORD,wchar_t*,DWORD,DWORD,void*,HKEY*,DWORD*);
LONG RegSetValueExW(HKEY,const wchar_t*,DWORD,DWORD,const BYTE*,DWORD);
LONG RegQueryValueExW(HKEY,const wchar_t*,DWORD*,DWORD*,BYTE*,DWORD*);
LONG RegDeleteValueW(HKEY,const wchar_t*);
LONG RegDeleteKeyExW(HKEY,const wchar_t*,DWORD,DWORD);
LONG RegEnumKeyExW(HKEY,DWORD,wchar_t*,DWORD*,DWORD*,wchar_t*,DWORD*,FILETIME*);
LONG RegGetValueW(HKEY,const wchar_t*,const wchar_t*,DWORD,DWORD*,BYTE*,DWORD*);
BOOL SetThreadUILanguage(UINT);
BOOL MessageBeepStub(UINT); void OutputDebugStringW(const wchar_t*);
void DebugBreak(void);
BOOL DeviceIoControl(HANDLE,DWORD,void*,DWORD,void*,DWORD,DWORD*,void*);
DWORD EventRegister(void*,void*,void*,void*);
DWORD EventSetInformation(void*,DWORD,void*,DWORD);
DWORD EventUnregister(void*);
DWORD EventWriteTransfer(void*,void*,void*,DWORD,void*);
HRESULT RoInitialize(int); void RoUninitialize(void);
BOOL ApiSetQueryApiSetPresence(void*,BOOL);
void* DelayLoadFailureHook(void*,void*);
void* ResolveDelayLoadedAPI(void*,void*,void*,void*,UINT,UINT);

// ntdll extensions
NTSTATUS NtCancelSynchronousIoFile(HANDLE,void*,void*);
NTSTATUS NtFsControlFile(HANDLE,void*,void*,void*,DWORD,void*,DWORD,void*,DWORD);
NTSTATUS NtOpenFile(PHANDLE,DWORD,void*,void*,DWORD,DWORD);
NTSTATUS NtOpenProcessToken(HANDLE,DWORD,PHANDLE);
NTSTATUS NtOpenThreadToken(HANDLE,DWORD,BOOL,PHANDLE);
NTSTATUS NtQueryInformationToken(HANDLE,int,void*,DWORD,DWORD*);
NTSTATUS NtQueryVolumeInformationFile(HANDLE,void*,void*,DWORD,int);
NTSTATUS NtSetInformationFile(HANDLE,void*,void*,DWORD,int);
NTSTATUS NtSetInformationProcess(HANDLE,int,void*,DWORD);
NTSTATUS NtQueryInformationProcess(HANDLE,int,void*,DWORD,DWORD*);
void RtlCaptureContext(void*);
void RtlVirtualUnwind(DWORD,ULONGLONG,ULONGLONG,void*);
void* RtlLookupFunctionEntry(ULONGLONG,ULONGLONG*,void*);
DWORD64 RtlFindLeastSignificantBit(ULONGLONG);
ULONG RtlNtStatusToDosError(NTSTATUS);
void RtlCreateUnicodeStringFromAsciiz(void*,const char*);
NTSTATUS RtlDosPathNameToNtPathName_U(const wchar_t*,void*,void*,void*);
NTSTATUS RtlDosPathNameToRelativeNtPathName_U_WithStatus(const wchar_t*,void*,void*,void*);
void RtlFreeUnicodeString(void*);
void RtlFreeHeap(void*,DWORD,void*);
void RtlReleaseRelativeName(void*);
NTSTATUS RtlRegisterFeatureConfigurationChangeNotification(const void*,void*,void*,void*,uint64_t*);
NTSTATUS RtlQueryFeatureConfiguration(ULONG,void*,ULONG,void*,ULONG*);
BOOL RtlDllShutdownInProgress(void);
void WilFailureNotifyWatchers(void*);
void LogStagedFeatureUsage(void*,void*,void*);
void RaiseFailFastException(void*,void*,DWORD);

// ucrtbase
FILE* _o___acrt_iob_func(int);
int _o___stdio_common_vfprintf(unsigned __int64,FILE*,const char*,void*,void*);
int _o___stdio_common_vswprintf(unsigned __int64,wchar_t*,size_t,const wchar_t*,void*,void*);
int _o___stdio_common_vswprintf_s(unsigned __int64,wchar_t*,size_t,const wchar_t*,void*,void*);
int _o___stdio_common_vswscanf(unsigned __int64,const wchar_t*,size_t,const wchar_t*,void*,void*);
int _o___stdio_common_vsprintf(unsigned __int64,char*,size_t,const char*,void*,void*);
int _o___stdio_common_vsscanf(unsigned __int64,const char*,size_t,const char*,void*,void*);
int _o_feof(void*); int _o_ferror(void*); int _o_fflush(void*);
char* _o_fgets(char*,int,void*);
void* _o_malloc(size_t); void* _o_calloc(size_t,size_t);
void* _o_realloc(void*,size_t); void _o_free(void*);
int _o__callnewh(size_t);
int _o__wcsicmp(const wchar_t*,const wchar_t*);
int _o__wcsnicmp(const wchar_t*,const wchar_t*,size_t);
wchar_t* _o__wcslwr(wchar_t*); wchar_t* _o__wcsupr(wchar_t*);
long _o__wtol(const wchar_t*);
wchar_t* _o__wpopen(const wchar_t*,const wchar_t*);
int _o__setmode(int,int); long _o__tell(int); int _o__getch(void);
int _o__get_osfhandle(int); int _o__open_osfhandle(intptr_t,int);
int _o__dup(int); int _o__dup2(int,int); int _o__close(int);
int _o__pclose(void*); int _o__pipe(int*,unsigned int,int);
char* _o_setlocale(int,const char*);
int _o__configthreadlocale(int); int _o__configure_narrow_argv(int);
int _o__initialize_narrow_environment(void);
char** _o__get_initial_narrow_environment(void);
char*** _o___p__environ(void); char* _o__get_home_dir(void);
int* _o___p___argc(void); char*** _o___p___argv(void);
void _o__cexit(void); void _o__c_exit(void); void _c_exit(void);
void _o_exit(int); void _o__exit(int);
int _o__crt_atexit(void(*)(void));
void _o_terminate(void); void _o__purecall(void);
void _o__invalid_parameter_noinfo(void);
int _o__seh_filter_exe(int,void*);
int* _o__errno(void);
long _o_wcstol(const wchar_t*,wchar_t**,int);
unsigned long _o_wcstoul(const wchar_t*,wchar_t**,int);
char* _o__ultoa(unsigned long,char*,int);
char* _o__ultoa_s(unsigned long,char*,size_t,int);
int* _o___p__commode(void);
void _o_qsort(void*,size_t,size_t,int(*)(const void*,const void*));
int _o_rand(void); void _o_srand(unsigned int);
int _o__set_app_type(int); void _o__set_fmode(int); void _o__set_new_mode(int);
void _o__initialize_onexit_table(void*);
int _o__register_onexit_function(void*,void*);
int _register_thread_local_exe_atexit_callback(void*);
void _initterm(void**,void**); int _initterm_e(void**,void**);
NTSTATUS __C_specific_handler(void*,void*,void*,void*);
void** __current_exception(void); void** __current_exception_context(void);
int __CxxFrameHandler3(void*,void*,void*,void*);
void _CxxThrowException(void*,void*);
void _local_unwind(void*,void*);
wint_t _o_iswalpha(wint_t); wint_t _o_iswdigit(wint_t);
wint_t _o_iswspace(wint_t); wint_t _o_iswxdigit(wint_t);
wint_t _o_towlower(wint_t); wint_t _o_towupper(wint_t);
void _o___std_exception_copy(void*,void*);
void _o___std_exception_destroy(void*);
time_t _time32(time_t*);

static const API_ENTRY g_api_table[] = {
    // kernel32 — core
    {"kernel32.dll","GetLastError",(void*)win32_get_last_error},
    {"kernel32.dll","SetLastError",(void*)win32_set_last_error},
    {"kernel32.dll","CreateFileA",(void*)win32_create_file},
    {"kernel32.dll","CreateFileW",(void*)win32_create_file},
    {"kernel32.dll","ReadFile",(void*)win32_read_file},
    {"kernel32.dll","WriteFile",(void*)win32_write_file},
    {"kernel32.dll","CloseHandle",(void*)win32_close_handle},
    {"kernel32.dll","GetFileSize",(void*)win32_get_file_size},
    {"kernel32.dll","GetFileSizeEx",(void*)win32_get_file_size},
    {"kernel32.dll","FlushFileBuffers",(void*)win32_flush_file_buffers},
    {"kernel32.dll","SetFilePointer",(void*)win32_set_file_pointer},
    {"kernel32.dll","SetFilePointerEx",(void*)win32_set_file_pointer},
    {"kernel32.dll","GetFileTime",(void*)win32_get_file_time},
    {"kernel32.dll","GetFullPathNameA",(void*)win32_get_full_path_name},
    {"kernel32.dll","GetFullPathNameW",(void*)GetFullPathNameW},
    {"kernel32.dll","MultiByteToWideChar",(void*)MultiByteToWideChar},
    {"kernel32.dll","WideCharToMultiByte",(void*)WideCharToMultiByte},
    {"kernel32.dll","lstrcmpW",(void*)lstrcmpW},
    {"kernel32.dll","lstrcmpiW",(void*)lstrcmpiW},
    {"kernel32.dll","OpenSemaphoreW",(void*)OpenSemaphoreW},
    {"kernel32.dll","WaitForSingleObjectEx",(void*)WaitForSingleObjectEx},
    {"kernel32.dll","GetSecurityDescriptorOwner",(void*)GetSecurityDescriptorOwner},
    {"kernel32.dll","RevertToSelf",(void*)RevertToSelf},
    {"kernel32.dll","RegCloseKey",(void*)RegCloseKey},
    {"kernel32.dll","RegOpenKeyExW",(void*)RegOpenKeyExW},
    {"kernel32.dll","RegCreateKeyExW",(void*)RegCreateKeyExW},
    {"kernel32.dll","RegSetValueExW",(void*)RegSetValueExW},
    {"kernel32.dll","RegQueryValueExW",(void*)RegQueryValueExW},
    {"kernel32.dll","RegDeleteValueW",(void*)RegDeleteValueW},
    {"kernel32.dll","RegDeleteKeyExW",(void*)RegDeleteKeyExW},
    {"kernel32.dll","RegEnumKeyExW",(void*)RegEnumKeyExW},
    {"kernel32.dll","RegGetValueW",(void*)RegGetValueW},
    {"kernel32.dll","SetEnvironmentStringsW",(void*)SetEnvironmentStringsW},
    {"kernel32.dll","SetThreadUILanguage",(void*)SetThreadUILanguage},
    {"kernel32.dll","GetTempPathA",(void*)win32_get_temp_path},
    {"kernel32.dll","GetTempPathW",(void*)win32_get_temp_path},
    {"kernel32.dll","GetTempFileNameA",(void*)win32_get_temp_file_name},
    {"kernel32.dll","GetTempFileNameW",(void*)win32_get_temp_file_name},
    {"kernel32.dll","CreateDirectoryA",(void*)win32_create_directory},
    {"kernel32.dll","CreateDirectoryW",(void*)win32_create_directory},
    {"kernel32.dll","RemoveDirectoryA",(void*)win32_remove_directory},
    {"kernel32.dll","RemoveDirectoryW",(void*)win32_remove_directory},
    {"kernel32.dll","DeleteFileA",(void*)win32_delete_file},
    {"kernel32.dll","DeleteFileW",(void*)win32_delete_file},
    {"kernel32.dll","MoveFileA",(void*)win32_move_file},
    {"kernel32.dll","MoveFileW",(void*)win32_move_file},
    {"kernel32.dll","MoveFileExA",(void*)win32_move_file},
    {"kernel32.dll","MoveFileExW",(void*)MoveFileExW},
    {"kernel32.dll","MoveFileWithProgressW",(void*)MoveFileWithProgressW},
    {"kernel32.dll","CopyFileA",(void*)win32_copy_file},
    {"kernel32.dll","CopyFileW",(void*)CopyFileW},
    {"kernel32.dll","CopyFileExW",(void*)CopyFileExW},
    {"kernel32.dll","SetConsoleInputExeNameW",(void*)SetConsoleInputExeNameW},
    {"kernel32.dll","GetFileAttributesA",(void*)win32_get_file_attributes},
    {"kernel32.dll","GetFileAttributesW",(void*)win32_get_file_attributes},
    {"kernel32.dll","SetFileAttributesA",(void*)win32_set_file_attributes},
    {"kernel32.dll","SetFileAttributesW",(void*)win32_set_file_attributes},
    {"kernel32.dll","SetCurrentDirectoryA",(void*)win32_set_current_directory},
    {"kernel32.dll","SetCurrentDirectoryW",(void*)win32_set_current_directory},
    {"kernel32.dll","GetCurrentDirectoryA",(void*)win32_get_current_directory},
    {"kernel32.dll","GetCurrentDirectoryW",(void*)win32_get_current_directory},
    {"kernel32.dll","AllocConsole",(void*)win32_alloc_console},
    {"kernel32.dll","FreeConsole",(void*)win32_free_console},
    {"kernel32.dll","SetConsoleTitleA",(void*)win32_set_console_title},
    {"kernel32.dll","SetConsoleTitleW",(void*)win32_set_console_title},
    {"kernel32.dll","GetConsoleTitleA",(void*)win32_get_console_title},
    {"kernel32.dll","GetConsoleTitleW",(void*)win32_get_console_title},
    {"kernel32.dll","SetConsoleCursorInfo",(void*)win32_set_console_cursor_info},
    {"kernel32.dll","GetConsoleCursorInfo",(void*)win32_get_console_cursor_info},
    {"kernel32.dll","ReadConsoleInputA",(void*)win32_read_console_input},
    {"kernel32.dll","ReadConsoleInputW",(void*)win32_read_console_input},
    {"kernel32.dll","WriteConsoleA",(void*)win32_write_console},
    {"kernel32.dll","WriteConsoleW",(void*)win32_write_console},
    {"kernel32.dll","SetConsoleMode",(void*)win32_set_console_mode},
    {"kernel32.dll","GetConsoleMode",(void*)win32_get_console_mode},
    {"kernel32.dll","GetConsoleScreenBufferInfo",(void*)win32_get_console_screen_buffer_info},
    {"kernel32.dll","FillConsoleOutputCharacterA",(void*)win32_fill_console_output_character},
    {"kernel32.dll","FillConsoleOutputCharacterW",(void*)win32_fill_console_output_character},
    {"kernel32.dll","FillConsoleOutputAttribute",(void*)win32_fill_console_output_attribute},
    {"kernel32.dll","SetConsoleTextAttribute",(void*)win32_set_console_text_attribute},
    {"kernel32.dll","Sleep",(void*)win32_sleep},
    {"kernel32.dll","GetTickCount",(void*)win32_get_tick_count},
    {"kernel32.dll","GetSystemTime",(void*)win32_get_system_time},
    {"kernel32.dll","GetLocalTime",(void*)win32_get_local_time},
    {"kernel32.dll","GetSystemTimeAsFileTime",(void*)win32_get_system_time_as_file_time},
    {"kernel32.dll","QueryPerformanceCounter",(void*)win32_query_performance_counter},
    {"kernel32.dll","QueryPerformanceFrequency",(void*)win32_query_performance_frequency},
    {"kernel32.dll","InitializeCriticalSection",(void*)win32_initialize_critical_section},
    {"kernel32.dll","EnterCriticalSection",(void*)win32_enter_critical_section},
    {"kernel32.dll","LeaveCriticalSection",(void*)win32_leave_critical_section},
    {"kernel32.dll","DeleteCriticalSection",(void*)win32_delete_critical_section},
    {"kernel32.dll","CreateMutexA",(void*)win32_create_mutex},
    {"kernel32.dll","CreateMutexW",(void*)win32_create_mutex},
    {"kernel32.dll","CreateMutexExW",(void*)win32_create_mutex},
    {"kernel32.dll","ReleaseMutex",(void*)win32_release_mutex},
    {"kernel32.dll","CreateEventA",(void*)win32_create_event},
    {"kernel32.dll","CreateEventW",(void*)win32_create_event},
    {"kernel32.dll","CreateEventExA",(void*)win32_create_event},
    {"kernel32.dll","CreateEventExW",(void*)win32_create_event},
    {"kernel32.dll","SetEvent",(void*)win32_set_event},
    {"kernel32.dll","ResetEvent",(void*)win32_reset_event},
    {"kernel32.dll","CreateSemaphoreA",(void*)win32_create_semaphore},
    {"kernel32.dll","CreateSemaphoreW",(void*)win32_create_semaphore},
    {"kernel32.dll","CreateSemaphoreExW",(void*)win32_create_semaphore},
    {"kernel32.dll","ReleaseSemaphore",(void*)win32_release_semaphore},
    {"kernel32.dll","WaitForSingleObject",(void*)win32_wait_for_single_object},
    {"kernel32.dll","WaitForMultipleObjects",(void*)win32_wait_for_multiple_objects},
    {"kernel32.dll","SleepEx",(void*)win32_sleep_ex},
    {"kernel32.dll","GetCurrentThreadId",(void*)win32_get_current_thread_id},
    {"kernel32.dll","GetCurrentProcessId",(void*)win32_get_current_process_id},
    {"kernel32.dll","CreateThread",(void*)win32_create_thread},
    {"kernel32.dll","SuspendThread",(void*)win32_suspend_thread},
    {"kernel32.dll","ResumeThread",(void*)win32_resume_thread},
    {"kernel32.dll","TerminateThread",(void*)win32_terminate_thread},
    {"kernel32.dll","GetThreadId",(void*)win32_get_thread_id},
    {"kernel32.dll","GetExitCodeThread",(void*)win32_get_exit_code_thread},
    {"kernel32.dll","GetExitCodeProcess",(void*)win32_get_exit_code_process},
    {"kernel32.dll","TlsAlloc",(void*)win32_tls_alloc},
    {"kernel32.dll","TlsFree",(void*)win32_tls_free},
    {"kernel32.dll","TlsGetValue",(void*)win32_tls_get_value},
    {"kernel32.dll","TlsSetValue",(void*)win32_tls_set_value},
    {"kernel32.dll","GetStartupInfoA",(void*)win32_get_startup_info},
    {"kernel32.dll","GetStartupInfoW",(void*)win32_get_startup_info},
    {"kernel32.dll","ExitProcess",(void*)win32_exit_process},
    {"kernel32.dll","ExitThread",(void*)win32_exit_thread},
    {"kernel32.dll","IsDebuggerPresent",(void*)win32_is_debugger_present},
    {"kernel32.dll","OutputDebugStringA",(void*)win32_output_debug_string},
    {"kernel32.dll","OutputDebugStringW",(void*)win32_output_debug_string},
    {"kernel32.dll","GetSystemInfo",(void*)win32_get_system_info},
    {"kernel32.dll","GetNativeSystemInfo",(void*)win32_get_system_info},
    {"kernel32.dll","GetEnvironmentVariableA",(void*)win32_get_environment_variable},
    {"kernel32.dll","GetEnvironmentVariableW",(void*)win32_get_environment_variable},
    {"kernel32.dll","SetEnvironmentVariableA",(void*)win32_set_environment_variable},
    {"kernel32.dll","SetEnvironmentVariableW",(void*)win32_set_environment_variable},
    {"kernel32.dll","GetModuleHandleA",(void*)win32_get_module_handle},
    {"kernel32.dll","GetModuleHandleW",(void*)win32_get_module_handle},
    {"kernel32.dll","GetModuleHandleExA",(void*)win32_get_module_handle},
    {"kernel32.dll","GetModuleHandleExW",(void*)GetModuleHandleExW},
    {"kernel32.dll","GetModuleFileNameA",(void*)GetModuleFileNameA},
    {"kernel32.dll","GetModuleFileNameW",(void*)GetModuleFileNameW},
    {"kernel32.dll","GetProcAddress",(void*)win32_get_proc_address},
    {"kernel32.dll","LoadLibraryExW",(void*)LoadLibraryExW},
    {"kernel32.dll","GetCommandLineW",(void*)GetCommandLineW},
    {"kernel32.dll","GetVersion",(void*)GetVersion},
    {"kernel32.dll","OpenThread",(void*)OpenThread},
    {"kernel32.dll","GetCurrentProcess",(void*)GetCurrentProcess},
    {"kernel32.dll","GetProcessHeap",(void*)GetProcessHeap},
    {"kernel32.dll","HeapAlloc",(void*)HeapAlloc},
    {"kernel32.dll","HeapFree",(void*)HeapFree},
    {"kernel32.dll","HeapReAlloc",(void*)HeapReAlloc},
    {"kernel32.dll","HeapSize",(void*)HeapSize},
    {"kernel32.dll","HeapSetInformation",(void*)HeapSetInformation},
    {"kernel32.dll","GlobalAlloc",(void*)GlobalAlloc},
    {"kernel32.dll","GlobalFree",(void*)GlobalFree},
    {"kernel32.dll","LocalAlloc",(void*)LocalAlloc},
    {"kernel32.dll","LocalFree",(void*)LocalFree},
    {"kernel32.dll","VirtualAlloc",(void*)VirtualAlloc},
    {"kernel32.dll","VirtualFree",(void*)VirtualFree},
    {"kernel32.dll","VirtualQuery",(void*)VirtualQuery},
    {"kernel32.dll","AcquireSRWLockExclusive",(void*)AcquireSRWLockExclusive},
    {"kernel32.dll","AcquireSRWLockShared",(void*)AcquireSRWLockShared},
    {"kernel32.dll","ReleaseSRWLockExclusive",(void*)ReleaseSRWLockExclusive},
    {"kernel32.dll","ReleaseSRWLockShared",(void*)ReleaseSRWLockShared},
    {"kernel32.dll","TryAcquireSRWLockExclusive",(void*)TryAcquireSRWLockExclusive},
    {"kernel32.dll","InitializeCriticalSectionEx",(void*)InitializeCriticalSectionEx},
    {"kernel32.dll","InitializeSListHead",(void*)InitializeSListHead},
    {"kernel32.dll","InitOnceBeginInitialize",(void*)InitOnceBeginInitialize},
    {"kernel32.dll","InitOnceComplete",(void*)InitOnceComplete},
    {"kernel32.dll","CreateProcessW",(void*)CreateProcessW},
    {"kernel32.dll","CreateProcessAsUserW",(void*)CreateProcessAsUserW},
    {"kernel32.dll","TerminateProcess",(void*)TerminateProcess},
    {"kernel32.dll","GetThreadGroupAffinity",(void*)GetThreadGroupAffinity},
    {"kernel32.dll","CreateThreadpoolTimer",(void*)CreateThreadpoolTimer},
    {"kernel32.dll","CloseThreadpoolTimer",(void*)CloseThreadpoolTimer},
    {"kernel32.dll","SetThreadpoolTimer",(void*)SetThreadpoolTimer},
    {"kernel32.dll","WaitForThreadpoolTimerCallbacks",(void*)WaitForThreadpoolTimerCallbacks},
    {"kernel32.dll","InitializeProcThreadAttributeList",(void*)InitializeProcThreadAttributeList},
    {"kernel32.dll","DeleteProcThreadAttributeList",(void*)DeleteProcThreadAttributeList},
    {"kernel32.dll","UpdateProcThreadAttribute",(void*)UpdateProcThreadAttribute},
    {"kernel32.dll","ReadProcessMemory",(void*)ReadProcessMemory},
    {"kernel32.dll","SetUnhandledExceptionFilter",(void*)SetUnhandledExceptionFilter},
    {"kernel32.dll","UnhandledExceptionFilter",(void*)UnhandledExceptionFilter},
    {"kernel32.dll","SetErrorMode",(void*)SetErrorMode},
    {"kernel32.dll","DuplicateHandle",(void*)DuplicateHandle},
    {"kernel32.dll","GetStdHandle",(void*)GetStdHandle},
    {"kernel32.dll","ReadConsoleW",(void*)ReadConsoleW},
    {"kernel32.dll","GetConsoleOutputCP",(void*)GetConsoleOutputCP},
    {"kernel32.dll","GetConsoleWindow",(void*)GetConsoleWindow},
    {"kernel32.dll","SetConsoleCursorPosition",(void*)SetConsoleCursorPosition},
    {"kernel32.dll","ScrollConsoleScreenBufferW",(void*)ScrollConsoleScreenBufferW},
    {"kernel32.dll","FlushConsoleInputBuffer",(void*)FlushConsoleInputBuffer},
    {"kernel32.dll","SetConsoleCtrlHandler",(void*)SetConsoleCtrlHandler},
    {"kernel32.dll","FindFirstFileW",(void*)FindFirstFileW},
    {"kernel32.dll","FindFirstFileExW",(void*)FindFirstFileExW},
    {"kernel32.dll","FindNextFileW",(void*)FindNextFileW},
    {"kernel32.dll","FindClose",(void*)FindClose},
    {"kernel32.dll","FindFirstStreamWStub",(void*)FindFirstStreamWStub},
    {"kernel32.dll","FindNextStreamWStub",(void*)FindNextStreamWStub},
    {"kernel32.dll","GetFileType",(void*)GetFileType},
    {"kernel32.dll","GetFileInformationByHandleEx",(void*)GetFileInformationByHandleEx},
    {"kernel32.dll","GetFileAttributesExW",(void*)GetFileAttributesExW},
    {"kernel32.dll","GetFileSecurityW",(void*)GetFileSecurityW},
    {"kernel32.dll","SearchPathW",(void*)SearchPathW},
    {"kernel32.dll","GetVolumeInformationW",(void*)GetVolumeInformationW},
    {"kernel32.dll","GetVolumePathNameW",(void*)GetVolumePathNameW},
    {"kernel32.dll","GetDriveTypeW",(void*)GetDriveTypeW},
    {"kernel32.dll","GetDiskFreeSpaceExW",(void*)GetDiskFreeSpaceExW},
    {"kernel32.dll","SetEndOfFile",(void*)SetEndOfFile},
    {"kernel32.dll","SetFileTime",(void*)SetFileTime},
    {"kernel32.dll","CreateHardLinkW",(void*)CreateHardLinkW},
    {"kernel32.dll","CreateSymbolicLinkW",(void*)CreateSymbolicLinkW},
    {"kernel32.dll","ExpandEnvironmentStringsW",(void*)ExpandEnvironmentStringsW},
    {"kernel32.dll","GetEnvironmentStringsW",(void*)GetEnvironmentStringsW},
    {"kernel32.dll","FreeEnvironmentStringsW",(void*)FreeEnvironmentStringsW},
    {"kernel32.dll","GetWindowsDirectoryW",(void*)GetWindowsDirectoryW},
    {"kernel32.dll","NeedCurrentDirectoryForExePathW",(void*)NeedCurrentDirectoryForExePathW},
    {"kernel32.dll","FormatMessageW",(void*)FormatMessageW},
    {"kernel32.dll","CompareFileTime",(void*)CompareFileTime},
    {"kernel32.dll","FileTimeToLocalFileTime",(void*)FileTimeToLocalFileTime},
    {"kernel32.dll","FileTimeToSystemTime",(void*)FileTimeToSystemTime},
    {"kernel32.dll","SystemTimeToFileTime",(void*)SystemTimeToFileTime},
    {"kernel32.dll","CompareStringOrdinal",(void*)CompareStringOrdinal},
    {"kernel32.dll","GetLocaleInfoW",(void*)GetLocaleInfoW},
    {"kernel32.dll","GetUserDefaultLCID",(void*)GetUserDefaultLCID},
    {"kernel32.dll","GetThreadLocale",(void*)GetThreadLocale},
    {"kernel32.dll","SetThreadLocale",(void*)SetThreadLocale},
    {"kernel32.dll","GetTimeFormatW",(void*)GetTimeFormatW},
    {"kernel32.dll","GetDateFormatW",(void*)GetDateFormatW},
    {"kernel32.dll","SetLocalTime",(void*)SetLocalTime},
    {"kernel32.dll","GetCPInfo",(void*)GetCPInfo},
    {"kernel32.dll","GetACP",(void*)GetACP},
    {"kernel32.dll","GetNumaHighestNodeNumber",(void*)GetNumaHighestNodeNumber},
    {"kernel32.dll","GetNumaNodeProcessorMaskEx",(void*)GetNumaNodeProcessorMaskEx},
    {"kernel32.dll","IsProcessorFeaturePresent",(void*)win32_is_debugger_present},
    {"kernel32.dll","BrandingFormatString",(void*)BrandingFormatString},
    {"kernel32.dll","CmdBatNotificationStub",(void*)CmdBatNotificationStub},
    {"kernel32.dll","DoSHChangeNotify",(void*)DoSHChangeNotify},
    {"kernel32.dll","GetVDMCurrentDirectoriesStub",(void*)GetVDMCurrentDirectoriesStub},
    {"kernel32.dll","LookupAccountSidWStub",(void*)LookupAccountSidWStub},
    {"kernel32.dll","QueryFullProcessImageNameWStub",(void*)QueryFullProcessImageNameWStub},
    {"kernel32.dll","SaferWorker",(void*)SaferWorker},
    {"kernel32.dll","ShellExecuteExW",(void*)ShellExecuteExW},
    {"kernel32.dll","ShellExecuteWorker",(void*)ShellExecuteWorker},
    {"kernel32.dll","MessageBeep",(void*)MessageBeepStub},
    {"kernelbase.dll","MessageBeepStub",(void*)MessageBeepStub},
    {"kernel32.dll","DebugBreak",(void*)DebugBreak},
    {"kernel32.dll","DeviceIoControl",(void*)DeviceIoControl},
    {"kernel32.dll","EventRegister",(void*)EventRegister},
    {"kernel32.dll","EventSetInformation",(void*)EventSetInformation},
    {"kernel32.dll","EventUnregister",(void*)EventUnregister},
    {"kernel32.dll","EventWriteTransfer",(void*)EventWriteTransfer},
    {"kernel32.dll","RoInitialize",(void*)RoInitialize},
    {"kernel32.dll","RoUninitialize",(void*)RoUninitialize},
    {"kernel32.dll","ApiSetQueryApiSetPresence",(void*)ApiSetQueryApiSetPresence},
    {"kernel32.dll","DelayLoadFailureHook",(void*)DelayLoadFailureHook},
    {"kernel32.dll","ResolveDelayLoadedAPI",(void*)ResolveDelayLoadedAPI},
    {"mpr.dll","WNetAddConnection2WStub",(void*)WNetAddConnection2WStub},
    {"mpr.dll","WNetCancelConnection2WStub",(void*)WNetCancelConnection2WStub},
    {"mpr.dll","WNetGetConnectionWStub",(void*)WNetGetConnectionWStub},
    // ntdll
    {"ntdll.dll","NtCreateThread",(void*)nt_create_thread},
    {"ntdll.dll","NtCreateUserThread",(void*)nt_create_thread},
    {"ntdll.dll","NtResumeThread",(void*)nt_resume_thread},
    {"ntdll.dll","NtWaitForSingleObject",(void*)nt_wait_for_single_object},
    {"ntdll.dll","NtClose",(void*)nt_close},
    {"ntdll.dll","NtCreateEvent",(void*)nt_create_event},
    {"ntdll.dll","NtSetEvent",(void*)nt_set_event},
    {"ntdll.dll","NtQuerySystemInformation",(void*)nt_query_system_information},
    {"ntdll.dll","NtQueryInformationProcess",(void*)nt_query_information_process},
    {"ntdll.dll","NtSetInformationProcess",(void*)nt_set_information_process},
    {"ntdll.dll","NtQueryInformationThread",(void*)nt_query_information_thread},
    {"ntdll.dll","NtTerminateProcess",(void*)nt_terminate_process},
    {"ntdll.dll","NtCreateProcess",(void*)nt_create_process},
    {"ntdll.dll","NtCancelSynchronousIoFile",(void*)NtCancelSynchronousIoFile},
    {"ntdll.dll","NtFsControlFile",(void*)NtFsControlFile},
    {"ntdll.dll","NtOpenFile",(void*)NtOpenFile},
    {"ntdll.dll","NtOpenProcessToken",(void*)NtOpenProcessToken},
    {"ntdll.dll","NtOpenThreadToken",(void*)NtOpenThreadToken},
    {"ntdll.dll","NtQueryInformationToken",(void*)NtQueryInformationToken},
    {"ntdll.dll","NtQueryVolumeInformationFile",(void*)NtQueryVolumeInformationFile},
    {"ntdll.dll","NtSetInformationFile",(void*)NtSetInformationFile},
    {"ntdll.dll","RtlCaptureContext",(void*)RtlCaptureContext},
    {"ntdll.dll","RtlVirtualUnwind",(void*)RtlVirtualUnwind},
    {"ntdll.dll","RtlLookupFunctionEntry",(void*)RtlLookupFunctionEntry},
    {"ntdll.dll","RtlFindLeastSignificantBit",(void*)RtlFindLeastSignificantBit},
    {"ntdll.dll","RtlNtStatusToDosError",(void*)RtlNtStatusToDosError},
    {"ntdll.dll","RtlCreateUnicodeStringFromAsciiz",(void*)RtlCreateUnicodeStringFromAsciiz},
    {"ntdll.dll","RtlDosPathNameToNtPathName_U",(void*)RtlDosPathNameToNtPathName_U},
    {"ntdll.dll","RtlDosPathNameToRelativeNtPathName_U_WithStatus",(void*)RtlDosPathNameToRelativeNtPathName_U_WithStatus},
    {"ntdll.dll","RtlFreeUnicodeString",(void*)RtlFreeUnicodeString},
    {"ntdll.dll","RtlFreeHeap",(void*)RtlFreeHeap},
    {"ntdll.dll","RtlReleaseRelativeName",(void*)RtlReleaseRelativeName},
    {"ntdll.dll","RtlAllocateHeap",(void*)HeapAlloc},
    {"ntdll.dll","RtlReAllocateHeap",(void*)HeapReAlloc},
    {"ntdll.dll","RtlSizeHeap",(void*)HeapSize},
    {"ntdll.dll","RtlDisownModuleHeapAllocation",(void*)RtlDisownModuleHeapAllocation},
    {"ntdll.dll","RtlRegisterFeatureConfigurationChangeNotification",(void*)RtlRegisterFeatureConfigurationChangeNotification},
    {"ntdll.dll","RtlQueryFeatureConfiguration",(void*)RtlQueryFeatureConfiguration},
    {"ntdll.dll","RtlDllShutdownInProgress",(void*)RtlDllShutdownInProgress},
    {"ntdll.dll","WilFailureNotifyWatchers",(void*)WilFailureNotifyWatchers},
    {"ntdll.dll","LogStagedFeatureUsage",(void*)LogStagedFeatureUsage},
    // ucrtbase
    {"ucrtbase.dll","_o___acrt_iob_func",(void*)_o___acrt_iob_func},
    {"ucrtbase.dll","_o___stdio_common_vfprintf",(void*)_o___stdio_common_vfprintf},
    {"ucrtbase.dll","_o___stdio_common_vswprintf",(void*)_o___stdio_common_vswprintf},
    {"ucrtbase.dll","_o___stdio_common_vswprintf_s",(void*)_o___stdio_common_vswprintf_s},
    {"ucrtbase.dll","_o___stdio_common_vswscanf",(void*)_o___stdio_common_vswscanf},
    {"ucrtbase.dll","_o___stdio_common_vsprintf",(void*)_o___stdio_common_vsprintf},
    {"ucrtbase.dll","_o___stdio_common_vsscanf",(void*)_o___stdio_common_vsscanf},
    {"ucrtbase.dll","_o_feof",(void*)_o_feof},
    {"ucrtbase.dll","_o_ferror",(void*)_o_ferror},
    {"ucrtbase.dll","_o_fflush",(void*)_o_fflush},
    {"ucrtbase.dll","_o_fgets",(void*)_o_fgets},
    {"ucrtbase.dll","_o_malloc",(void*)_o_malloc},
    {"ucrtbase.dll","_o_calloc",(void*)_o_calloc},
    {"ucrtbase.dll","_o_realloc",(void*)_o_realloc},
    {"ucrtbase.dll","_o_free",(void*)_o_free},
    {"ucrtbase.dll","_o__callnewh",(void*)_o__callnewh},
    {"ucrtbase.dll","_o__wcsicmp",(void*)_o__wcsicmp},
    {"ucrtbase.dll","_o__wcsnicmp",(void*)_o__wcsnicmp},
    {"ucrtbase.dll","_o__wcslwr",(void*)_o__wcslwr},
    {"ucrtbase.dll","_o__wcsupr",(void*)_o__wcsupr},
    {"ucrtbase.dll","_o__wtol",(void*)_o__wtol},
    {"ucrtbase.dll","_o__wpopen",(void*)_o__wpopen},
    {"ucrtbase.dll","_o__setmode",(void*)_o__setmode},
    {"ucrtbase.dll","_o__tell",(void*)_o__tell},
    {"ucrtbase.dll","_o__getch",(void*)_o__getch},
    {"ucrtbase.dll","_o__get_osfhandle",(void*)_o__get_osfhandle},
    {"ucrtbase.dll","_o__open_osfhandle",(void*)_o__open_osfhandle},
    {"ucrtbase.dll","_o__dup",(void*)_o__dup},
    {"ucrtbase.dll","_o__dup2",(void*)_o__dup2},
    {"ucrtbase.dll","_o__close",(void*)_o__close},
    {"ucrtbase.dll","_o__pclose",(void*)_o__pclose},
    {"ucrtbase.dll","_o__pipe",(void*)_o__pipe},
    {"ucrtbase.dll","_o_setlocale",(void*)_o_setlocale},
    {"ucrtbase.dll","_o__configthreadlocale",(void*)_o__configthreadlocale},
    {"ucrtbase.dll","_o__configure_narrow_argv",(void*)_o__configure_narrow_argv},
    {"ucrtbase.dll","_o__initialize_narrow_environment",(void*)_o__initialize_narrow_environment},
    {"ucrtbase.dll","_o__get_initial_narrow_environment",(void*)_o__get_initial_narrow_environment},
    {"ucrtbase.dll","_o__get_home_dir",(void*)_o__get_home_dir},
    {"ucrtbase.dll","_o___p___argc",(void*)_o___p___argc},
    {"ucrtbase.dll","_o___p___argv",(void*)_o___p___argv},
    {"ucrtbase.dll","_o___p__commode",(void*)_o___p__commode},
    {"ucrtbase.dll","_o__ultoa_s",(void*)_o__ultoa_s},
    {"ucrtbase.dll","_c_exit",(void*)_c_exit},
    {"ucrtbase.dll","_o__cexit",(void*)_o__cexit},
    {"ucrtbase.dll","_o__c_exit",(void*)_o__c_exit},
    {"ucrtbase.dll","_o_exit",(void*)_o_exit},
    {"ucrtbase.dll","_o__exit",(void*)_o__exit},
    {"ucrtbase.dll","_o__crt_atexit",(void*)_o__crt_atexit},
    {"ucrtbase.dll","_o_terminate",(void*)_o_terminate},
    {"ucrtbase.dll","_o__purecall",(void*)_o__purecall},
    {"ucrtbase.dll","_o__invalid_parameter_noinfo",(void*)_o__invalid_parameter_noinfo},
    {"ucrtbase.dll","_o__seh_filter_exe",(void*)_o__seh_filter_exe},
    {"ucrtbase.dll","_o__errno",(void*)_o__errno},
    {"ucrtbase.dll","_o_wcstol",(void*)_o_wcstol},
    {"ucrtbase.dll","_o_wcstoul",(void*)_o_wcstoul},
    {"ucrtbase.dll","_o__ultoa",(void*)_o__ultoa},
    {"ucrtbase.dll","_o_qsort",(void*)_o_qsort},
    {"ucrtbase.dll","_o_rand",(void*)_o_rand},
    {"ucrtbase.dll","_o_srand",(void*)_o_srand},
    {"ucrtbase.dll","_o__set_app_type",(void*)_o__set_app_type},
    {"ucrtbase.dll","_o__set_fmode",(void*)_o__set_fmode},
    {"ucrtbase.dll","_o__set_new_mode",(void*)_o__set_new_mode},
    {"ucrtbase.dll","_o__initialize_onexit_table",(void*)_o__initialize_onexit_table},
    {"ucrtbase.dll","_o__register_onexit_function",(void*)_o__register_onexit_function},
    {"ucrtbase.dll","_register_thread_local_exe_atexit_callback",(void*)_register_thread_local_exe_atexit_callback},
    {"ucrtbase.dll","_initterm",(void*)_initterm},
    {"ucrtbase.dll","_initterm_e",(void*)_initterm_e},
    {"ucrtbase.dll","_o___std_exception_copy",(void*)_o___std_exception_copy},
    {"ucrtbase.dll","_o___std_exception_destroy",(void*)_o___std_exception_destroy},
    {"ucrtbase.dll","_o_iswalpha",(void*)_o_iswalpha},
    {"ucrtbase.dll","_o_iswdigit",(void*)_o_iswdigit},
    {"ucrtbase.dll","_o_iswspace",(void*)_o_iswspace},
    {"ucrtbase.dll","_o_iswxdigit",(void*)_o_iswxdigit},
    {"ucrtbase.dll","_o_towlower",(void*)_o_towlower},
    {"ucrtbase.dll","_o_towupper",(void*)_o_towupper},
    {"ucrtbase.dll","_time32",(void*)_time32},
    {"ucrtbase.dll","__C_specific_handler",(void*)__C_specific_handler},
    {"ucrtbase.dll","__current_exception",(void*)__current_exception},
    {"ucrtbase.dll","__current_exception_context",(void*)__current_exception_context},
    {"ucrtbase.dll","__CxxFrameHandler3",(void*)__CxxFrameHandler3},
    {"ucrtbase.dll","_CxxThrowException",(void*)_CxxThrowException},
    {"ucrtbase.dll","_local_unwind",(void*)_local_unwind},
    {"ucrtbase.dll","memcmp",(void*)memcmp},
    {"ucrtbase.dll","memcpy",(void*)memcpy},
    {"ucrtbase.dll","memmove",(void*)memmove},
    {"ucrtbase.dll","memset",(void*)memset},
    {"ucrtbase.dll","wcschr",(void*)lsw_utf16_wcschr},
    {"ucrtbase.dll","wcscmp",(void*)lsw_utf16_wcscmp},
    {"ucrtbase.dll","wcsncmp",(void*)lsw_utf16_wcsncmp},
    {"ucrtbase.dll","wcsrchr",(void*)lsw_utf16_wcsrchr},
    {"ucrtbase.dll","wcsspn",(void*)lsw_utf16_wcsspn},
    {"ucrtbase.dll","wcsstr",(void*)lsw_utf16_wcsstr},
    {"ucrtbase.dll","wcslen",(void*)lsw_utf16_wcslen},
    // api-ms-win-crt-* aliases
    {"api-ms-win-crt-string-l1-1-0.dll","memcmp",(void*)memcmp},
    {"api-ms-win-crt-string-l1-1-0.dll","memcpy",(void*)memcpy},
    {"api-ms-win-crt-string-l1-1-0.dll","memmove",(void*)memmove},
    {"api-ms-win-crt-string-l1-1-0.dll","memset",(void*)memset},
    {"api-ms-win-crt-string-l1-1-0.dll","wcschr",(void*)lsw_utf16_wcschr},
    {"api-ms-win-crt-string-l1-1-0.dll","wcscmp",(void*)lsw_utf16_wcscmp},
    {"api-ms-win-crt-string-l1-1-0.dll","wcsncmp",(void*)lsw_utf16_wcsncmp},
    {"api-ms-win-crt-string-l1-1-0.dll","wcsrchr",(void*)lsw_utf16_wcsrchr},
    {"api-ms-win-crt-string-l1-1-0.dll","wcsspn",(void*)lsw_utf16_wcsspn},
    {"api-ms-win-crt-string-l1-1-0.dll","wcsstr",(void*)lsw_utf16_wcsstr},
    {"api-ms-win-crt-string-l1-1-0.dll","wcslen",(void*)lsw_utf16_wcslen},
    {"api-ms-win-crt-time-l1-1-0.dll","_time32",(void*)_time32},
    {"api-ms-win-crt-runtime-l1-1-0.dll","_initterm",(void*)_initterm},
    {"api-ms-win-crt-runtime-l1-1-0.dll","_initterm_e",(void*)_initterm_e},
    {"api-ms-win-crt-runtime-l1-1-0.dll","_register_thread_local_exe_atexit_callback",(void*)_register_thread_local_exe_atexit_callback},
    {"api-ms-win-crt-runtime-l1-1-0.dll","_o__c_exit",(void*)_o__c_exit},
    {"api-ms-win-crt-runtime-l1-1-0.dll","_o__crt_atexit",(void*)_o__crt_atexit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__get_initial_narrow_environment",(void*)_o__get_initial_narrow_environment},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__get_osfhandle",(void*)_o__get_osfhandle},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__getch",(void*)_o__getch},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__initialize_narrow_environment",(void*)_o__initialize_narrow_environment},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__initialize_onexit_table",(void*)_o__initialize_onexit_table},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__register_onexit_function",(void*)_o__register_onexit_function},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__open_osfhandle",(void*)_o__open_osfhandle},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__pipe",(void*)_o__pipe},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__purecall",(void*)_o__purecall},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__set_app_type",(void*)_o__set_app_type},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__set_fmode",(void*)_o__set_fmode},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__set_new_mode",(void*)_o__set_new_mode},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__close",(void*)_o__close},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__cexit",(void*)_o__cexit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__callnewh",(void*)_o__callnewh},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__dup",(void*)_o__dup},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__dup2",(void*)_o__dup2},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__errno",(void*)_o__errno},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__exit",(void*)_o__exit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_exit",(void*)_o_exit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__invalid_parameter_noinfo",(void*)_o__invalid_parameter_noinfo},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__pclose",(void*)_o__pclose},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__seh_filter_exe",(void*)_o__seh_filter_exe},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__setmode",(void*)_o__setmode},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__tell",(void*)_o__tell},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wcsicmp",(void*)_o__wcsicmp},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wcslwr",(void*)_o__wcslwr},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wcsnicmp",(void*)_o__wcsnicmp},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wcsupr",(void*)_o__wcsupr},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wpopen",(void*)_o__wpopen},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__wtol",(void*)_o__wtol},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_calloc",(void*)_o_calloc},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_free",(void*)_o_free},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_malloc",(void*)_o_malloc},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_qsort",(void*)_o_qsort},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_rand",(void*)_o_rand},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_realloc",(void*)_o_realloc},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_srand",(void*)_o_srand},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_setlocale",(void*)_o_setlocale},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_terminate",(void*)_o_terminate},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_towlower",(void*)_o_towlower},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_towupper",(void*)_o_towupper},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_wcstol",(void*)_o_wcstol},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_wcstoul",(void*)_o_wcstoul},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__configthreadlocale",(void*)_o__configthreadlocale},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__configure_narrow_argv",(void*)_o__configure_narrow_argv},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__ultoa",(void*)_o__ultoa},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___p___argc",(void*)_o___p___argc},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___p___argv",(void*)_o___p___argv},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___acrt_iob_func",(void*)_o___acrt_iob_func},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___std_exception_copy",(void*)_o___std_exception_copy},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___std_exception_destroy",(void*)_o___std_exception_destroy},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vsprintf",(void*)_o___stdio_common_vsprintf},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vsscanf",(void*)_o___stdio_common_vsscanf},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vfprintf",(void*)_o___stdio_common_vfprintf},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vswprintf",(void*)_o___stdio_common_vswprintf},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vswprintf_s",(void*)_o___stdio_common_vswprintf_s},
    {"api-ms-win-crt-private-l1-1-0.dll","_o___stdio_common_vswscanf",(void*)_o___stdio_common_vswscanf},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_feof",(void*)_o_feof},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_ferror",(void*)_o_ferror},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_fflush",(void*)_o_fflush},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_fgets",(void*)_o_fgets},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_iswalpha",(void*)_o_iswalpha},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_iswdigit",(void*)_o_iswdigit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_iswspace",(void*)_o_iswspace},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_iswxdigit",(void*)_o_iswxdigit},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_towlower",(void*)_o_towlower},
    {"api-ms-win-crt-private-l1-1-0.dll","_o_towupper",(void*)_o_towupper},
    {"api-ms-win-crt-private-l1-1-0.dll","_o__get_home_dir",(void*)_o__get_home_dir},
    {"api-ms-win-crt-string-l1-1-0.dll","_o__wcsicmp",(void*)_o__wcsicmp},
    {"api-ms-win-crt-string-l1-1-0.dll","_o__wcsnicmp",(void*)_o__wcsnicmp},
    {"api-ms-win-crt-string-l1-1-0.dll","_o__wcslwr",(void*)_o__wcslwr},
    {"api-ms-win-crt-string-l1-1-0.dll","_o__wcsupr",(void*)_o__wcsupr},
    {"api-ms-win-crt-string-l1-1-0.dll","_o__wtol",(void*)_o__wtol},
    {"api-ms-win-crt-string-l1-1-0.dll","_o_wcstol",(void*)_o_wcstol},
    {"api-ms-win-crt-string-l1-1-0.dll","_o_wcstoul",(void*)_o_wcstoul},
    // kernelbase aliases
    {"kernelbase.dll","CreateFile",(void*)win32_create_file},
    {"kernelbase.dll","CloseHandle",(void*)win32_close_handle},
    {"kernelbase.dll","GetFileSize",(void*)win32_get_file_size},
    {"kernelbase.dll","GetTickCount",(void*)win32_get_tick_count},
    {"kernelbase.dll","SetFilePointer",(void*)win32_set_file_pointer},
    {"kernelbase.dll","CreateEvent",(void*)win32_create_event},
    {"kernelbase.dll","OpenProcess",(void*)GetCurrentProcess},
    {"kernelbase.dll","RaiseFailFastException",(void*)RaiseFailFastException},
    // Wldp stub
    {"Wldp.dll","WldpIsDynamicCodePolicyEnabled",(void*)win32_is_debugger_present},
    // ext-ms-win stubs
    {"ext-ms-win-branding-winbrand-l1-1-0.dll","BrandingFormatString",(void*)BrandingFormatString},
    {"ext-ms-win-cmd-util-l1-1-0.dll","CmdBatNotificationStub",(void*)CmdBatNotificationStub},
};

static const size_t g_api_count = sizeof(g_api_table) / sizeof(g_api_table[0]);

static void* g_tramp[512];
static const char* g_tramp_name[512];
static int g_tramp_ready = 0;

/* Global trace function called by trampolines when LSW_TRACE_ALL is set */
void ntll_trampoline_trace(const char* name, void* target) {
    (void)target;
    /* Skip high-frequency noisy functions */
    if (name[0] == 'G' && (
        strcmp(name, "GetConsoleMode") == 0 || strcmp(name, "GetStdHandle") == 0 ||
        strcmp(name, "GetConsoleOutputCP") == 0 || strcmp(name, "GetACP") == 0 ||
        strcmp(name, "GetThreadLocale") == 0 || strcmp(name, "GetCPInfo") == 0 ||
        strcmp(name, "GetLastError") == 0 || strcmp(name, "GetCurrentThreadId") == 0 ||
        strcmp(name, "GetCurrentProcessId") == 0 || strcmp(name, "GetCurrentProcess") == 0 ||
        strcmp(name, "IsDebuggerPresent") == 0 || strcmp(name, "IsProcessorFeaturePresent") == 0))
        return;
    if (name[0] == 'S' && (strcmp(name, "SetLastError") == 0 || strcmp(name, "SetThreadLocale") == 0))
        return;
    fprintf(stderr, "[trace] %s\n", name);
}

static void emit8(unsigned char** p, unsigned char v) { *(*p)++ = v; }
static void emit32(unsigned char** p, unsigned long v) {
    emit8(p, (unsigned char)(v & 0xff));
    emit8(p, (unsigned char)((v >> 8) & 0xff));
    emit8(p, (unsigned char)((v >> 16) & 0xff));
    emit8(p, (unsigned char)((v >> 24) & 0xff));
}
static void emit64(unsigned char** p, unsigned long long v) {
    emit32(p, (unsigned long)(v & 0xffffffff));
    emit32(p, (unsigned long)(v >> 32));
}

/*
 * Generate a machine-code trampoline that converts a Windows x64 ABI call
 * (args 1-4 in rcx, rdx, r8, r9) into a System V ABI call (args 1-6 in
 * rdi, rsi, rdx, rcx, r8, r9) and tail-invokes `target`.
 * This lets PE code call our standard C functions at arbitrary arity.
 */
static void* make_trampoline(void* target, const char* name) {
    unsigned char* base = mmap(NULL, 512, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    unsigned char* p = base;
    emit8(&p, 0x48); emit8(&p, 0x83); emit8(&p, 0xec); emit8(&p, 0x58); /* sub rsp,0x58 */
    emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x7c); emit8(&p, 0x24); emit8(&p, 0x40); /* mov [rsp+0x40],rdi save MS rdi */
    emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x74); emit8(&p, 0x24); emit8(&p, 0x48); /* mov [rsp+0x48],rsi save MS rsi */
    if (getenv("LSW_TRACE_ALL")) {
        /* LSW_TRACE_ALL: save all Win64 arg regs, call ntll_trampoline_trace(name, target) */
        emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x0c); emit8(&p, 0x24); /* mov [rsp],rcx */
        emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x54); emit8(&p, 0x24); emit8(&p, 0x08); /* mov [rsp+0x08],rdx */
        emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0x44); emit8(&p, 0x24); emit8(&p, 0x10); /* mov [rsp+0x10],r8 */
        emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0x4c); emit8(&p, 0x24); emit8(&p, 0x18); /* mov [rsp+0x18],r9 */
        emit8(&p, 0x48); emit8(&p, 0xbf); emit64(&p, (unsigned long long)(uintptr_t)name);   /* mov rdi, name */
        emit8(&p, 0x48); emit8(&p, 0xbe); emit64(&p, (unsigned long long)(uintptr_t)target);  /* mov rsi, target */
        emit8(&p, 0x48); emit8(&p, 0xb8); emit64(&p, (unsigned long long)(uintptr_t)ntll_trampoline_trace); /* mov rax, trace */
        emit8(&p, 0xff); emit8(&p, 0xd0); /* call rax */
        emit8(&p, 0x48); emit8(&p, 0x8b); emit8(&p, 0x0c); emit8(&p, 0x24); /* mov rcx,[rsp] */
        emit8(&p, 0x48); emit8(&p, 0x8b); emit8(&p, 0x54); emit8(&p, 0x24); emit8(&p, 0x08); /* mov rdx,[rsp+0x08] */
        emit8(&p, 0x4c); emit8(&p, 0x8b); emit8(&p, 0x44); emit8(&p, 0x24); emit8(&p, 0x10); /* mov r8,[rsp+0x10] */
        emit8(&p, 0x4c); emit8(&p, 0x8b); emit8(&p, 0x4c); emit8(&p, 0x24); emit8(&p, 0x18); /* mov r9,[rsp+0x18] */
    }
    emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0xcf); /* mov rdi, rcx */
    emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0xd6); /* mov rsi, rdx */
    emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0xc2); /* mov rdx, r8 */
    emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0xc9); /* mov rcx, r9 */
    emit8(&p, 0x4c); emit8(&p, 0x8b); emit8(&p, 0x84); emit8(&p, 0x24); emit32(&p, 0x80); /* mov r8, [rsp+0x80] arg5 */
    emit8(&p, 0x4c); emit8(&p, 0x8b); emit8(&p, 0x8c); emit8(&p, 0x24); emit32(&p, 0x88); /* mov r9, [rsp+0x88] arg6 */
    {
        static const unsigned srcd[8] = {0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0, 0xc8};
        static const unsigned dstd[8] = {0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38};
        for (int i = 0; i < 8; i++) {
            emit8(&p, 0x48); emit8(&p, 0x8b); emit8(&p, 0x84); emit8(&p, 0x24); emit32(&p, srcd[i]); /* mov rax, [rsp+srcd] */
            if (dstd[i]) {
                emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x44); emit8(&p, 0x24); emit8(&p, (unsigned char)dstd[i]); /* mov [rsp+dst], rax */
            } else {
                emit8(&p, 0x48); emit8(&p, 0x89); emit8(&p, 0x04); emit8(&p, 0x24); /* mov [rsp], rax */
            }
        }
    }
    /* NOTE: sources (0x90-0xc8) are above dests (0x00-0x38), no overlap. */
    unsigned char* jmp_pos = p;
    emit8(&p, 0x48); emit8(&p, 0xb8); /* mov rax, imm64 */
    emit64(&p, (unsigned long long)(uintptr_t)target);
    emit8(&p, 0xff); emit8(&p, 0xd0); /* call rax */
    emit8(&p, 0x48); emit8(&p, 0x8b); emit8(&p, 0x74); emit8(&p, 0x24); emit8(&p, 0x48); /* mov rsi,[rsp+0x48] restore MS rsi */
    emit8(&p, 0x48); emit8(&p, 0x8b); emit8(&p, 0x7c); emit8(&p, 0x24); emit8(&p, 0x40); /* mov rdi,[rsp+0x40] restore MS rdi */
    emit8(&p, 0x48); emit8(&p, 0x83); emit8(&p, 0xc4); emit8(&p, 0x58); /* add rsp,0x58 */
    emit8(&p, 0xc3); /* ret */
    (void)jmp_pos;
    if (mprotect(base, 512, PROT_EXEC | PROT_READ) != 0) return NULL;
    return base;
}

void* ntll_dispatch(PNTLL_MODULE module, const char* name) {
    (void)module;
    if (getenv("LSW_TRACE_DISPATCH"))
        fprintf(stderr, "[trace] dispatch %s\n", name);
    if (!g_tramp_ready) {
        memset(g_tramp, 0, sizeof(g_tramp));
        g_tramp_ready = 1;
    }
    for (size_t i = 0; i < g_api_count; i++) {
        if (strcmp(g_api_table[i].name, name) == 0) {
            if (!g_tramp[i]) g_tramp[i] = make_trampoline(g_api_table[i].func, name);
            return g_tramp[i];
        }
    }
    NTLL_LOG_WARN("unresolved import: %s", name);
    return NULL;
}

PNTLL_MODULE ntll_load_system_module(const char* dll_name) {
    static NTLL_MODULE stub = {0};
    static int initialized = 0;
    (void)dll_name;
    if (!initialized) {
        strcpy(stub.name, dll_name);
        strcpy(stub.full_path, "(system)");
        initialized = 1;
    }
    return &stub;
}

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

void ntll_log(int level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    const char* names[] = {"INFO","WARN","ERROR","DEBUG"};
    fprintf(stderr, "[ntll:%s] ", names[level >= 0 && level <= 3 ? level : 0]);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}
