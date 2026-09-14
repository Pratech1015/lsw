// process.c - Windows process & thread emulation for LSW/NTLL
// Copyright (c) 2026 LSW Contributors

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>

#include "ntll.h"

static pthread_mutex_t g_process_lock = PTHREAD_MUTEX_INITIALIZER;
static PNTLL_PROCESS g_current_process = NULL;

// Boot-time process ID from Linux; the emulated PID table is separate
static DWORD g_pid_counter = 1000;
static DWORD g_tid_counter = 1000;

static PNTLL_PROCESS g_process_table[1024];
static int g_process_count = 0;

static void default_environment_setup(void);

// Initialize process management
static int process_init(void) {
    g_current_process = calloc(1, sizeof(NTLL_PROCESS));
    if (!g_current_process) return -1;

    g_current_process->pid = ++g_pid_counter;
    g_current_process->parent_pid = 0;

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        g_current_process->current_directory = strdup(cwd);
    }
    default_environment_setup();

    g_process_table[0] = g_current_process;
    g_process_count = 1;
    return 0;
}

// Default environment variables (the WINDIR etc.)
static void default_environment_setup(void) {
    setenv("WINDIR", "/var/lib/lsw/root/Windows", 0);
    setenv("SystemRoot", "/var/lib/lsw/root/Windows", 0);
    setenv("SystemDrive", "C:", 0);
    setenv("PROCESSOR_ARCHITECTURE", "AMD64", 0);
    setenv("NUMBER_OF_PROCESSORS", "0", 0);
    setenv("OS", "Windows_NT", 0);
    setenv("CATALOGUE_ROOT", "\\SystemRoot\\Registration", 0);
    setenv("USERNAME", "Administrator", 1);
    setenv("USERPROFILE", "/var/lib/lsw/root/Users/Administrator", 0);
    setenv("APPDATA", "/var/lib/lsw/root/Users/Administrator/AppData/Roaming", 0);
    setenv("LOCALAPPDATA", "/var/lib/lsw/root/Users/Administrator/AppData/Local", 0);
    setenv("TEMP", "/tmp", 1);
    setenv("TMP", "/tmp", 1);
    setenv("windir", "/var/lib/lsw/root/Windows", 0);
    setenv("ComSpec", "/var/lib/lsw/root/Windows/System32/cmd.exe", 0);
    setenv("Path", "/var/lib/lsw/root/Windows/System32;/var/lib/lsw/root/Windows", 0);
}

// Get the current (only) emulated process
NTSTATUS nt_get_current_process(PNTLL_PROCESS* process) {
    if (!process) return STATUS_INVALID_PARAMETER;
    if (!g_current_process) {
        int rc = process_init();
        if (rc != 0) return STATUS_NO_MEMORY;
    }
    *process = g_current_process;
    return STATUS_SUCCESS;
}

NTSTATUS nt_get_current_thread(PNTLL_THREAD* thread) {
    static NTLL_THREAD main_thread = {0};
    PNTLL_PROCESS proc;
    if (nt_get_current_process(&proc) != STATUS_SUCCESS)
        return STATUS_UNSUCCESSFUL;

    if (main_thread.tid == 0) {
        main_thread.tid = ++g_tid_counter;
        main_thread.process_id = proc->pid;
        main_thread.running = TRUE;
        main_thread.thread_handle = (HANDLE)(uintptr_t)pthread_self();
    }
    if (thread) *thread = &main_thread;
    return STATUS_SUCCESS;
}

NTSTATUS nt_create_process(const char* image_path, const char* command_line,
                          const char* current_dir, PNTLL_PROCESS* out_process) {
    if (!image_path || !out_process) return STATUS_INVALID_PARAMETER;

    // A full Windows make-believe process: in-process for now, but
    // fork(2)+exec(3) is the vector for cross-process isolation later.
    PNTLL_PROCESS proc = calloc(1, sizeof(NTLL_PROCESS));
    if (!proc) return STATUS_NO_MEMORY;

    proc->pid = ++g_pid_counter;
    proc->parent_pid = g_current_process ? g_current_process->pid : 0;
    proc->command_line = command_line ? strdup(command_line) : strdup(image_path);
    proc->current_directory = current_dir ? strdup(current_dir)
                                          : (g_current_process && g_current_process->current_directory)
                                              ? strdup(g_current_process->current_directory)
                                              : strdup("/");

    pthread_mutex_lock(&g_process_lock);
    if (g_process_count < 1024) {
        g_process_table[g_process_count++] = proc;
    }
    pthread_mutex_unlock(&g_process_lock);

    *out_process = proc;
    NTLL_LOG_INFO("created process %u (%s)", proc->pid, image_path);
    return STATUS_SUCCESS;
}

NTSTATUS nt_terminate_process(PNTLL_PROCESS process, NTSTATUS exit_status) {
    if (!process) {
        // Terminate current process
        NTSTATUS st = nt_get_current_process(&process);
        if (st != STATUS_SUCCESS) return st;
    }

    process->exit_code = (int)exit_status;
    process->initialized = FALSE;

    // If this is the current process, exit
    if (process == g_current_process) {
        // Nothing to free - we're about to exit
        _exit(exit_status & 0xFF);
    }

    NTLL_LOG_INFO("terminated process %u with status %d", process->pid, exit_status);
    return STATUS_SUCCESS;
}

// Registry the process table
void ntll_process_set_pid(DWORD pid) {
    if (g_current_process) g_current_process->pid = pid;
}

DWORD nt_get_current_process_id(void) {
    PNTLL_PROCESS proc;
    if (nt_get_current_process(&proc) == STATUS_SUCCESS) {
        return proc->pid;
    }
    return 0;
}

// Fork-based process isolation: executes a Windows image in a child
// process with its own address space.
NTSTATUS nt_create_process_isolated(const char* image_path, const char* command_line,
                                    const char* current_dir) {
    pid_t pid = fork();
    if (pid < 0) return STATUS_NO_MEMORY;
    if (pid == 0) {
        // Child
        PNTLL_PROCESS proc = calloc(1, sizeof(NTLL_PROCESS));
        proc->pid = getpid();
        proc->parent_pid = getppid();
        proc->command_line = strdup(command_line ? command_line : image_path);
        proc->current_directory = strdup(current_dir ? current_dir : "/");
        g_current_process = proc;
        g_process_table[0] = proc;
        g_process_count = 1;

        // Load and run
        PNTLL_MODULE mod = pe_load(image_path);
        if (!mod) {
            NTLL_LOG_ERROR("failed to load %s in child", image_path);
            _exit(1);
        }
        // Call entry point
        void (*entry)(void) = mod->entry_point;
        // Type mismatch set aside: run in the same process environment.
        ((void(*)(void))(uintptr_t)entry)();
        _exit(proc->exit_code);
    }
    NTLL_LOG_INFO("spawned isolated process %d for %s", pid, image_path);
    return STATUS_SUCCESS;
}

NTSTATUS nt_create_thread(PHANDLE thread, DWORD access,
                         POBJECT_ATTRIBUTES obj, HANDLE process,
                         PVOID start, PVOID param, BOOL suspend,
                         DWORD stack_size, PULONG_PTR tls,
                         PCLIENT_ID cid) {
    (void)access; (void)obj; (void)process;
    (void)stack_size; (void)tls;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    if (suspend) {
        // Lazy resume: can't suspend with pthreads directly; we handle
        // suspend via a runtime flag. Create the thread suspended means
        // polling a flag - not implemented for the v1 runtime;
        // for now we just spawn it.
    }

    NTLL_THREAD* t = calloc(1, sizeof(NTLL_THREAD));
    if (!t) return STATUS_NO_MEMORY;
    t->tid = ++g_tid_counter;
    t->parameter = param;
    t->start_address = start;

    if (pthread_create(&tid, &attr, (void* (*)(void*))start, param) != 0) {
        free(t);
        return STATUS_INVALID_HANDLE;
    }
    t->running = TRUE;
    if (thread) *thread = (HANDLE)(uintptr_t)t->tid;
    if (cid) {
        cid->UniqueThread = (HANDLE)t->tid;
    }
    NTLL_LOG_DEBUG("created thread %u", t->tid);
    return STATUS_SUCCESS;
}

NTSTATUS nt_resume_thread(HANDLE thread, PULONG suspend_count) {
    (void)thread;
    if (suspend_count) *suspend_count = 0;
    return STATUS_SUCCESS;
}

NTSTATUS nt_wait_for_single_object(HANDLE handle, BOOL alertable,
                                  PLARGE_INTEGER timeout) {
    (void)handle; (void)alertable; (void)timeout;
    // v1: no real object handles; treat as success
    return STATUS_SUCCESS;
}

NTSTATUS nt_create_event(PHANDLE event, DWORD access,
                        POBJECT_ATTRIBUTES obj, int type, BOOL initial) {
    (void)access; (void)obj; (void)type; (void)initial;
    // Allocate a pseudo event identifier
    static DWORD event_counter = 0x10000;
    if (event) *event = (HANDLE)(uintptr_t)(++event_counter);
    return STATUS_SUCCESS;
}

NTSTATUS nt_set_event(HANDLE event, PULONG previous) {
    (void)event;
    if (previous) *previous = 0;
    return STATUS_SUCCESS;
}

// Mutex wrappers mapped onto a global pthread mutex pair
NTSTATUS nt_create_mutex(PHANDLE mutex, DWORD access,
                        POBJECT_ATTRIBUTES obj, BOOL initial_owner) {
    (void)access; (void)obj; (void)initial_owner;
    static DWORD counter = 0x11000;
    if (mutex) *mutex = (HANDLE)(uintptr_t)(++counter);
    return STATUS_SUCCESS;
}

NTSTATUS nt_close(HANDLE handle) {
    (void)handle;
    return STATUS_SUCCESS;
}

// Full environment
char** nt_get_environment(void) {
    return environ;
}

char* nt_get_environment_variable(const char* name) {
    return getenv(name);
}

void nt_set_environment_variable(const char* name, const char* value) {
    setenv(name, value ? value : "", 1);
}

void nt_free_environment(char** env) {
    (void)env;
}