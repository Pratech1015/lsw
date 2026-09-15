// runtime.c - LSW runtime entry point
// Copyright (c) 2026 LSW Contributors
//
// Executes a Windows PE executable using the NTLL compatibility layer.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "ntll.h"

static PNTLL_MODULE g_main_module = NULL;

/*
 * Builtin programs shipped with LSW: cmd.exe and a small set of console
 * apps (winver, hostname, whoami, echo, ver, date, time). These are
 * compiled into the runtime so no PE image is required. Returns >=0 when
 * handled, -1 otherwise.
 */
static int run_builtin(const char* base, int argc, char** argv) {
    size_t len = strlen(base);
    const char* ext = (len > 4) ? base + (len - 4) : NULL;

    if (strcasecmp(base, "cmd") == 0 || strcasecmp(base, "cmd.exe") == 0 ||
        (ext && (strcasecmp(ext, ".bat") == 0 || strcasecmp(ext, ".cmd") == 0))) {
        return nt_builtin_cmd(argc, argv);
    }
    int r = nt_builtin_exec(base, argc, argv);
    if (r >= 0) return r;

    /* Native reimplementations of bundled System32 CLI tools (ipconfig, ping, ...) */
    return nt_tool_dispatch(base, argc, argv);
}

static void usage(const char* prog) {
    fprintf(stderr,
        "LSW runtime v%s\n"
        "Usage: %s [options] <windows-program>.exe [args...]\n"
        "Options:\n"
        "  -v, --verbose     Enable verbose logging\n"
        "  -q, --quiet       Suppress all logging\n"
        "  -w, --windows=N   Windows version to emulate (default: 11)\n"
        "  --build=N         Windows build number (default: 22631)\n"
        "  -c, --config=F    Configuration file\n",
        NTLL_VERSION, prog);
}

static void signal_handler(int sig) {
    fprintf(stderr, "[lsw] process interrupted by signal %d\n", sig);
    exit(128 + sig);
}

int main(int argc, char* argv[]) {
    const char* program = NULL;
    int rest_start = 1;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            verbose = 1;
            rest_start = i + 1;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            // silence - handled by env var
            rest_start = i + 1;
        } else if (strncmp(a, "--windows=", 10) == 0) {
            const char* ver = a + 10;
            if (strcmp(ver, "10") == 0) {
                nt_set_os_version(10, 0, 19045);
            } else {
                nt_set_os_version(10, 0, 22631);
            }
            rest_start = i + 1;
        } else if (strncmp(a, "--build=", 8) == 0) {
            nt_set_os_version(10, 0, (DWORD)atoi(a + 8));
            rest_start = i + 1;
        } else if (a[0] != '-') {
            program = a;
            rest_start = i;
            break;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!program) {
        usage(argv[0]);
        return 1;
    }

    if (verbose) {
        setenv("NTLL_LOG_LEVEL", "3", 0);
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    // Initialize the runtime
    ntll_init();

    NTLL_LOG_INFO("starting LSW runtime v%s", NTLL_VERSION);

    // Try the builtin program set first (cmd.exe, winver, ..., *.bat)
    const char* base = strrchr(program, '/');
    base = base ? base + 1 : program;
    int builtin = run_builtin(base, argc - rest_start, &argv[rest_start]);
    if (builtin >= 0) {
        ntll_cleanup();
        return builtin;
    }

    NTLL_LOG_INFO("image: %s", program);

    // Load the executable
    g_main_module = pe_load(program);
    if (!g_main_module) {
        NTLL_LOG_ERROR("failed to load executable: %s", program);
        return 1;
    }

    NTLL_LOG_INFO("entry point: %p", g_main_module->entry_point);

    // Set up process info
    PNTLL_PROCESS proc;
    if (nt_get_current_process(&proc) == STATUS_SUCCESS) {
        proc->image_base = (DWORD64)(uintptr_t)g_main_module->base_address;
        proc->initialized = TRUE;
    }

    // Set the environment so that the process can self-locate
    setenv("LSW_MODULE_PATH", program, 1);
    setenv("_", program, 1);

    int argc_native = argc - rest_start;
    char** argv_native = &argv[rest_start];

    // Invoke the entry point with Windows calling convention (ms_abi wrapper)
    void (*entry)(int, char**) = (void (*)(int, char**))(uintptr_t)g_main_module->entry_point;
    entry(argc_native, argv_native);

    // If the entry point returns, exit normally (ExitProcess not called)
    int exit_code = proc ? proc->exit_code : 0;
    NTLL_LOG_INFO("entry point returned, status %d", exit_code);

    // Unload
    pe_unload(g_main_module);
    ntll_cleanup();

    return exit_code;
}