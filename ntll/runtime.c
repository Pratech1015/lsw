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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <execinfo.h>
#include "ntll.h"

static PNTLL_MODULE g_main_module = NULL;

PNTLL_MODULE ntll_get_main_module(void) { return g_main_module; }

/* fake Windows TEB/PEB so PE code can access gs-relative structures */
static void* g_teb = NULL;
static void* g_peb = NULL;
void* g_procparams = NULL;
wchar_t g_cmdline[4096] = {0};
extern char* g_image_path;

#ifdef __x86_64__
#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
/* minimal TEB offsets (x64) */
#define TEB_STACKBASE     0x08
#define TEB_STACKLIMIT    0x10
#define TEB_SELF          0x30
#define TEB_PEB           0x60
/* minimal PEB offsets (x64) */
#define PEB_LOCK          0x04
#define PEB_IMAGEBASE     0x10
#define PEB_LDR           0x18
#define PEB_PARAMS        0x20
#define PEB_HEAP          0x30
#define PEB_MAXHEAP       0x40
/* PEB_LDR_DATA offsets */
#define LDR_LEN           0x00
#define LDR_INIT          0x04
#define LDR_LOCK          0x08
#define LDR_MODLOAD       0x10  /* InLoadOrderModuleList */
#define LDR_MODMEM        0x20  /* InMemoryOrderModuleList  */
#define LDR_MODINIT       0x30  /* InInitializationOrderModuleList */
/* RTL_USER_PROCESS_PARAMETERS offsets (x64) */
#define RUP_LEN           0x00
#define RUP_MAXLEN        0x04
#define RUP_CONSOLE       0x10  /* ConsoleHandle (Ptr64) */
#define RUP_CONFLAGS      0x18  /* ConsoleFlags */
#define RUP_STDIN         0x20  /* StandardInput (Ptr64) */
#define RUP_STDOUT        0x28  /* StandardOutput (Ptr64) */
#define RUP_STDERR        0x30  /* StandardError (Ptr64) */
#define RUP_CURDIR        0x38  /* CurrentDirectoryDosPath(UNICODE_STRING) */
#define RUP_CURDIRHANDLE  0x48  /* CurrentDirectoryHandle */
#define RUP_DLLPATH       0x58
#define RUP_IMAGEPATH     0x68
#define RUP_CMDLINE       0x78
#define RUP_ENV           0x88


static void setup_win_teb_peb(PNTLL_MODULE module, int argc, char** argv) {
    /* reserve 16 pages: TEB, PEB, LDR, proc params, cmdline, image path, env */
    size_t pagesz = 4096;
    void* base = mmap(NULL, pagesz * 16, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return;
    memset(base, 0, pagesz * 16);
    g_teb        = base;
    g_peb        = (char*)base + pagesz;      /* page 1 */
    void* ldr    = (char*)base + pagesz * 2;  /* page 2 */
    g_procparams = (char*)base + pagesz * 3;  /* page 3-4 */
    wchar_t* wcmd_buf = (wchar_t*)g_procparams;              /* page 3 */
    wchar_t* wp = (wchar_t*)((char*)base + pagesz * 6);      /* page 6: image path */
    wchar_t* wenv = (wchar_t*)((char*)base + pagesz * 8);    /* page 8+: env block */

    /* build command line from argv */
    size_t cmd_len = 0;
    for (int i = 0; i < argc; i++) cmd_len += strlen(argv[i]) + 3;
    wchar_t* wc_cmd = malloc((cmd_len + 2) * sizeof(wchar_t));
    wchar_t* wcp = wc_cmd;
    for (int i = 0; i < argc; i++) {
        if (i > 0) *wcp++ = L' ';
        *wcp++ = L'"';
        for (const char* s = argv[i]; *s; s++) *wcp++ = (wchar_t)(unsigned char)*s;
        *wcp++ = L'"';
    }
    *wcp = 0;
    size_t cmd_charcount = (size_t)(wcp - wc_cmd);
    /* save command line for GetCommandLineW before struct header overwrites wcmd_buf */
    memcpy(g_cmdline, wc_cmd, (cmd_charcount + 1) * sizeof(wchar_t));
    /* write into process params region */
    memcpy(wcmd_buf, wc_cmd, (cmd_charcount + 1) * sizeof(wchar_t));
    free(wc_cmd);
    /* set up RTL_USER_PROCESS_PARAMETERS */
    uint32_t* pup_len = (uint32_t*)((char*)g_procparams + RUP_LEN);
    uint32_t* pup_maxlen = (uint32_t*)((char*)g_procparams + RUP_MAXLEN);
    *pup_len = pagesz;
    *pup_maxlen = pagesz;
    /* ConsoleHandle = stdin handle (console attached) */
    uintptr_t* con = (uintptr_t*)((char*)g_procparams + RUP_CONSOLE);
    *con = (uintptr_t)0; /* placeholder, set after handle alloc */
    /* ImagePathName */
    uint16_t* imgpath_u = (uint16_t*)((char*)g_procparams + RUP_IMAGEPATH);
    uint64_t* imgpath_b = (uint64_t*)((char*)g_procparams + RUP_IMAGEPATH + 8);
    size_t path_len = module ? strlen(module->full_path) : 0;
    for (size_t i = 0; i < path_len; i++) wp[i] = (wchar_t)(unsigned char)module->full_path[i];
    wp[path_len] = 0;
    imgpath_u[0] = (uint16_t)(path_len * sizeof(wchar_t));  /* Length */
    imgpath_u[1] = (uint16_t)((path_len + 1) * sizeof(wchar_t)); /* MaximumLength */
    *imgpath_b = (uintptr_t)wp;
    /* CommandLine */
    uint16_t* cmd_u = (uint16_t*)((char*)g_procparams + RUP_CMDLINE);
    uint64_t* cmd_b = (uint64_t*)((char*)g_procparams + RUP_CMDLINE + 8);
    cmd_u[0] = (uint16_t)(cmd_charcount * sizeof(wchar_t));
    cmd_u[1] = (uint16_t)((cmd_charcount + 1) * sizeof(wchar_t));
    *cmd_b = (uintptr_t)wcmd_buf;
    /* Environment: null-terminated list of "KEY=VALUE" wide strings, then double-null.
     * Use proper 2-byte UTF-16LE encoding (Windows wchar_t = 2 bytes).
     * Filter out Linux-specific env vars that would confuse PE code. */
    extern char** environ;
    uint16_t* wep = (uint16_t*)wenv;
    /* Host env vars to skip (Linux-specific, not meaningful to PE code) */
    static const char* skip_vars[] = {
        "PWD", "OLDPWD", "HOME", "SHELL", "USER", "LOGNAME", "TERM",
        "LS_COLORS", "LSW_MODULE_PATH", "LSW_ROOTFS", "LSW_TRACE_WCSRCHR",
        "DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
        "COLORTERM", "CONDA_DEFAULT_ENV", "CONDA_PREFIX",
        "_", NULL
    };
    for (char** e = environ; *e; e++) {
        /* Extract variable name (before '=') */
        const char* eq = strchr(*e, '=');
        if (!eq) continue;
        size_t namelen = (size_t)(eq - *e);
        /* Check if this var should be skipped */
        int skip = 0;
        for (const char** s = skip_vars; *s; s++) {
            if (strlen(*s) == namelen && strncmp(*e, *s, namelen) == 0) {
                skip = 1;
                break;
            }
        }
        if (skip) continue;
        /* Write KEY=VALUE as 2-byte UTF-16LE */
        k32_utf8_to_utf16le(*e, wep, 2048);
        while (*wep) wep++;
        wep++; /* skip null terminator */
    }
    *wep = 0; wep++; *wep = 0; /* double-null terminate */
    uint64_t* env_ptr = (uint64_t*)((char*)g_procparams + RUP_ENV);
    *env_ptr = (uintptr_t)wenv;

    /* CurrentDirectory = C:\ (CURDIR structure at RUP_CURDIR)
     * Use a separate buffer (page 9) for the path string. */
    static const uint16_t kCwd[] = { 'C', ':', '\\', 0 };
    uint16_t* curdir_buf = (uint16_t*)((char*)base + pagesz * 9);
    memcpy(curdir_buf, kCwd, sizeof(kCwd));
    uint16_t* curdir_len = (uint16_t*)((char*)g_procparams + RUP_CURDIR);
    uint16_t* curdir_maxlen = (uint16_t*)((char*)g_procparams + RUP_CURDIR + 2);
    *curdir_len = (uint16_t)(3 * sizeof(uint16_t));
    *curdir_maxlen = (uint16_t)(4 * sizeof(uint16_t));
    uint64_t* curdir_ptr = (uint64_t*)((char*)g_procparams + RUP_CURDIR + 8);
    *curdir_ptr = (uintptr_t)curdir_buf;

    /* PEB_LDR_DATA */
    memset(ldr, 0, pagesz);
    uint32_t* ldr_len = (uint32_t*)((char*)ldr + LDR_LEN);
    *ldr_len = 0x58;
    uint32_t* ldr_init = (uint32_t*)((char*)ldr + LDR_INIT);
    *ldr_init = 1; /* Initialized */

    /* PEB */
    uint8_t* peb8 = (uint8_t*)g_peb;
    peb8[0x02] = 0; /* BeingDebugged = FALSE */
    peb8[0x03] = 0; /* BitField */
    uint64_t* peb_ib = (uint64_t*)((char*)g_peb + PEB_IMAGEBASE);
    *peb_ib = (uintptr_t)(module ? module->base_address : NULL);
    uint64_t* peb_ldr = (uint64_t*)((char*)g_peb + PEB_LDR);
    *peb_ldr = (uintptr_t)ldr;
    uint64_t* peb_params = (uint64_t*)((char*)g_peb + PEB_PARAMS);
    *peb_params = (uintptr_t)g_procparams;
    /* heap: sentinel */
    uint64_t* peb_heap = (uint64_t*)((char*)g_peb + PEB_HEAP);
    *peb_heap = 0; /* 0 = no heap yet; GetProcessHeap returns sentinel */
    uint64_t* peb_maxh = (uint64_t*)((char*)g_peb + PEB_MAXHEAP);
    *peb_maxh = 0;

    /* TEB */
    uint64_t* teb64 = (uint64_t*)g_teb;
    teb64[1] = 0; /* StackBase (offset 0x08) — will be set after stack snapshot */
    teb64[2] = 0; /* StackLimit */
    teb64[TEB_SELF/8] = (uintptr_t)g_teb;
    teb64[TEB_PEB/8]  = (uintptr_t)g_peb;
    /* set stack base/limit from current rsp */
    uintptr_t rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    /* Windows stack grows down; StackBase = top of stack (+ 4MB guard) */
    teb64[TEB_STACKBASE/8]  = rsp + 4 * 1024 * 1024;
    teb64[TEB_STACKLIMIT/8] = rsp - 128 * 1024;

    /* set GS segment base to the TEB */
    long ret = syscall(SYS_arch_prctl, ARCH_SET_GS, g_teb);
    if (ret != 0) {
        NTLL_LOG_WARN("arch_prctl ARCH_SET_GS failed (%ld), "
                      "PE code using gs-relative access will crash", ret);
    } else {
        NTLL_LOG_INFO("set GS base -> TEB at %p", g_teb);
    }

    /* populate PEB->ProcessParameters standard handles */
    extern void win32_init_peb_standard_handles(void);
    win32_init_peb_standard_handles();
}
#else
static void setup_win_teb_peb(PNTLL_MODULE module, int argc, char** argv) {
    (void)module; (void)argc; (void)argv;
}
#endif

/*
 * Builtin programs shipped with LSW: cmd.exe and a small set of console
 * apps (winver, hostname, whoami, echo, ver, date, time). These are
 * compiled into the runtime so no PE image is required. Returns >=0 when
 * handled, -1 otherwise.
 */
static int run_builtin(const char* base, int argc, char** argv) {
    size_t len = strlen(base);
    const char* ext = (len > 4) ? base + (len - 4) : NULL;

    if (ext && (strcasecmp(ext, ".bat") == 0 || strcasecmp(ext, ".cmd") == 0)) {
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
    if (sig == SIGSEGV) {
        void* ret[16];
        int n = backtrace(ret, 16);
        fprintf(stderr, "[lsw] backtrace (%d frames):\n", n);
        backtrace_symbols_fd(ret, n, 2);
    }
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

    // Resolve a bare "cmd"/"cmd.exe" to the real Windows 11 system shell in the
    // distro rootfs so it runs as a real PE through the NTLL loader rather than
    // the custom builtin interpreter.
    if (strcasecmp(base, "cmd") == 0 || strcasecmp(base, "cmd.exe") == 0) {
        const char* rootfs = getenv("LSW_ROOTFS");
        static char cmd_path[4096];
        if (rootfs) {
            snprintf(cmd_path, sizeof(cmd_path), "%s/drive_c/Windows/System32/cmd.exe", rootfs);
            if (access(cmd_path, R_OK) == 0) program = cmd_path;
        }
    }

    int builtin = run_builtin(base, argc - rest_start, &argv[rest_start]);
    if (builtin >= 0) {
        ntll_cleanup();
        return builtin;
    }

    NTLL_LOG_INFO("image: %s", program);

    /* Set global image path for nt_get_system_root auto-detection */
    g_image_path = (char*)program;

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

    // Build a synthetic Windows TEB/PEB and point the GS segment at it so
    // PE code can read %gs-relative Windows structures (TEB, PEB).
    setup_win_teb_peb(g_main_module, argc_native, argv_native);

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