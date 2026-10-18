/*
 * lsw2 - placeholder CLI entry point for the LSW2 (virtualization) line.
 *
 * This mirrors the `wsl` command surface, but no commands are implemented
 * yet: the virtualization runtime does not exist. Each flag reports the
 * component that will eventually back it so the scaffold fails loudly rather
 * than silently pretending to work.
 */
#include <stdio.h>
#include <string.h>

#define LSW2_VERSION "0.0.1-dev"

static void usage(FILE* out, const char* prog) {
    fprintf(out,
            "%s - Linux Subsystem for Windows 2 (virtualized approach)\n"
            "\n"
            "Usage:\n"
            "  %s --version          Print version and exit\n"
            "  %s --help             Print this help\n"
            "  %s --list             List registered Windows environments\n"
            "  %s --shutdown         Stop the virtual machine monitor\n"
            "  %s <command>          Run a command in the default environment\n",
            prog, prog, prog, prog, prog, prog);
}

int main(int argc, char** argv) {
    const char* prog = (argc > 0 && argv[0]) ? argv[0] : "lsw2";

    if (argc < 2) {
        usage(stdout, prog);
        return 0;
    }

    const char* arg = argv[1];

    if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
        printf("lsw2 %s\n", LSW2_VERSION);
        printf("line: WSL2 approach (real Windows kernel in a VM)\n");
        printf("runtime: not yet implemented\n");
        return 0;
    }
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
        usage(stdout, prog);
        return 0;
    }
    if (strcmp(arg, "--list") == 0) {
        fprintf(stderr, "lsw2: --list requires the environment manager (not yet implemented)\n");
        return 1;
    }
    if (strcmp(arg, "--shutdown") == 0) {
        fprintf(stderr, "lsw2: --shutdown requires the VM monitor (not yet implemented)\n");
        return 1;
    }

    fprintf(stderr,
            "lsw2: '%s' requires the virtualized runtime (not yet implemented)\n"
            "      see docs/ARCHITECTURE.md\n", arg);
    return 1;
}
