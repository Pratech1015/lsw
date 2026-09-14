// test-app.c - Windows PE test application for NTLL runtime
// Compile with a Windows PE cross-toolchain to test the loader:
//   x86_64-w64-mingw32-gcc -o test-app.exe test-app.c
#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;
    printf("Hello from Windows 11 running under LSW!\n");
    printf("Showing off the NTLL compatibility layer:\n");
    printf("  TickCount:   %lu\n", (unsigned long)GetTickCount());
    printf("  CurrentPID:  %lu\n", (unsigned long)GetCurrentProcessId());
    printf("  CurThreadID: %lu\n", (unsigned long)GetCurrentThreadId());
    printf("  Windows:     %s\n", "Windows 11");
    return 0;
}