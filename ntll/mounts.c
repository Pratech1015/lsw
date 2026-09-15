// mounts.c - Host drive mounts for the LSW Windows environment
// Copyright (c) 2026 LSW Contributors
//
// Lets NTLL path conversion map Windows drive letters (D:, E:, ...) onto
// real host directories, mirroring WSL's [automount]. The mapping is read
// from the LSW_MOUNTS environment variable (set by the lsw launcher from
// the distro lsw.conf [automount] mounts= entry) as comma-separated
// "letter=path" pairs, e.g. "d=/, e=/run/media/pra1015/Games".

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ntll.h"

/* Returns 0 and fills out (host path, no trailing slash except "/") when the
   given drive letter has a mount mapping, -1 otherwise. */
int nt_mount_lookup(char drive_letter, char* out, size_t sz) {
    const char* env = getenv("LSW_MOUNTS");
    if (!env || !out || sz == 0) return -1;

    char letter = (char)tolower((unsigned char)drive_letter);
    const char* p = env;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if ((char)tolower((unsigned char)*p) == letter && p[1] == '=') {
            p += 2;
            while (*p == ' ' || *p == '\t') p++;
            size_t n = 0;
            while (p[n] && p[n] != ',') n++;
            while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
            if (n >= sz) n = sz - 1;
            memcpy(out, p, n);
            out[n] = '\0';
            if (n > 1 && out[n - 1] == '/') out[n - 1] = '\0';
            return 0;
        }
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
    }
    return -1;
}