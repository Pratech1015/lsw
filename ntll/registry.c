// registry.c - Windows registry emulation for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Backed by JSON-like text files under the LSW data dir. The registry
// tree mirrors the Windows hive layout (HKLM\SYSTEM\..., etc).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

#include "ntll.h"

#define HKLM_ROOT 0x80000002

static pthread_mutex_t g_reg_lock = PTHREAD_MUTEX_INITIALIZER;

static const char* registry_base_path(void) {
    return "/var/lib/lsw/registry";
}

// Create storage path for a registry key
static void reg_path_for(const char* hkey, const char* subkey, char* out, size_t out_size) {
    const char* base = registry_base_path();
    if (strcmp(hkey, "HKLM") == 0 || ((uint32_t)(uintptr_t)hkey >> 28) == 0x8) {
        snprintf(out, out_size, "%s/HKLM/%s", base, subkey ? subkey : "");
    } else {
        snprintf(out, out_size, "%s/%s/%s", base, hkey, subkey ? subkey : "");
    }
}

// Extract the root hive from the numeric handle value
static const char* hive_name(DWORD hkey) {
    switch (hkey) {
        case 0x80000002: return "HKLM";
        case 0x80000001: return "HKCU";
        case 0x80000003: return "HKCR";
        case 0x80000004: return "HKU";
        case 0x80000005: return "HKCC";
        default: return "HKLM";
    }
}

static void ensure_dir(const char* path) {
    char tmp[4096];
    strncpy(tmp, path, sizeof(tmp) - 1);
    char* p = tmp;
    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (strlen(tmp)) mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

// Write a value's data out as a file
static void write_value_file(const char* base, const char* key_path,
                            const char* value_name, DWORD type,
                            const void* data, DWORD data_size) {
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s/%s", base, key_path);
    ensure_dir(dir);

    char vfile[8192];
    if (value_name[0]) {
        snprintf(vfile, sizeof(vfile), "%s/%s.val", dir, value_name);
    } else {
        snprintf(vfile, sizeof(vfile), "%s/.default.val", dir);
    }

    FILE* f = fopen(vfile, "wb");
    if (!f) return;
    fwrite(&type, sizeof(type), 1, f);
    if (data && data_size) fwrite(data, 1, data_size, f);
    fclose(f);
}

static DWORD read_value_file(const char* path, void* buf, DWORD buf_size,
                            DWORD* out_type) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    DWORD type = 0;
    if (fread(&type, sizeof(type), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    size_t got = fread(buf, 1, buf_size, f);
    fclose(f);
    if (out_type) *out_type = type;
    return (DWORD)got;
}

// NtOpenKey
NTSTATUS nt_open_key(PHANDLE key, DWORD access_mask, POBJECT_ATTRIBUTES obj) {
    (void)access_mask;
    if (!key || !obj || !obj->ObjectName || !obj->ObjectName->Buffer)
        return STATUS_INVALID_PARAMETER;

    char subkey[4096];
    int len = nt_wide_to_narrow(obj->ObjectName->Buffer, subkey, sizeof(subkey));
    if (len < 0) return STATUS_OBJECT_NAME_NOT_FOUND;

    const char* hive = obj->RootDirectory ? hive_name((DWORD)(uintptr_t)obj->RootDirectory)
                                          : "HKLM";
    char path[8192];
    reg_path_for(hive, subkey, path, sizeof(path));
    if (access(path, F_OK) != 0) {
        NTLL_LOG_DEBUG("registry key not found: %s", path);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    static DWORD key_counter = 0x40000;
    *key = (HANDLE)(uintptr_t)(++key_counter);
    return STATUS_SUCCESS;
}

// NtCreateKey
NTSTATUS nt_create_key(PHANDLE key, DWORD access_mask, POBJECT_ATTRIBUTES obj,
                      DWORD title_index, PUNICODE_STRING class_name,
                      DWORD options, PULONG disposition) {
    (void)access_mask; (void)title_index; (void)class_name; (void)options;
    if (!key || !obj || !obj->ObjectName || !obj->ObjectName->Buffer)
        return STATUS_INVALID_PARAMETER;

    char subkey[4096];
    nt_wide_to_narrow(obj->ObjectName->Buffer, subkey, sizeof(subkey));

    const char* hive = obj->RootDirectory ? hive_name((DWORD)(uintptr_t)obj->RootDirectory)
                                          : "HKLM";
    char path[8192];
    reg_path_for(hive, subkey, path, sizeof(path));
    ensure_dir(path);

    if (disposition) *disposition = access(path, F_OK) == 0 ? 1 : 2;

    static DWORD key_counter = 0x41000;
    *key = (HANDLE)(uintptr_t)(++key_counter);
    return STATUS_SUCCESS;
}

// NtSetValueKey
NTSTATUS nt_set_value_key(HANDLE key, PUNICODE_STRING name,
                         DWORD title_index, DWORD type, PVOID data, ULONG data_size) {
    (void)key; (void)title_index;
    if (!name || !name->Buffer) return STATUS_INVALID_PARAMETER;

    char value_name[1024];
    nt_wide_to_narrow(name->Buffer, value_name, sizeof(value_name));

    // For simplicity, store at the default location under HKLM\CurrentVersion\...
    // Real routing would keep the key handle -> path map.
    char path[8192];
    snprintf(path, sizeof(path), "%s/HKLM", registry_base_path());
    write_value_file(path, "tmp", value_name, type, data, data_size);
    return STATUS_SUCCESS;
}

// NtQueryValueKey
NTSTATUS nt_query_value_key(HANDLE key, PUNICODE_STRING name,
                           int info_class, PVOID buf, ULONG len, PULONG ret_len) {
    (void)key;
    if (!name || !name->Buffer) return STATUS_INVALID_PARAMETER;

    char value_name[1024];
    nt_wide_to_narrow(name->Buffer, value_name, sizeof(value_name));

    char path[8192];
    snprintf(path, sizeof(path), "%s/HKLM/tmp/%s.val", registry_base_path(), value_name);

    if (access(path, F_OK) != 0) return STATUS_OBJECT_NAME_NOT_FOUND;

    DWORD type = 0;
    DWORD got = read_value_file(path, buf, len, &type);
    if (ret_len) *ret_len = got;
    return STATUS_SUCCESS;
}

NTSTATUS nt_delete_key(HANDLE key) {
    (void)key;
    return STATUS_SUCCESS;
}

NTSTATUS nt_close_key(HANDLE key) {
    (void)key;
    return STATUS_SUCCESS;
}

NTSTATUS nt_enum_key(HANDLE key, DWORD index, PVOID info, ULONG len,
                    PULONG ret_len) {
    (void)key; (void)index; (void)info; (void)len;
    if (ret_len) *ret_len = 0;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}