// pe_loader.c - Portable Executable loader for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Implements a full PE/COFF loader: parses DOS/NT headers, loads sections,
// resolves imports, applies relocations, and exposes export lookup.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "ntll.h"

/* ms_abi wrappers for setjmp/longjmp — bypass trampolines */
extern int  ms_setjmp(void* j) __attribute__((ms_abi));
extern void ms_longjmp(void* j, int v) __attribute__((ms_abi, noreturn));

static const char* g_system_root = "/var/lib/lsw/root";
static pthread_mutex_t g_pe_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void* rva_to_ptr(PNTLL_MODULE mod, DWORD rva) {
    // Sections are mapped at their virtual addresses (base_address + va),
    // so an RVA resolves to the same image-relative offset in memory.
    return rva ? (BYTE*)mod->base_address + rva : NULL;
}

// Read file into memory
static unsigned char* read_whole_file(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    unsigned char* buf = malloc(sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    if (out_size) *out_size = (size_t)sz;
    return buf;
}

// Allocate a memory block into which we map the whole image with correct protection
static PVOID allocate_image_memory(const IMAGE_NT_HEADERS64* nt) {
    size_t size = nt->OptionalHeader.SizeOfImage;
    size_t align = 0x10000; // 64K allocation granularity
    size = (size + align - 1) & ~(align - 1);
    void* addr = mmap(NULL, size, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (addr == MAP_FAILED) return NULL;
    return addr;
}

// Map each section into its ImageBase-relative VA
static NTSTATUS map_sections(PNTLL_MODULE mod, const unsigned char* file_data,
                             const IMAGE_NT_HEADERS64* nt, void* image_base) {
    DWORD i;
    DWORD section_count = nt->FileHeader.NumberOfSections;
    DWORD header_size = nt->OptionalHeader.SizeOfHeaders;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    long page = (long)sysconf(_SC_PAGESIZE);

    // Map headers (copy first, then tighten protection below)
    if (mprotect(image_base, (header_size + page - 1) & ~(page - 1),
                 PROT_READ | PROT_WRITE) != 0)
        return STATUS_NO_MEMORY;
    memcpy(image_base, file_data, header_size);

    for (i = 0; i < section_count; i++) {
        const IMAGE_SECTION_HEADER* sh = &mod->sections[i];
        DWORD va = sh->VirtualAddress;
        DWORD vs = sh->Misc.VirtualSize;
        DWORD raw = sh->PointerToRawData;
        DWORD raw_size = sh->SizeOfRawData;
        DWORD padding = 0;

        if (vs == 0) vs = raw_size;
        vs = (vs + page - 1) & ~(page - 1);
        if ((size_t)va + vs > image_size) vs = (DWORD)(image_size - (size_t)va);

        // Write data into the section with full access first
        if (mprotect((BYTE*)image_base + va, vs, PROT_READ | PROT_WRITE) != 0)
            return STATUS_NO_MEMORY;
        if (raw_size && raw > 0) {
            memcpy((BYTE*)image_base + va, file_data + raw, raw_size);
            padding = (sh->Misc.VirtualSize > raw_size && sh->Misc.VirtualSize <= vs)
                          ? (sh->Misc.VirtualSize - raw_size) : 0;
        } else {
            padding = vs;
        }
        if (padding > 0)
            memset((BYTE*)image_base + va + (raw_size ? raw_size : 0), 0, padding);
    }

    // Tighten protections to match section characteristics
    DWORD iat_rva = 0, iat_size = 0;
    {
        IMAGE_DATA_DIRECTORY* iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        iat_rva = iat->VirtualAddress;
        iat_size = iat->Size;
    }
    for (i = 0; i < section_count; i++) {
        const IMAGE_SECTION_HEADER* sh = &mod->sections[i];
        DWORD va = sh->VirtualAddress;
        DWORD vs = sh->Misc.VirtualSize;
        DWORD raw_size = sh->SizeOfRawData;
        int prot = PROT_NONE;

        if (vs == 0) vs = raw_size;
        vs = (vs + page - 1) & ~(page - 1);
        if ((size_t)va + vs > image_size) vs = (DWORD)(image_size - (size_t)va);

        DWORD flags = sh->Characteristics;
        if (flags & IMAGE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;
        if (flags & IMAGE_SCN_MEM_READ) prot |= PROT_READ;
        if (flags & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;

        // The import address table gets patched at load time, so its backing
        // section must stay writable even if the image marks it read-only.
        if (iat_rva && iat_size &&
            ((iat_rva >= va && iat_rva < va + vs) ||
             (iat_rva < va && iat_rva + iat_size > va)))
            prot |= PROT_WRITE;

        mprotect((BYTE*)image_base + va, vs, prot);
    }

    // Lock the headers down to read-only
    mprotect(image_base, (header_size + page - 1) & ~(page - 1), PROT_READ);
    return STATUS_SUCCESS;
}

// Parse and validate the headers
static BOOL parse_pe(const unsigned char* data, size_t size,
                     IMAGE_DOS_HEADER** dos, IMAGE_NT_HEADERS64** nt) {
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    *dos = (IMAGE_DOS_HEADER*)data;
    if ((*dos)->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((*dos)->e_lfanew <= 0) return FALSE;

    *nt = (IMAGE_NT_HEADERS64*)(data + (*dos)->e_lfanew);
    if (sizeof(IMAGE_NT_HEADERS64) > size - (size_t)(*dos)->e_lfanew) return FALSE;
    if ((*nt)->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if ((*nt)->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        NTLL_LOG_ERROR("only PE32+ (64-bit) images supported for now");
        return FALSE;
    }
    if ((*nt)->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        NTLL_LOG_ERROR("only x86-64 images supported");
        return FALSE;
    }
    return TRUE;
}

// Load a PE image file into an NTLL_MODULE
PNTLL_MODULE pe_load(const char* path) {
    size_t file_size = 0;
    unsigned char* file_data = read_whole_file(path, &file_size);
    if (!file_data) {
        NTLL_LOG_ERROR("failed to read %s", path);
        return NULL;
    }

    IMAGE_DOS_HEADER* dos = NULL;
    IMAGE_NT_HEADERS64* nt = NULL;
    if (!parse_pe(file_data, file_size, &dos, &nt)) {
        free(file_data);
        NTLL_LOG_ERROR("invalid PE image: %s", path);
        return NULL;
    }

    PNTLL_MODULE mod = calloc(1, sizeof(NTLL_MODULE));
    if (!mod) {
        free(file_data);
        return NULL;
    }

    strncpy(mod->name, strrchr(path, '/') ? strrchr(path, '/') + 1 : path, MAX_PATH - 1);
    strncpy(mod->full_path, path, MAX_PATH - 1);
    nt_narrow_to_wide(mod->name, mod->wide_name, MAX_PATH);

    // Allocate the image memory
    void* image_base = allocate_image_memory(nt);
    if (!image_base) {
        NTLL_LOG_ERROR("failed to allocate image memory for %s", path);
        free(mod);
        free(file_data);
        return NULL;
    }

    mod->base_address = image_base;
    mod->size_of_image = nt->OptionalHeader.SizeOfImage;
    mod->entry_point = (void*)((BYTE*)image_base + nt->OptionalHeader.AddressOfEntryPoint);
    mod->nt_headers = (IMAGE_NT_HEADERS64*)((BYTE*)image_base + dos->e_lfanew);
    mod->sections = (IMAGE_SECTION_HEADER*)((BYTE*)mod->nt_headers +
                     sizeof(IMAGE_NT_HEADERS64));

    NTSTATUS st = map_sections(mod, file_data, nt, image_base);
    uintptr_t preferred_base = (uintptr_t)nt->OptionalHeader.ImageBase;
    free(file_data);
    if (!NT_SUCCESS(st)) {
        munmap(image_base, mod->size_of_image);
        free(mod);
        return NULL;
    }

    // Apply relocations
    pthread_mutex_lock(&g_pe_lock);
    intptr_t delta = (intptr_t)mod->base_address - (intptr_t)preferred_base;
    if (delta != 0) {
        pe_relocate(mod, delta);
    }
    pthread_mutex_unlock(&g_pe_lock);

    // Resolve imports (lazy - system DLLs are loaded via ntll)
    pe_resolve_imports(mod);

    NTLL_LOG_INFO("loaded image %s at %p, entry %p", path, mod->base_address, mod->entry_point);
    return mod;
}

// Load from memory buffer
PNTLL_MODULE pe_load_from_memory(const void* data, size_t size) {
    // For now, write to a temp file and delegate
    char tmpl[] = "/tmp/lsw-pe-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return NULL;
    }
    close(fd);
    PNTLL_MODULE mod = pe_load(tmpl);
    unlink(tmpl);
    return mod;
}

// Unload a module
void pe_unload(PNTLL_MODULE module) {
    if (!module) return;
    if (module->base_address) {
        munmap(module->base_address, module->size_of_image);
    }
    free(module);
}

// Get named export from a module
void* pe_get_export(PNTLL_MODULE module, const char* name) {
    if (!module) return NULL;
    IMAGE_NT_HEADERS64* nt = module->nt_headers;
    if (!nt) return NULL;

    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = rva_to_ptr(module, dir->VirtualAddress);
    if (!exp) return NULL;

    DWORD* functions = rva_to_ptr(module, exp->AddressOfFunctions);
    DWORD* names = rva_to_ptr(module, exp->AddressOfNames);
    WORD* ordinals = rva_to_ptr(module, exp->AddressOfNameOrdinals);
    if (!functions || !names || !ordinals) return NULL;

    DWORD i;
    for (i = 0; i < exp->NumberOfNames; i++) {
        char* export_name = rva_to_ptr(module, names[i]);
        if (export_name && strcmp(export_name, name) == 0) {
            WORD ord = ordinals[i];
            if (ord < exp->NumberOfFunctions) {
                DWORD func_rva = functions[ord];
                return (BYTE*)module->base_address + func_rva;
            }
        }
    }
    return NULL;
}

// Get export by ordinal
void* pe_get_export_by_ordinal(PNTLL_MODULE module, WORD ordinal) {
    if (!module) return NULL;
    IMAGE_NT_HEADERS64* nt = module->nt_headers;
    if (!nt) return NULL;

    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = rva_to_ptr(module, dir->VirtualAddress);
    DWORD* functions = rva_to_ptr(module, exp->AddressOfFunctions);
    if (!functions) return NULL;

    DWORD index = ordinal - exp->Base;
    if (index < exp->NumberOfFunctions) {
        return (BYTE*)module->base_address + functions[index];
    }
    return NULL;
}

// Apply relocations when the image has a different base than preferred
NTSTATUS pe_relocate(PNTLL_MODULE module, intptr_t delta) {
    if (!module || delta == 0) return STATUS_SUCCESS;
    IMAGE_NT_HEADERS64* nt = module->nt_headers;

    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->VirtualAddress || !dir->Size) return STATUS_SUCCESS; // no relocations needed

    IMAGE_BASE_RELOCATION* reloc = rva_to_ptr(module, dir->VirtualAddress);
    IMAGE_BASE_RELOCATION* reloc_end = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + dir->Size);

    while (reloc < reloc_end && reloc->SizeOfBlock > 0) {
        DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        WORD* types = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        DWORD i;
        for (i = 0; i < entries; i++) {
            WORD entry = types[i];
            DWORD type = entry >> 12;
            DWORD offset = entry & 0x0FFF;
            void* target = (BYTE*)module->base_address + reloc->VirtualAddress + offset;

            switch (type) {
                case 0: // ABSOLUTE
                    break;
                case 1: // HIGH (deprecated, 32-bit)
                case 2: // LOW
                    break;
                case 3: // HIGHLOW (32-bit)
                    *((DWORD*)target) += (DWORD)delta;
                    break;
                case 10: // DIR64
                    *((DWORD64*)target) += (DWORD64)delta;
                    break;
                default:
                    break;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return STATUS_SUCCESS;
}

// Resolve imports - forward to the LSW API dispatch layer
NTSTATUS pe_resolve_imports(PNTLL_MODULE module) {
    if (!module) return STATUS_INVALID_PARAMETER;
    IMAGE_NT_HEADERS64* nt = module->nt_headers;
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress || !dir->Size) return STATUS_SUCCESS;

    IMAGE_IMPORT_DESCRIPTOR* imp = rva_to_ptr(module, dir->VirtualAddress);
    while (imp->Name && imp->OriginalFirstThunk) {
        char* dll_name = rva_to_ptr(module, imp->Name);
        PNTLL_MODULE dep = ntll_load_system_module(dll_name);
        if (!dep) {
            NTLL_LOG_ERROR("cannot resolve dependency %s for %s", dll_name, module->name);
            return STATUS_DLL_NOT_FOUND;
        }

        IMAGE_THUNK_DATA64* orig = rva_to_ptr(module, imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA64* first = rva_to_ptr(module, imp->FirstThunk);

        if (!orig && !first) {
            imp++;
            continue;
        }
        // If OriginalFirstThunk is 0, use FirstThunk as the original
        if (!orig) orig = first;
        if (!first) first = orig;

        int idx = 0;
        while (orig[idx].u1.AddressOfData || orig[idx].u1.Ordinal) {
            void* api = NULL;
            UINT64 val = orig[idx].u1.AddressOfData;
            if (val & 0x8000000000000000ULL) {
                // Imported by ordinal
                api = pe_get_export_by_ordinal(dep, (WORD)(val & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* iin = (IMAGE_IMPORT_BY_NAME*)((BYTE*)module->base_address + (DWORD)val);
                if (iin) {
                    api = ntll_dispatch(dep, (const char*)iin->Name);
                    /* Bypass trampoline for setjmp/longjmp: the trampoline
                       frame breaks longjmp's context restore. */
                    const char* nm = (const char*)iin->Name;
                    if (strcmp(nm, "__intrinsic_setjmp") == 0)
                        api = (void*)ms_setjmp;
                    else if (strcmp(nm, "longjmp") == 0)
                        api = (void*)ms_longjmp;
                }
            }
            first[idx].u1.Function = (UINT64)(uintptr_t)api;
            idx++;
        }
        imp++;
    }
    return STATUS_SUCCESS;
}