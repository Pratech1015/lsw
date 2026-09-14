// memory.c - Windows virtual memory emulation for LSW/NTLL
// Copyright (c) 2026 LSW Contributors
//
// Implements VirtualAlloc/VirtualFree equivalents plus heap APIs.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#include "ntll.h"

#define PAGE_SIZE 4096

typedef struct _NTLL_VM_HEAD {
    void* base;
    size_t size;
    int prot;
    struct _NTLL_VM_HEAD* next;
} NTLL_VM_HEAD;

static NTLL_VM_HEAD* g_vm_heads = NULL;
static pthread_mutex_t g_vm_lock = PTHREAD_MUTEX_INITIALIZER;
static void* g_heap_base = NULL;
static size_t g_heap_top = 0;

static int win_prot_to_linux(DWORD prot) {
    switch (prot) {
        case 0x01: return PROT_READ;                                  // PAGE_NOACCESS... (0x01 is NOACCESS)
        case 0x02: return PROT_READ;                                  // PAGE_READONLY
        case 0x04: return PROT_READ | PROT_WRITE;                     // PAGE_READWRITE
        case 0x08: return PROT_WRITE;                                 // PAGE_WRITECOPY
        case 0x10: return PROT_READ | PROT_EXEC;                      // PAGE_EXECUTE
        case 0x20: return PROT_READ | PROT_EXEC;                      // PAGE_EXECUTE_READ
        case 0x40: return PROT_READ | PROT_WRITE | PROT_EXEC;         // PAGE_EXECUTE_READWRITE
        case 0x80: return PROT_READ | PROT_WRITE;                     // PAGE_EXECUTE_WRITECOPY
        default:   return PROT_READ | PROT_WRITE;
    }
}

// VirtualAlloc
PVOID nt_alloc_virtual_memory(SIZE_T size, DWORD protection) {
    if (size == 0) size = PAGE_SIZE;
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    int prot = win_prot_to_linux(protection);
    void* p = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;

    NTLL_VM_HEAD* h = malloc(sizeof(NTLL_VM_HEAD));
    if (!h) {
        munmap(p, size);
        return NULL;
    }

    pthread_mutex_lock(&g_vm_lock);
    h->base = p;
    h->size = size;
    h->prot = prot;
    h->next = g_vm_heads;
    g_vm_heads = h;
    pthread_mutex_unlock(&g_vm_lock);

    NTLL_LOG_DEBUG("VirtualAlloc %zu bytes at %p", size, p);
    return p;
}

// VirtualFree
NTSTATUS nt_free_virtual_memory(PVOID base, SIZE_T size) {
    (void)size;
    pthread_mutex_lock(&g_vm_lock);
    NTLL_VM_HEAD** pp = &g_vm_heads;
    while (*pp) {
        if ((*pp)->base == base) {
            NTLL_VM_HEAD* victim = *pp;
            *pp = victim->next;
            munmap(base, victim->size);
            free(victim);
            pthread_mutex_unlock(&g_vm_lock);
            return STATUS_SUCCESS;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_vm_lock);
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS nt_protect_virtual_memory(PVOID base, SIZE_T size, DWORD new_protect,
                                  DWORD* old_protect) {
    pthread_mutex_lock(&g_vm_lock);
    NTLL_VM_HEAD* p = g_vm_heads;
    while (p) {
        if (p->base == base) {
            if (old_protect) {
                *old_protect = (p->prot & PROT_WRITE) ? 0x04 : 0x02;
            }
            int linux_prot = win_prot_to_linux(new_protect);
            if (mprotect(base, p->size, linux_prot) == 0) {
                p->prot = linux_prot;
                pthread_mutex_unlock(&g_vm_lock);
                return STATUS_SUCCESS;
            }
            pthread_mutex_unlock(&g_vm_lock);
            return STATUS_ACCESS_VIOLATION;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&g_vm_lock);
    return STATUS_INVALID_PARAMETER;
}

// HeapAlloc / HeapFree backing
void* ntll_heap_alloc(size_t size) {
    if (!g_heap_base) {
        g_heap_base = nt_alloc_virtual_memory(64 * 1024 * 1024, 0x04);
        g_heap_top = 0;
    }
    size = (size + 15) & ~(size_t)15;
    if (g_heap_top + size >= 64 * 1024 * 1024) {
        // Grow heap (simplified: allocate another chunk)
        void* extra = nt_alloc_virtual_memory(64 * 1024 * 1024, 0x04);
        if (!extra) return NULL;
        // Simple bump allocator pointer switch - v1 just sets base to extra
        g_heap_base = extra;
        g_heap_top = 0;
    }
    void* result = (BYTE*)g_heap_base + g_heap_top;
    g_heap_top += size;
    NTLL_LOG_DEBUG("heap alloc %zu -> %p", size, result);
    return result;
}

void ntll_heap_free(void* ptr) {
    (void)ptr; // v1 bump allocator: no free
}

// Map view of section (backed by a file)
PVOID nt_map_view_of_file(HANDLE file, SIZE_T size, DWORD protection) {
    (void)file;
    int prot = win_prot_to_linux(protection);
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    void* p = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    NTLL_LOG_DEBUG("mapped view of size %zu at %p", size, p);
    return p;
}

// Query memory info - minimal
NTSTATUS nt_query_virtual_memory(PVOID base, int info_class, PVOID buf,
                                SIZE_T len, PSIZE_T ret_len) {
    if (info_class == 0x00) { // MemoryBasicInformation
        if (len < 48) return STATUS_BUFFER_TOO_SMALL;
        memset(buf, 0, len);
        DWORD* out = buf;
        out[0] = (DWORD)(uintptr_t)base; // BaseAddress
        out[1] = 0;                     // AllocationBase
        out[2] = 0x8000 | 0x2000;       // AllocationProtect MEM_PRIVATE|READWRITE
        out[3] = 0x10000;               // RegionSize
        out[4] = 0x1000;                // State MEM_COMMIT
        out[5] = 0x0004;                // Protect PAGE_READWRITE
        out[6] = 0x20000;               // Type MEM_PRIVATE
        if (ret_len) *ret_len = 48;
        return STATUS_SUCCESS;
    }
    if (ret_len) *ret_len = 0;
    return STATUS_SUCCESS;
}

// Allocate aligned block (used by CRT often)
void* ntll_aligned_alloc(size_t alignment, size_t size) {
    void* p = malloc(size + alignment + sizeof(void*));
    if (!p) return NULL;
    uintptr_t addr = (uintptr_t)p + sizeof(void*);
    addr = (addr + alignment - 1) & ~(alignment - 1);
    ((void**)addr)[-1] = p;
    return (void*)addr;
}

void ntll_aligned_free(void* ptr) {
    if (!ptr) return;
    void* original = ((void**)ptr)[-1];
    free(original);
}