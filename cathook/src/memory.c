#include "cathook_internal.h"
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

size_t ch_get_page_size(void)
{
    long sz = sysconf(_SC_PAGESIZE);
    return sz > 0 ? (size_t)sz : 4096;
}

void *ch_alloc_rx(size_t size)
{
    size_t pagesize = ch_get_page_size();
    size = (size + pagesize - 1) & ~(pagesize - 1);

    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;

    mprotect(p, size, PROT_READ | PROT_EXEC);
    return p;
}

int ch_make_writable(void *addr, size_t size)
{
    size_t pagesize = ch_get_page_size();
    uintptr_t page = (uintptr_t)addr & ~(pagesize - 1);
    uintptr_t end   = ((uintptr_t)addr + size + pagesize - 1) & ~(pagesize - 1);

    return mprotect((void *)page, end - page, PROT_READ | PROT_WRITE | PROT_EXEC);
}

int ch_make_executable(void *addr, size_t size)
{
    size_t pagesize = ch_get_page_size();
    uintptr_t page = (uintptr_t)addr & ~(pagesize - 1);
    uintptr_t end   = ((uintptr_t)addr + size + pagesize - 1) & ~(pagesize - 1);

    return mprotect((void *)page, end - page, PROT_READ | PROT_EXEC);
}
