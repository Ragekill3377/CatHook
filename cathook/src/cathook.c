#include "cathook_internal.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef struct hook {
    void   *target;
    void   *replacement;
    void   *original;
    void   *trampoline;
    size_t  trampoline_size;
    uint8_t saved_bytes[CH_STOLEN_MAX];
    size_t  stolen_size;
    struct hook *next;
} hook_t;

static hook_t *g_hooks = NULL;

static hook_t *find_hook(void *target)
{
    hook_t *h = g_hooks;
    while (h) {
        if (h->target == target) return h;
        h = h->next;
    }
    return NULL;
}

int ch_hook(void *target, void *replace, void **original)
{
    if (!target || !replace) return CH_ERR_NOT_HOOKED;

    if (find_hook(target)) return CH_ERR_INSTALLED;

    uint8_t stolen[CH_STOLEN_MAX];
    size_t stolen_size = ch_disasm_stolen((const uint8_t *)target,
                                          CH_STOLEN_MAX, CH_JMP32_SIZE);
    if (stolen_size < CH_JMP32_SIZE || stolen_size > CH_STOLEN_MAX)
        return CH_ERR_DISASM;

    memcpy(stolen, target, stolen_size);

    size_t tramp_size = CH_TRAMP_SIZE;
    void *trampoline = ch_alloc_rx(tramp_size);
    if (!trampoline) return CH_ERR_MEMORY;

    ch_trampoline_build(
        (uint8_t *)trampoline,
        stolen, stolen_size,
        (uint64_t)target,
        (uint64_t)trampoline);

    if (ch_make_writable(target, stolen_size) != 0) {
        munmap(trampoline, tramp_size);
        return CH_ERR_PROTECT;
    }

    ch_write_jmp32((uint8_t *)target, (uint64_t)target, (uint64_t)replace);

    for (size_t i = CH_JMP32_SIZE; i < stolen_size; i++)
        ((uint8_t *)target)[i] = 0x90;

    ch_make_executable(target, stolen_size);

    hook_t *h = calloc(1, sizeof(*h));
    if (!h) {
        munmap(trampoline, tramp_size);
        return CH_ERR_MEMORY;
    }
    h->target      = target;
    h->replacement = replace;
    h->original    = trampoline;
    h->trampoline  = trampoline;
    h->trampoline_size = tramp_size;
    h->stolen_size = stolen_size;
    memcpy(h->saved_bytes, stolen, stolen_size);
    h->next = g_hooks;
    g_hooks  = h;

    if (original) *original = trampoline;
    return CH_ERR_OK;
}

int ch_unhook(void *target)
{
    if (!target) return CH_ERR_NOT_FOUND;

    hook_t **pp = &g_hooks;
    while (*pp) {
        hook_t *h = *pp;
        if (h->target == target) {
            ch_make_writable(target, h->stolen_size);
            memcpy(target, h->saved_bytes, h->stolen_size);
            ch_make_executable(target, h->stolen_size);
            munmap(h->trampoline, h->trampoline_size);
            *pp = h->next;
            free(h);
            return CH_ERR_OK;
        }
        pp = &(*pp)->next;
    }

    return CH_ERR_NOT_HOOKED;
}
