#ifndef CATHOOK_INTERNAL_H
#define CATHOOK_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define CH_JMP32_SIZE    5
#define CH_JMPABS_SIZE   14
#define CH_STOLEN_MIN    5
#define CH_STOLEN_MAX    64
#define CH_TRAMP_SIZE    256

typedef enum {
    CH_ERR_OK          = 0,
    CH_ERR_MEMORY      = -1,
    CH_ERR_PROTECT     = -2,
    CH_ERR_DISASM      = -3,
    CH_ERR_RELOCATE    = -4,
    CH_ERR_INSTALLED   = -5,
    CH_ERR_NOT_FOUND   = -6,
    CH_ERR_NOT_HOOKED  = -7,
} ch_err_t;

size_t ch_get_page_size(void);
void *ch_alloc_rx(size_t size);
int  ch_make_writable(void *addr, size_t size);
int  ch_make_executable(void *addr, size_t size);

size_t ch_disasm_len(const uint8_t *code, size_t max_len);
size_t ch_disasm_stolen(const uint8_t *code, size_t max_len, size_t min_needed);

size_t ch_trampoline_build(uint8_t *buf, const uint8_t *stolen,
                            size_t stolen_size, uint64_t orig_addr,
                            uint64_t tramp_addr);

size_t ch_write_jmp32(uint8_t *buf, uint64_t src, uint64_t dst);
size_t ch_write_jmpabs(uint8_t *buf, uint64_t dst);

#endif
