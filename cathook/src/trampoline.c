#include "cathook_internal.h"
#include <string.h>

/* --------------------------------------------------
 * Helpers
 * -------------------------------------------------- */

/* Find ModR/M byte offset within instruction (after prefixes + opcode).
 * Also returns whether REX.B is set (to distinguish r13 from [rip]). */
static size_t find_modrm(const uint8_t *insn, size_t insn_len, bool *rex_b)
{
    size_t off = 0;

    /* skip legacy prefixes */
    while (off < insn_len) {
        uint8_t b = insn[off];
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 ||
            b == 0xF0 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x26 || b == 0x64 || b == 0x65) {
            off++;
            continue;
        }
        break;
    }

    /* REX */
    *rex_b = false;
    if (off < insn_len && (insn[off] & 0xF0) == 0x40) {
        *rex_b = (insn[off] & 1) != 0;
        off++;
    }

    if (off >= insn_len) return off;
    uint8_t op = insn[off++];

    if (op == 0x0F && off < insn_len) {
        op = insn[off++];
        if ((op == 0x38 || op == 0x3A) && off < insn_len)
            off++;
    }

    return off;  /* ModR/M is at this offset, or past the end */
}

/* --------------------------------------------------
 * Public API
 * -------------------------------------------------- */

size_t ch_write_jmp32(uint8_t *buf, uint64_t src, uint64_t dst)
{
    buf[0] = 0xE9;
    int64_t rel64 = (int64_t)(dst - (src + 5));
    int32_t rel32 = (int32_t)rel64;
    memcpy(buf + 1, &rel32, 4);
    return 5;
}

size_t ch_write_jmpabs(uint8_t *buf, uint64_t dst)
{
    buf[0] = 0xFF;
    buf[1] = 0x25;
    int32_t zero = 0;
    memcpy(buf + 2, &zero, 4);
    memcpy(buf + 6, &dst, 8);
    return 14;
}

/* --------------------------------------------------
 * Trampoline build
 * -------------------------------------------------- */

size_t ch_trampoline_build(uint8_t *buf, const uint8_t *stolen,
                            size_t stolen_size, uint64_t orig_addr,
                            uint64_t tramp_addr)
{
    size_t tramp_pos  = 0;
    size_t stolen_pos = 0;
    uint64_t stolen_end = orig_addr + stolen_size;

    while (stolen_pos < stolen_size) {
        const uint8_t *insn     = stolen + stolen_pos;
        uint64_t insn_orig_addr = orig_addr + stolen_pos;
        uint64_t insn_tramp_addr = tramp_addr + tramp_pos;
        size_t orig_insn_len    = ch_disasm_len(insn, stolen_size - stolen_pos);
        if (orig_insn_len == 0) orig_insn_len = 1;

        uint8_t op0 = insn[0];
        uint8_t op1 = (orig_insn_len > 1) ? insn[1] : 0;

        /* ---- JMP rel32 (E9) ---- */
        if (op0 == 0xE9 && orig_insn_len >= 5) {
            int32_t old_rel;
            memcpy(&old_rel, insn + 1, 4);
            uint64_t target = insn_orig_addr + 5 + (int64_t)old_rel;

            if (target >= orig_addr && target < stolen_end) {
                memcpy(buf + tramp_pos, insn, 5);
            } else {
                buf[tramp_pos] = 0xE9;
                int32_t new_rel = (int32_t)((int64_t)target - ((int64_t)insn_tramp_addr + 5));
                memcpy(buf + tramp_pos + 1, &new_rel, 4);
            }
            tramp_pos  += 5;
            stolen_pos += 5;
            continue;
        }

        /* ---- Jcc rel8 (0x70-0x7F) ---- */
        if (op0 >= 0x70 && op0 <= 0x7F && orig_insn_len >= 2) {
            uint8_t cond = op0 & 0x0F;
            int8_t old_rel8 = (int8_t)insn[1];
            uint64_t target = insn_orig_addr + 2 + (int64_t)old_rel8;

            if (target >= orig_addr && target < stolen_end) {
                int16_t new_rel = (int16_t)((int64_t)target - ((int64_t)insn_tramp_addr + 2));
                if (new_rel >= -128 && new_rel <= 127) {
                    buf[tramp_pos]     = op0;
                    buf[tramp_pos + 1] = (uint8_t)new_rel;
                    tramp_pos  += 2;
                    stolen_pos += 2;
                    continue;
                }
            }
            /* widen to 6-byte near form */
            buf[tramp_pos]     = 0x0F;
            buf[tramp_pos + 1] = 0x80 | cond;
            int32_t new_rel32 = (int32_t)((int64_t)target - ((int64_t)insn_tramp_addr + 6));
            memcpy(buf + tramp_pos + 2, &new_rel32, 4);
            tramp_pos  += 6;
            stolen_pos += 2;
            continue;
        }

        /* ---- Jcc rel32 (0F 80-8F) ---- */
        if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F && orig_insn_len >= 6) {
            int32_t old_rel;
            memcpy(&old_rel, insn + 2, 4);
            uint64_t target = insn_orig_addr + 6 + (int64_t)old_rel;

            if (target >= orig_addr && target < stolen_end) {
                memcpy(buf + tramp_pos, insn, 6);
            } else {
                buf[tramp_pos]     = 0x0F;
                buf[tramp_pos + 1] = op1;
                int32_t new_rel = (int32_t)((int64_t)target - ((int64_t)insn_tramp_addr + 6));
                memcpy(buf + tramp_pos + 2, &new_rel, 4);
            }
            tramp_pos  += 6;
            stolen_pos += 6;
            continue;
        }

        /* ---- CALL rel32 (E8) ---- */
        if (op0 == 0xE8 && orig_insn_len >= 5) {
            int32_t old_rel;
            memcpy(&old_rel, insn + 1, 4);
            uint64_t target = insn_orig_addr + 5 + (int64_t)old_rel;

            if (target >= orig_addr && target < stolen_end) {
                memcpy(buf + tramp_pos, insn, 5);
            } else {
                buf[tramp_pos] = 0xE8;
                int32_t new_rel = (int32_t)((int64_t)target - ((int64_t)insn_tramp_addr + 5));
                memcpy(buf + tramp_pos + 1, &new_rel, 4);
            }
            tramp_pos  += 5;
            stolen_pos += 5;
            continue;
        }

        /* ---- RIP-relative addressing (ModR/M mod=00 rm=101, no REX.B) ---- */
        {
            bool rex_b = false;
            size_t modrm_off = find_modrm(insn, orig_insn_len, &rex_b);
            if (modrm_off + 5 <= orig_insn_len) {
                uint8_t modrm = insn[modrm_off];
                uint8_t mod   = (modrm >> 6) & 3;
                uint8_t rm    = modrm & 7;
                if (mod == 0 && rm == 5 && !rex_b) {
                    int32_t old_disp;
                    memcpy(&old_disp, insn + modrm_off + 1, 4);
                    uint64_t src_rip = insn_orig_addr + modrm_off + 5;
                    uint64_t target  = src_rip + (int64_t)old_disp;
                    uint64_t dst_rip = insn_tramp_addr + modrm_off + 5;
                    int32_t new_disp = (int32_t)((int64_t)target - (int64_t)dst_rip);

                    memcpy(buf + tramp_pos, insn, orig_insn_len);
                    memcpy(buf + tramp_pos + modrm_off + 1, &new_disp, 4);
                    tramp_pos  += orig_insn_len;
                    stolen_pos += orig_insn_len;
                    continue;
                }
            }
        }

        /* ---- Default: copy verbatim ---- */
        memcpy(buf + tramp_pos, insn, orig_insn_len);
        tramp_pos  += orig_insn_len;
        stolen_pos += orig_insn_len;
    }

    /* Append jump back to orig_addr + stolen_size */
    tramp_pos += ch_write_jmp32(buf + tramp_pos,
                                 tramp_addr + tramp_pos,
                                 orig_addr + stolen_size);

    return tramp_pos;
}
