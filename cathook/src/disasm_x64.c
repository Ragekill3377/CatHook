/*
 * disasm_x64.c — x86_64 instruction length decoder for cathook
 *
 * Determines the exact byte length of any x86_64 instruction.
 * This is used to find safe instruction boundaries when stealing
 * function prologue code for inline hooking.
 *
 * Algorithm:
 *   [legacy prefixes]*  [REX]?  [VEX|EVEX|XOP]?  [opcode 1-3]
 *   [ModR/M]?  [SIB]?  [displacement]?  [immediate]?
 */

#include "cathook_internal.h"
#include <stdint.h>

/* -----------------------------------------------------------------------
 * Flag tables
 * ----------------------------------------------------------------------- */

/*
 * Encoding for immediate-type tables:
 *   0 = no immediate
 *   1 = imm8
 *   2 = imm16 or imm32  (depends on operand-size prefix 0x66)
 *   3 = imm32 or imm64  (depends on REX.W)
 *   4 = always imm16
 *   5 = rel8            (counted as 1 byte)
 *   6 = rel32           (counted as 4 bytes, not prefix-dependent)
 *   7 = moffs           (no ModR/M; displacement acts as address)
 *   8 = imm8 + imm8     (ENTER: imm16 + imm8)
 *   9 = group dependent (checked by handler)
 */

#define IT_NONE    0
#define IT_IMM8    1
#define IT_IMMZ    2
#define IT_IMMV    3
#define IT_IMM16   4
#define IT_REL8    5
#define IT_REL32   6
#define IT_MOFFS   7
#define IT_ENTER   8
#define IT_GROUP   9

/* Does the 1-byte opcode need a ModR/M byte?  1 = needs ModR/M */
static const uint8_t has_modrm_1[256] = {
    /* 0x00 */ 1,1,1,1, 0,0,1,1, 1,1,1,1, 0,0,1,1,
    /* 0x10 */ 1,1,1,1, 0,0,1,1, 1,1,1,1, 0,0,1,1,
    /* 0x20 */ 1,1,1,1, 0,0,1,1, 1,1,1,1, 0,0,1,1,
    /* 0x30 */ 1,1,1,1, 0,0,1,1, 1,1,1,1, 0,0,1,1,
    /* 0x40 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0x50 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0x60 */ 0,0,0,1, 0,0,0,0, 0,1,0,1, 0,0,0,0,
    /* 0x70 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0x80 */ 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* 0x90 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xA0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xB0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xC0 */ 1,1,0,0, 0,0,1,1, 0,0,0,0, 0,0,0,0,
    /* 0xD0 */ 1,1,1,1, 0,0,0,0, 1,1,1,1, 1,1,1,1,
    /* 0xE0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xF0 */ 0,0,0,0, 0,0,1,1, 0,0,0,0, 0,0,1,1,
};

/* Immediate-type for 1-byte opcodes.
 * Values: see IT_* constants above.
 */
static const uint8_t imm_type_1[256] = {
    /* 0x00 */ 0,0,0,0, IT_IMM8,IT_IMMZ,0,0, 0,0,0,0, IT_IMM8,IT_IMMZ,0,0,
    /* 0x10 */ 0,0,0,0, IT_IMM8,IT_IMMZ,0,0, 0,0,0,0, IT_IMM8,IT_IMMZ,0,0,
    /* 0x20 */ 0,0,0,0, IT_IMM8,IT_IMMZ,0,0, 0,0,0,0, IT_IMM8,IT_IMMZ,0,0,
    /* 0x30 */ 0,0,0,0, IT_IMM8,IT_IMMZ,0,0, 0,0,0,0, IT_IMM8,IT_IMMZ,0,0,
    /* 0x40 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0x50 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0x60 */ 0,0,0,0, 0,0,0,0, IT_IMMZ,IT_IMMZ,IT_IMM8,IT_IMM8, 0,0,0,0,
    /* 0x70 */ IT_REL8,IT_REL8,IT_REL8,IT_REL8, IT_REL8,IT_REL8,IT_REL8,IT_REL8,
              IT_REL8,IT_REL8,IT_REL8,IT_REL8, IT_REL8,IT_REL8,IT_REL8,IT_REL8,
    /* 0x80 */ IT_IMM8,IT_IMMZ,IT_IMM8,IT_IMM8, 0,0,0,0,
              0,0,0,0, 0,0,0,0,
    /* 0x90 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xA0 */ IT_MOFFS,IT_MOFFS,IT_MOFFS,IT_MOFFS, 0,0,0,0,
              IT_IMM8,IT_IMMZ,0,0, 0,0,0,0,
    /* 0xB0 */ IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8, IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
              IT_IMMV,IT_IMMV,IT_IMMV,IT_IMMV, IT_IMMV,IT_IMMV,IT_IMMV,IT_IMMV,
    /* 0xC0 */ IT_IMM8,IT_IMMZ,IT_IMM16,0, 0,0,IT_IMM8,IT_IMMZ,
              IT_ENTER,0,IT_IMM16,0, 0,IT_IMM8,0,0,
    /* 0xD0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 0xE0 */ IT_REL8,IT_REL8,IT_REL8,IT_REL8, IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
              IT_REL32,IT_REL32,0,IT_REL8, 0,0,0,0,
    /* 0xF0 */ 0,0,0,0, 0,0,IT_GROUP,IT_GROUP, 0,0,0,0, 0,0,IT_GROUP,IT_GROUP,
};

/* -----------------------------------------------------------------------
 * 0x0F two-byte opcode tables
 * ----------------------------------------------------------------------- */

/* Does this 0x0F NN opcode need a ModR/M byte? */
static const uint8_t has_modrm_0f[256] = {
    /*          x0  x1  x2  x3  x4  x5  x6  x7   x8  x9  xA  xB  xC  xD  xE  xF */
    /* 0x00 */  1,  1,  1,  1,  0,  0,  0,  0,    0,  0,  0,  0,  0,  1,  0,  1,
    /* 0x10 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0x20 */  1,  1,  1,  1,  1,  1,  0,  0,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0x30 */  0,  0,  0,  0,  0,  0,  0,  0,    0,  0,  0,  0,  0,  0,  0,  0,
    /* 0x40 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0x50 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0x60 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0x70 */  1,  1,  1,  1,  1,  1,  1,  1,    0,  0,  0,  0,  0,  0,  1,  1,
    /* 0x80-0x8F Jcc rel32 — no ModR/M */
    /* 0x80 */  0,  0,  0,  0,  0,  0,  0,  0,    0,  0,  0,  0,  0,  0,  0,  0,
    /* 0x90 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0xA0 */  0,  0,  0,  1,  1,  1,  0,  0,    0,  0,  0,  1,  1,  1,  1,  1,
    /* 0xB0 */  1,  1,  1,  1,  1,  1,  1,  1,    0,  1,  1,  1,  1,  1,  1,  1,
    /* 0xC0 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0xD0 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0xE0 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
    /* 0xF0 */  1,  1,  1,  1,  1,  1,  1,  1,    1,  1,  1,  1,  1,  1,  1,  1,
};

/* Immediate types for 0x0F NN opcodes */
static const uint8_t imm_type_0f[256] = {
    /* 0x00 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x10 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x20 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x30 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x40 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x50 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8, 0,0,0,0,  0,0,0,0,0,0,0,0,
    /* 0x80-0x8F */
    /* 0x80 */  IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32,
                IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32, IT_REL32,
    /* 0x90 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xB0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xC0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 */  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
};

/* -----------------------------------------------------------------------
 * 0x0F 0x38 / 0x0F 0x3A three-byte opcode tables
 * ----------------------------------------------------------------------- */

static const uint8_t has_modrm_0f38[256] = {
    /* 0x00 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x10 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x20 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x30 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x40 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x50 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x60 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x70 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x80 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x90 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xA0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xB0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xC0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xD0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xE0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xF0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0,
};

static const uint8_t imm_type_0f38[256] = {
    /* 0x00 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x10 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x20 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x30 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x40 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x50 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x60 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x70 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x80 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x90 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xA0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xB0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xC0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xD0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xE0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xF0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,IT_IMM8,0,
};

static const uint8_t has_modrm_0f3a[256] = {
    /* 0x00 */  0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1,
    /* 0x10 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x20 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x30 */  1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0,
    /* 0x40 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x50 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x60 */  1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
    /* 0x70 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x80 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x90 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xA0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xB0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xC0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xD0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xE0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xF0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

static const uint8_t imm_type_0f3a[256] = {
    /* 0x00 */  0,0,0,0,0,0,0,0, IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x10 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x20 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x30 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                0,0,0,0,0,0,0,0,
    /* 0x40 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x50 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x60 */  IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
                IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,IT_IMM8,
    /* 0x70 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x80 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x90 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xA0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xB0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xC0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xD0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xE0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0xF0 */  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

/* -----------------------------------------------------------------------
 * Helper: compute immediate byte count
 * ----------------------------------------------------------------------- */

static size_t imm_bytes(uint8_t immt, bool opsize_66, bool rex_w,
                         uint8_t modrm_reg)
{
    switch (immt) {
    case IT_NONE:   return 0;
    case IT_IMM8:   return 1;
    case IT_IMM16:  return 2;
    case IT_REL8:   return 1;
    case IT_REL32:  return 4;
    case IT_ENTER:  return 3;           /* imm16 + imm8 = 3 bytes */
    case IT_IMMZ:
        if (opsize_66) return 2;        /* imm16 */
        return 4;                       /* imm32 */
    case IT_IMMV:
        if (rex_w)     return 8;        /* imm64 */
        if (opsize_66) return 2;        /* imm16 */
        return 4;                       /* imm32 */
    case IT_MOFFS:
        /* moffs offset: 64-bit address by default, 32-bit with 0x67 prefix.
         * The caller handles this via has_addrsize flag. */
        return 0;                       /* caller adds displacement */
    case IT_GROUP:
        /* Group 4 (F6/F7): reg=0,1 → imm. F6=imm8, F7=immZ */
        if (modrm_reg == 0 || modrm_reg == 1) {
            /* The exact opcode determines size; handled by caller */
            return 0;                   /* caller decides */
        }
        return 0;
        /* Group 5-8 (FE/FF): no immediate */
    default:        return 0;
    }
}

/* -----------------------------------------------------------------------
 * ModR/M displacement decoding
 *
 * Reads the ModR/M, optional SIB, and displacement bytes.
 * Returns the number of bytes consumed (ModR/M + SIB + displacement).
 * Sets *p_modrm to the raw ModR/M byte value.
 * Sets *p_has_displacement to true if a displacement was present.
 * Sets *p_sib to the SIB byte if SIB was present (0 otherwise).
 * Returns 0 on failure (buffer too short).
 * ----------------------------------------------------------------------- */

static size_t modrm_decode(const uint8_t *p, const uint8_t *end,
                            bool rex_b,
                            uint8_t *p_modrm, bool *p_has_disp,
                            uint8_t *p_sib)
{
    uint8_t modrm, sib = 0;
    size_t  len = 1; /* ModR/M byte itself */

    if (p >= end) return 0;
    modrm = *p;
    *p_modrm = modrm;

    uint8_t mod  = (modrm >> 6) & 3;
    uint8_t rm   =  modrm & 7;

    /* mod=11: register-to-register — no memory operand */
    if (mod == 3) {
        *p_has_disp = false;
        *p_sib = 0;
        return len; /* just 1 byte */
    }

    /* Determine if SIB is present.
     * SIB is needed when rm == 4 (binary 100) and mod != 3. */
    bool need_sib = (rm == 4);

    /* SIB byte */
    if (need_sib) {
        if (p + len >= end) return 0;
        sib = *(p + len);
        len++;
        *p_sib = sib;
    } else {
        *p_sib = 0;
    }

    /* Displacement size based on mod and special rm encodings */
    size_t disp_bytes = 0;

    if (mod == 1) {
        /* mod=01: 8-bit displacement */
        disp_bytes = 1;
    } else if (mod == 2) {
        /* mod=10: 32-bit displacement (16-bit if 16-bit address mode,
         * but in x86_64 addr16 is not supported; addr32 uses disp32) */
        disp_bytes = 4;
    } else {
        /* mod=00:
         *   rm=101 (without SIB) → RIP-relative in 64-bit mode → disp32
         *     (in 32-bit mode it would be [disp32] absolute)
         *   rm=100 (SIB) with base=101 → [index*scale + disp32] (no base)
         *     Exception: if REX.B is set, base is r13 and there is
         *     no displacement (acts like a normal register).
         */
        if (!need_sib && rm == 5) {
            /* [rip+disp32] in 64-bit mode, [disp32] in 32-bit */
            disp_bytes = 4;
        } else if (need_sib) {
            uint8_t base = sib & 7;
            /* If base=101 under mod=00 and REX.B=0:
             *   [index*scale + disp32] (no base register).
             * If base=101 under mod=00 and REX.B=1 (r13):
             *   [r13 + index*scale] with no displacement.
             * If base != 101: no displacement.
             */
            if (base == 5 && !rex_b) {
                disp_bytes = 4;
            }
            /* else: base != 101, or base=101 with REX.B (r13) — no disp */
        }
        /* else: normal [base] or [base+index] — no displacement */
    }

    if (disp_bytes) {
        if (p + len + disp_bytes > end) return 0;
        len += disp_bytes;
        *p_has_disp = true;
    } else {
        *p_has_disp = false;
    }

    return len;
}

/* -----------------------------------------------------------------------
 * Core decoder — run after prefixes have been skipped
 *
 * Parameters:
 *   p          — points to opcode byte (AFTER all prefixes)
 *   end        — end of buffer
 *   has_opsize — 0x66 operand-size override prefix seen
 *   has_addrs  — 0x67 address-size override prefix seen
 *   rex_w      — REX.W bit (64-bit operand size)
 *   rex_b      — REX.B bit (extends ModR/M rm / SIB base)
 *   vex_m      — VEX.m-mmmm map select (0 if not VEX)
 *
 * Returns: length of instruction starting from `p`, or 0 on error.
 * ----------------------------------------------------------------------- */

static size_t decode_op(const uint8_t *p, const uint8_t *end,
                         bool has_opsize, bool has_addrs,
                         bool rex_w, bool rex_b,
                         uint8_t vex_m)
{
    const uint8_t *start = p;
    uint8_t op, op2, op3;
    bool    need_modrm;
    uint8_t immt;
    uint8_t modrm = 0, sib = 0;
    bool    has_disp = false;
    size_t  len;
    uint8_t modrm_reg;

    /* ---- Read the opcode byte(s) ---- */

    if (p >= end) return 0;
    op = *p++;

    /* Implied 0x0F prefix from VEX.m-mmmm:
     *   VEX.m = 1 → 0x0F
     *   VEX.m = 2 → 0x0F 0x38
     *   VEX.m = 3 → 0x0F 0x3A
     * For non-VEX: we read 0x0F explicitly.
     */
    if (vex_m == 1) {
        /* Implied 0x0F — op is the second opcode byte */
        if (p >= end) return 0;
        op2 = *p++;
        need_modrm = has_modrm_0f[op2];
        immt       = imm_type_0f[op2];
        goto have_opcode;
    }
    if (vex_m == 2) {
        /* Implied 0x0F 0x38 */
        if (p >= end) return 0;
        op2 = *p++;
        need_modrm = has_modrm_0f38[op2];
        immt       = imm_type_0f38[op2];
        goto have_opcode;
    }
    if (vex_m == 3) {
        /* Implied 0x0F 0x3A */
        if (p >= end) return 0;
        op2 = *p++;
        need_modrm = has_modrm_0f3a[op2];
        immt       = imm_type_0f3a[op2];
        goto have_opcode;
    }

    /* No implied prefix: check for explicit 0x0F */
    if (op == 0x0F) {
        if (p >= end) return 0;
        op2 = *p++;

        if (op2 == 0x38) {
            if (p >= end) return 0;
            op3 = *p++;
            need_modrm = has_modrm_0f38[op3];
            immt       = imm_type_0f38[op3];
            goto have_opcode;
        }
        if (op2 == 0x3A) {
            if (p >= end) return 0;
            op3 = *p++;
            need_modrm = has_modrm_0f3a[op3];
            immt       = imm_type_0f3a[op3];
            goto have_opcode;
        }

        need_modrm = has_modrm_0f[op2];
        immt       = imm_type_0f[op2];
        goto have_opcode;
    }

    /* 1-byte opcode — no 0x0F prefix */
    need_modrm = has_modrm_1[op];
    immt       = imm_type_1[op];

have_opcode:
    /* ---- Handle ModR/M ---- */

    if (need_modrm) {
        len = modrm_decode(p, end, rex_b,
                            &modrm, &has_disp, &sib);
        if (len == 0) return 0;
        p += len;
    }

    modrm_reg = (modrm >> 3) & 7;

    /* ---- Handle immediate ---- */

    /* For IT_GROUP (F6/F7 and FE/FF groups):
     * We need to look at the ModR/M.reg field to determine if an
     * immediate is present. This only applies to Group 4 (F6/F7).
     * FE/FF (Group 5/6) never have an immediate.
     */
    if (immt == IT_GROUP) {
        if (op == 0xF6 && (modrm_reg == 0 || modrm_reg == 1)) {
            immt = IT_IMM8;
        } else if (op == 0xF7 && (modrm_reg == 0 || modrm_reg == 1)) {
            immt = IT_IMMZ;
        } else {
            immt = IT_NONE;
        }
    }

    if (immt == IT_MOFFS) {
        /* MOV AL/AX/EAX/RAX, moffs (A0-A3)
         * moffs offset: 8 bytes in 64-bit mode, 4 with 0x67 prefix */
        size_t moffs_len = has_addrs ? 4 : 8;
        if (p + moffs_len > end) return 0;
        p += moffs_len;
        return (size_t)(p - start);
    }

    size_t ilen = imm_bytes(immt, has_opsize, rex_w, modrm_reg);
    if (ilen) {
        if (p + ilen > end) return 0;
        p += ilen;
    }

    return (size_t)(p - start);
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

static bool is_legacy_prefix(uint8_t b)
{
    switch (b) {
    case 0xF0: /* LOCK   */
    case 0xF2: /* REPNE  */
    case 0xF3: /* REP    */
    case 0x2E: /* CS     */
    case 0x36: /* SS     */
    case 0x3E: /* DS     */
    case 0x26: /* ES     */
    case 0x64: /* FS     */
    case 0x65: /* GS     */
    case 0x66: /* operand-size override */
    case 0x67: /* address-size override */
        return true;
    default:
        return false;
    }
}

size_t ch_disasm_len(const uint8_t *code, size_t max_len)
{
    const uint8_t *p   = code;
    const uint8_t *end = code + max_len;
    bool has_opsize = false;
    bool has_addrs  = false;
    bool rex_w      = false;
    bool rex_b      = false;
    uint8_t vex_m   = 0;

    /* Step 1: scan legacy prefixes.
     * Multiple legacy prefixes can appear in any order.
     * We cap at 15 bytes total prefixes per Intel recommendations. */
    size_t prefix_count = 0;
    while (p < end && is_legacy_prefix(*p) && prefix_count < 15) {
        switch (*p) {
        case 0x66: has_opsize = true; break;
        case 0x67: has_addrs  = true; break;
        default:   break;
        }
        p++;
        prefix_count++;
    }

    /* Step 2: REX prefix (0x40-0x4F).
     * Must be the LAST prefix before the opcode.
     * In x86_64, REX.W=1 gives 64-bit operand size. */
    if (p < end && *p >= 0x40 && *p <= 0x4F) {
        uint8_t rex_byte = *p;
        rex_w   = (rex_byte & 0x08) != 0;
        rex_b   = (rex_byte & 0x01) != 0;
        /* REX.R = bit 2, REX.X = bit 1 — not needed for length decoding */
        p++;
    }

    /* Step 3: VEX / EVEX / XOP prefixes */

    /* 2-byte VEX: 0xC5 <byte2>
     * byte2: [7:3] = ~R|~X|~B|map_select[4:0] */
    if (p + 1 < end && *p == 0xC5 && p[1] >= 0x80) {
        uint8_t b2 = p[1];
        /* In 2-byte VEX, R, X, B are inverted. R=~(b2>>7)&1, etc.
         * For length decoding, REX.B equivalent = ~(b2>>2)&1
         * VEX.m-mmmm = b2 & 0x1F (low 5 bits) */
        uint8_t m = b2 & 0x1F;
        if (m == 1 || m == 2 || m == 3) {
            vex_m   = m;
            /* In 2-byte VEX, VEX.W is always 0 (only in 3-byte VEX) */
            rex_w   = false;
            /* Inverted B: rex_b = ~(b2>>2) & 1 */
            rex_b   = (~b2 >> 2) & 1;
            p += 2;
            goto decode;
        }
    }

    /* 3-byte VEX: 0xC4 <byte2> <byte3>
     * byte2: [7:3] = ~R|~X|~B|map_select[4:0]
     * byte3: [7] = W, [6:3] = ~vvvv, [2:0] = ~L */
    if (p + 2 < end && *p == 0xC4 && (p[1] & 0x80)) {
        uint8_t b2 = p[1];
        uint8_t b3 = p[2];
        uint8_t m  = b2 & 0x1F;
        if (m == 1 || m == 2 || m == 3) {
            vex_m   = m;
            rex_w   = (b3 >> 7) & 1;
            rex_b   = (~b2 >> 2) & 1;
            p += 3;
            goto decode;
        }
    }

    /* EVEX: 0x62 <P0> <P1> <P2> (4 bytes total) */
    if (p + 3 < end && *p == 0x62) {
        uint8_t b2 = p[1];
        /* Check that R' and X' from P0 are properly set (bits 7 and 6 of P0
         * should be 0 for 64-bit mode; 1 means 32-bit compat mode).
         * Skip if R' or X' set (indicates 32-bit EVEX encoding,
         * not valid in 64-bit mode). */
        if ((b2 & 0xC0) == 0x00) {
            uint8_t b3 = p[2];
            uint8_t b4 = p[3];
            uint8_t m  = b2 & 0x07;    /* P0[3:1] = mm, P0[0]=R' already checked as 0 */
            vex_m      = m;
            rex_w      = (b3 >> 7) & 1;  /* P1[7] = W */
            rex_b      = (~b4 >> 4) & 1; /* P2[4] = B with inverted meaning */
            p += 4;
            goto decode;
        }
    }

    /* XOP: 0x8F (3-byte, AMD XOP)
     * Only valid when ModR/M field is present.
     * We check if next byte's high 3 bits are set (indicating the ~R|~X|~B
     * signature of VEX/XOP style prefixes). */
    if (p + 2 < end && *p == 0x8F && (p[1] & 0x80)) {
        uint8_t b2 = p[1];
        uint8_t b3 = p[2];
        uint8_t m  = b2 & 0x1F;
        /* XOP map: 8=0x08, 9=0x09, 10=0x0A */
        if (m >= 8 && m <= 10) {
            vex_m   = m;
            rex_w   = (b3 >> 7) & 1;
            rex_b   = (~b2 >> 2) & 1;
            p += 3;
            goto decode;
        }
    }

decode:
    /* Step 4: decode the opcode and operands */
    if (p >= end) return 0;

    size_t insn_len = decode_op(p, end, has_opsize, has_addrs,
                                 rex_w, rex_b, vex_m);
    if (insn_len == 0) return 0;

    return (size_t)(p - code) + insn_len;
}

size_t ch_disasm_stolen(const uint8_t *code, size_t max_len,
                         size_t min_needed)
{
    size_t total  = 0;
    const uint8_t *p = code;

    while (total < min_needed && total < max_len) {
        size_t remaining = max_len - (size_t)(p - code);
        size_t len = ch_disasm_len(p, remaining);
        if (len == 0) {
            /* Decode failure — return 0 to signal error */
            return 0;
        }
        total += len;
        p     += len;
    }

    return total;
}
