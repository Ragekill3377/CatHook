# cathook

A zero-dependency x86_64 function hooking library for Linux. Works within loaded address space.

```
ch_hook(target, replacement, &original);
// target() now calls replacement()
// original() calls the real target()
ch_unhook(target);
// back to normal
```
simple as that.

## How it works

cathook does what MSHookFunction does on iOS, but for x86_64 Linux.

### 1. Steal instructions

The first `N` bytes of the target function are decoded using a built-in x86_64 length disassembler. Instructions are walked until at least 5 bytes are covered (the size of a `JMP rel32`). 

### 2. Build a trampoline

The stolen bytes are copied to a freshly `mmap`'d read-execute page. Any PC-relative instructions are patched so they work at the new address:

| Instruction | What happens |
|---|---|
| `JMP rel32` (E9) | Offset recalculated for trampoline position |
| `CALL rel32` (E8) | Same |
| `Jcc rel8` (7x) | Widened to near form (0F 8x + rel32) if needed |
| `Jcc rel32` (0F 8x) | Offset recalculated |
| `[RIP + disp32]` | Displacement patched to same absolute address |
| Everything else | Copied verbatim |

If a branch targets another stolen instruction, the relative offset is preserved — no fixup needed.

A `JMP` back to `target + stolen_size` is appended to the end of the trampoline. This is the `original` function pointer returned to you.

### 3. Patch the target

`mprotect` makes the target page writable. A 5-byte `JMP rel32` is written at the start, redirecting execution to your replacement function. Any stolen bytes beyond the first 5 are NOP-filled. The page is then made executable again.

### 4. On unhook

The saved original bytes are written back. The trampoline buffer is `munmap`'d. The function returns to stock behavior.

## Architecture

```
include/cathook.h          Public API — two functions

src/
├── cathook_internal.h     Internal types and error codes
├── cathook.c              Core engine — hook/unhook, linked-list state
├── disasm_x64.c           x86_64 instruction length decoder (660+ lines)
├── trampoline.c           Trampoline builder — byte relocation, branch fixup
└── memory.c               mmap / mprotect primitives
```

### disasm_x64.c

The only complex part. A full x86_64 length decoder that understands:

- **Legacy prefixes** — LOCK, REP/REPNE, segment overrides, operand size (0x66), address size (0x67)
- **REX prefix** — handles W/R/X/B bits for 64-bit operand sizing and extended registers
- **VEX 2-byte / 3-byte** — AVX with inverted R/X/B, map select (0F, 0F38, 0F3A)
- **EVEX 4-byte** — AVX-512
- **XOP 3-byte** — AMD extension
- **ModR/M + SIB** — RIP-relative addressing detection, displacement sizing, base/index/scale decoding
- **Immediate fields** — 8/16/32/64-bit sizing based on opcode tables, prefixes, and REX.W

Two public functions:

- `ch_disasm_len(code, max)` — byte length of one instruction, 0 on decode failure
- `ch_disasm_stolen(code, max, min)` — walks instructions until ≥ `min` bytes covered

No dependency on capstone, udis86, Zydis, or any other disassembly library.

## API

```c
#include "cathook.h"

// Install a hook
//   target      — address of the function to hook
//   replacement — your replacement function (must have same signature)
//   original    — receives a trampoline you can call to invoke the real function
// Returns 0 on success, negative error code on failure
int ch_hook(void *target, void *replacement, void **original);

// Remove a hook
//   target — address of the previously hooked function
// Returns 0 on success
int ch_unhook(void *target);
```

### Error codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | Memory allocation failed |
| -2 | mprotect failed |
| -3 | Disassembly error (couldn't find enough stolen bytes) |
| -5 | Function already hooked |
| -7 | Function not currently hooked |

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

Produces `libcathook.a` and `test/test_cathook`. The library has no dependencies beyond libc and targets C11.

Link against it:

```cmake
target_link_libraries(your_target PRIVATE cathook)
target_include_directories(your_target PRIVATE path/to/cathook/include)
```

## Usage

### Hook a function by name

```c
#include "cathook.h"
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int add_hook(int a, int b) {
    printf("hooked: %d + %d\n", a, b);
    return 0;
}

int main() {
    void *original = NULL;
    ch_hook((void *)add, (void *)add_hook, &original);

    add(3, 5);                              // → "hooked: 3 + 5", returns 0

    int (*real_add)(int, int) = original;
    real_add(3, 5);                         // → returns 8

    ch_unhook((void *)add);
    add(3, 5);                              // → returns 8 (back to normal)
}
```

### Hook a function by address

```c
#include <dlfcn.h>
#include "cathook.h"

void *addr = dlsym(RTLD_DEFAULT, "strlen");
void *original = NULL;
ch_hook(addr, (void *)my_strlen, &original);
ch_unhook(addr);
```

### Hook a static function in a stripped binary

```c
void *addr = (void *)(base_address + 0x12a0);
void *orig = NULL;
ch_hook(addr, replacement, &orig);
```

## Testing

```bash
cd build && ./test/test_cathook
```

Tests cover:

| Test | What it verifies |
|------|-----------------|
| Basic hook | Interception works, original called through trampoline |
| Trampoline | Original function pointer behaves correctly |
| Unhook | Restored function works exactly as before |
| Double hook | Duplicate hooks are rejected safely |
| Leaf function | Functions with no stack frame hook correctly |
| strlen | Hooking a libc function and restoring it |
| Stress rehook | 100 hook/unhook cycles, no memory leaks |
| Branchy function | Functions containing conditional jumps in their prologue |

## Limitations

- **x86_64 Linux only.** The disassembler and calling conventions are architecture-specific.
- **Relative offset range.** The `JMP rel32` patch (±2 GB) must reach from the target to the replacement. For anything farther, the hook will fail to install. TODO: add support for higher range.
- **Not thread-safe** during hook install/uninstall. Pause threads or single-thread before hooking.
- **Stolen bytes must decode cleanly.** The length disassembler handles nearly all x86_64 encodings, but exotic or undocumented opcodes will be treated as 1-byte instructions as a fallback.

## License

MIT
