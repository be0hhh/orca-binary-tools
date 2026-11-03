# Binary & Assembly Tools for Orca

An extension for [Orca](https://useorca.com/) providing low-level binary inspection and syntax highlighting for Assembly languages.

## Features

- **Interactive Binary Inspector**
  - Custom visual editor for object files, static libraries, shared libraries, and executables (`.o`, `.obj`, `.a`, `.lib`, `.so`, `.dylib`, `.dll`, `.exe`, `.bin`, `.elf`, `.out`).
  - **Virtualized Hex View**: Smooth 60fps scrolling, byte color grouping (null, printable ASCII, control chars, high bytes), synchronized byte-to-ASCII highlight.
  - **Structure & Headers Tab**: Parses 32-bit & 64-bit ELF headers and section tables, PE/COFF sections, and AR headers. Click any section to jump directly to its offset in hex view.
  - **Archive Members Tab**: Complete archive viewer for static libraries (`.a`, `.lib`). Inspect individual `.o` object files directly or view in hex. Clean deterministic build timestamps.
  - **Strings Extractor**: Extract ASCII/UTF-8 strings (length >= 4) with search filtering and direct offset jumping.
  - **Interactive Data Inspector**: Side panel showing 8-bit, 16-bit, 32-bit, 64-bit integers (Little & Big Endian), Float32, Float64, binary bitfield, and ASCII representation for any selected byte.
  - **Large File Support**: Handles files over 50 MB smoothly via chunked streaming.

- **Assembly Syntax Highlighting**
  - **x86 & x86_64** (`.asm`, `.inc`): Intel and AT&T syntax, registers (`rax`, `r15`, `ymm0`, `zmm0`), instructions (AVX-512, SSE, VMX, AMX), NASM/FASM directives.
  - **ARM & AArch64** (`.arm`, `.a64`): 32-bit ARM and 64-bit AArch64 instructions, NEON vectors (`v0.4s`), condition codes, shift operands.
  - **GAS / AT&T** (`.s`): GNU Assembler directives (`.globl`, `.section`, `.cfi_*`), labels, AT&T operands (`%rax`, `(%rdi,%rsi,4)`).

## Installation

Install directly in Orca or clone into Orca's plugins directory:

```sh
# Windows WSL / Local path
git clone https://github.com/be0hhh/orca-binary-tools.git ~/.orca/plugins/be0hhh.binary-tools
```

## License

MIT © [be0hhh](https://github.com/be0hhh)
