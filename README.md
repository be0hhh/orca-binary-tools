# Assembly & Binary Tools for Orca

[![Orca Plugin](https://img.shields.io/badge/Orca-Plugin-blue.svg)](https://onorca.dev/plugins)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Native & low-level development toolkit for [Orca](https://github.com/stablyai/orca) — assembly syntax highlighting, C++ inline/template implementations (`.ipp`, `.inl`, `.tpp`), and interactive binary inspection.

If you work with compiled code, embedded systems, firmware, reverse engineering, kernel/OS development, game engines, or C++ template libraries — this plugin makes Orca your dedicated low-level workbench.

---

## Features

### 🔧 1. Assembly & Native Syntax Highlighting

Full syntax highlighting for native development files with support for multiple architectures and languages:

| Language | Extensions | Flavors & Coverage |
|----------|------------|-------------------|
| **x86 / x86-64 Assembly** | `.asm` | Intel & AT&T syntax, NASM & GAS directives, x86-64 registers (`rax`, `r8`-`r15`), SIMD (`xmm`, `ymm`, `zmm`), SSE/AVX |
| **ARM / AArch64 Assembly** | *(selectable)* | ARM32 (A32/T32), AArch64 (A64), NEON/VFP registers (`x0`-`x30`, `w0`-`w30`, `v0`-`v31`), Thumb directives |
| **Generic GAS Assembly** | `.s`, `.S` | GNU Assembler compatible, C preprocessor directives (`#include`, `#define`, `#ifdef`), all targets |
| **C++ Inlines & Templates** | `.ipp`, `.inl`, `.tpp` | Modern C++20 / C++23 templates, `concept`, `requires`, `constexpr`, `inline`, STL types, lambdas, raw strings |

**What gets highlighted in Assembly:**
- ✅ **Instructions**: Data movement (`mov`, `lea`, `push`, `pop`), arithmetic (`add`, `sub`, `imul`), logic (`and`, `or`, `xor`), branches (`jmp`, `call`, `ret`, `je`, `jne`), SIMD (`movaps`, `pxor`), system calls (`syscall`, `int`, `svc`)
- ✅ **Registers**: General purpose, 64-bit, 32-bit, 16/8-bit, segment, control (`cr0`-`cr8`), debug, and SIMD
- ✅ **Directives**: `.text`, `.data`, `.rodata`, `.bss`, `.section`, `.global`, `.type`, `.size`, `section`, `db`, `dw`, `dd`, `dq`, `times`
- ✅ **Numeric Literals**: Hex (`0x1A`, `0FFh`), binary (`0b1010`, `1010b`), octal, and decimal
- ✅ **Labels & Functions**: Global labels, local labels (`.loop:`, `.L0:`), and numeric labels (`1:`)
- ✅ **Strings & Characters**: Single and double-quoted strings with escape sequences
- ✅ **Comments**: Semicolon (`;`), hash (`#`), double slash (`//`), at sign (`@`), and block comments (`/* ... */`)
- ✅ **Preprocessors**: NASM macros (`%macro`, `%define`, `%ifdef`) and C preprocessor (`#include`, `#define`)

**What gets highlighted in C++ Inlines (`.ipp` / `.inl` / `.tpp`):**
- ✅ **Templates & Concepts**: `template`, `typename`, `concept`, `requires`
- ✅ **Modifiers**: `inline`, `constexpr`, `consteval`, `constinit`, `explicit`, `virtual`, `override`, `noexcept`
- ✅ **Keywords & Types**: `class`, `struct`, `auto`, `decltype`, standard fixed-width types (`uint32_t`, `size_t`), STL containers
- ✅ **Raw Strings & Escapes**: `R"(...)"`, string escapes, binary/hex numbers with digit separators (`0x10'00ULL`)

---

### 🔍 2. Interactive Binary Inspector & Hex Viewer

Open compiled object files (`.o`), static libraries (`.a`), and binaries (`.bin`, `.elf`, `.so`) directly in Orca with a high-performance visual inspector:

- ⚡ **Virtualized Hex Dump**: Fast 60 FPS scrolling even for large binaries.
- 🎨 **Semantic Byte Coloring**:
  - `0x00` (Null bytes): Dimmed gray to quickly spot alignment and padding
  - `0x20`–`0x7E` (Printable ASCII): Sky blue for fast string identification
  - `0x01`–`0x1F` (Control characters): Warm amber
  - `0x80`–`0xFF` (High bytes): Purple
- 📑 **ELF Parser**:
  - Automatically identifies ELF32 / ELF64, Little / Big Endian, target ISA (x86-64, ARM, AArch64, RISC-V, MIPS)
  - Full **Section Headers Table**: `.text`, `.data`, `.bss`, `.rodata`, `.symtab`, `.rela.*` with offsets, sizes, and flags
  - **One-click Navigation**: Click "View Hex" on any section to jump directly to its byte offset in the hex view!
- 🏷️ **Symbol Table Browser**:
  - Lists functions (`FUNC`), objects (`OBJECT`), sections, and symbols with instant search/filter
  - Jump to symbol definitions with a single click
- 📦 **AR Archive Explorer**:
  - Browse members inside `.a` static libraries
  - Inspect individual object members without extracting the archive to disk
- 🔬 **Data Inspector Panel**:
  - Click any byte to inspect its interpretation as 8-bit, 16-bit, 32-bit, 64-bit integers (Little & Big Endian), float32, float64, binary bitmask, and ASCII
- 🔎 **Pattern Search**:
  - Search both hex sequences (e.g. `7F 45 4C`) and ASCII strings (e.g. `main`) with match counts and next/previous jumping

---

## Supported File Types

| Extension | Category | Editor Mode |
|-----------|----------|-------------|
| `.asm` | Assembly source | Syntax Highlighting (Intel x86 default) |
| `.s` | Assembly source | Syntax Highlighting (GAS generic default) |
| `.S` | Assembly with C Preprocessor | Syntax Highlighting (GAS + Preprocessor) |
| `.ipp` | C++ inline / template implementation | Syntax Highlighting (Modern C++20/23) |
| `.inl` | C++ inline definitions (GameDev/Unreal) | Syntax Highlighting (Modern C++20/23) |
| `.tpp` | C++ template implementations | Syntax Highlighting (Modern C++20/23) |
| `.o` | Object file | Binary Inspector (Hex + ELF) |
| `.a` | Static library archive | Binary Inspector (Hex + AR) |
| `.elf`, `.bin`, `.so` | Executables / Shared libraries | Binary Inspector (Hex + ELF) |

---

## Installation

### Method A: From Orca Settings (when published)
1. Open Orca → Settings → Plugins
2. Search for `Assembly & Binary Tools`
3. Click Install

### Method B: Manual / Local Installation
Clone or copy this directory into your Orca plugins folder:
```sh
# Example local installation
cp -r plugins/lowlevel-tools ~/.config/orca/plugins/
```

---

## Quick Testing

Sample files are included in `samples/`:
- `samples/math_vector.ipp` — C++ inline/template methods test
- `samples/hello_x86_intel.asm` — Intel syntax x86-64 test
- `samples/hello_x86_att.s` — AT&T syntax GAS test
- `samples/hello_arm.s` — AArch64 test
- `samples/sample.o` — Real ELF64 object file
- `samples/sample.a` — Real AR static archive containing `sample.o`

---

## Publishing to Orca Community Catalog

This plugin is ready to be published as an official or community plugin:

1. Create a GitHub repository named `orca-lowlevel-tools` under your account (e.g. `be0h/orca-lowlevel-tools`).
2. Push this plugin code to the repository.
3. Add the GitHub repository topic: `orca-plugin`.
4. Create a release tag, e.g. `v0.3.0`.
5. The plugin will be automatically discovered and listed on [onorca.dev/plugins](https://www.onorca.dev/plugins)!

---

## Contributing

Contributions are welcome!
- 🏗️ Support for additional ISAs: RISC-V, MIPS, WebAssembly bytecode
- 🔬 Binary formats: PE/COFF (`.obj`, `.exe`, `.dll`) and Mach-O (`.dylib`, `.o`)
- 🎨 TextMate grammar refinements

## License

[MIT](LICENSE) © 2026 be0h
