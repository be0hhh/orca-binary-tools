# Binary & Assembly Tools for Orca

[![Release](https://img.shields.io/github/v/release/be0hhh/orca-binary-tools?color=blue&label=release)](https://github.com/be0hhh/orca-binary-tools/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Orca Plugin](https://img.shields.io/badge/Orca-Plugin-orange.svg)](https://onorca.dev/)

<p align="center">
  <img src="assets/cover.jpg" alt="Binary & Assembly Tools Cover" width="100%">
</p>

An extension for [Orca](https://useorca.com/) providing low-level binary inspection and syntax highlighting for Assembly languages.

---

## Features

### 1. Interactive Binary Inspector
Visual custom editor for object files, static archives, shared libraries, and executables:
- **Supported extensions**: `.o`, `.obj`, `.a`, `.lib`, `.so`, `.dylib`, `.dll`, `.exe`, `.bin`, `.elf`, `.out`
- **Virtualized Hex View**: Smooth 60fps scrolling, byte color grouping (null, printable ASCII, control chars, high bytes), synchronized byte-to-ASCII highlight.
- **Structure & Headers Tab**: Parses 32-bit & 64-bit ELF headers and section tables, PE/COFF sections, and AR headers. Click any section (`.text`, `.rodata`, `.data`) to jump directly to its offset in the hex view.
- **Archive Members Tab**: Complete archive viewer for static libraries (`.a`, `.lib`). Inspect individual `.o` object files directly or view in hex. Shows deterministic build timestamps cleanly with navigation back to the archive.
- **Strings Extractor**: Extract ASCII/UTF-8 strings (length ≥ 4) with search filtering and direct offset jumping.
- **Interactive Data Inspector**: Collapsible side panel showing 8-bit, 16-bit, 32-bit, 64-bit integers (Little & Big Endian), Float32, Float64, binary bitfield, and ASCII representation for any selected byte.
- **Large File Support**: Handles large binaries smoothly via chunked streaming and responsive virtualized scrolling.

### 2. Assembly Syntax Highlighting
- **x86 & x86_64** (`.asm`, `.inc`): Intel and AT&T syntax, registers (`rax`, `r15`, `ymm0`, `zmm0`), instructions (AVX-512, SSE, VMX, AMX), NASM/FASM directives.
- **ARM & AArch64** (`.arm`, `.a64`): 32-bit ARM and 64-bit AArch64 instructions, NEON vectors (`v0.4s`), condition codes, shift operands.
- **GAS / AT&T** (`.s`): GNU Assembler directives (`.globl`, `.section`, `.cfi_*`), labels, AT&T operands (`%rax`, `(%rdi,%rsi,4)`).

---

## Installation

### Method 1: In Orca Settings (Recommended)
1. Open Orca and go to **Settings** (`Ctrl+,`) → **Plugins**.
2. Click **Add Plugin** / **Install from Git URL**.
3. Paste the repository URL:
   ```
   https://github.com/be0hhh/orca-binary-tools
   ```
4. Click **Install**, then click **Review** → **Approve** when prompted.

### Method 2: Manual Clone
Clone directly into your Orca plugins directory:
```sh
# Linux / macOS
git clone https://github.com/be0hhh/orca-binary-tools.git ~/.orca/plugins/be0hhh.binary-tools

# Windows
git clone https://github.com/be0hhh/orca-binary-tools.git "%APPDATA%\orca\plugins\be0hhh.binary-tools"
```

---

## License

MIT © [be0hhh](https://github.com/be0hhh)
