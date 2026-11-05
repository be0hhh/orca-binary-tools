import { pagedSource, cancelled, SCAN_BYTES } from "./byte-source.mjs";
/* Binary analysis without DOM or host dependencies. Invalid metadata never hides bytes. */
const MAX_ITEMS = 100000;
const MAX_TEXT_BYTES = 8 * 1024 * 1024;
const MAX_NAME_BYTES = 4096;
function analysisLimit(message) {
  const error = new Error(
    `Analysis limited: ${message}; hex remains available.`,
  );
  error.code = "ANALYSIS_LIMIT";
  throw error;
}
const hex = (n) => `0x${BigInt(n).toString(16).toUpperCase()}`;
const decoder = new TextDecoder("utf-8");
export class Reader {
  constructor(source, { signal } = {}) {
    this.source = pagedSource(source);
    this.byteLength = this.source.byteLength;
    this.signal = signal;
    this.le = true;
    this.records = 0;
    this.textBytes = 0;
    this.outputBytes = 0;
    this.names = new Map();
  }
  output(text) {
    this.outputBytes += text.length * 2;
    if (this.outputBytes > MAX_TEXT_BYTES) analysisLimit("expanded text budget exceeded");
    return text;
  }
  async record() {
    if (++this.records > MAX_ITEMS) analysisLimit("record budget exceeded");
    if ((this.records & 255) === 0) { await pause(); this.check(); }
  }
  check() { cancelled(this.signal); this.source.check?.(this.signal); }
  textBudget(n) {
    this.textBytes += n;
    if (this.textBytes > MAX_TEXT_BYTES) analysisLimit("text budget exceeded");
  }
  has(o, n) {
    return Number.isSafeInteger(o) && Number.isSafeInteger(n) && o >= 0 && n >= 0 && o <= this.byteLength && n <= this.byteLength - o;
  }
  need(o, n) {
    this.check();
    if (!this.has(o, n)) throw new Error(`Truncated or invalid range at ${Number.isFinite(o) ? hex(o) : "?"}`);
  }
  async read(o, n) {
    try {
      const bytes = await this.source.read(o, n, { signal: this.signal });
      this.check(); return bytes;
    } catch (error) {
      if (error.code === "FILE_CHANGED" || error.name === "AbortError") throw error;
      throw Object.assign(new Error(error.message), { code: "SOURCE_READ", cause: error });
    }
  }
  async view(o, n) {
    this.need(o, n);
    const b = await this.read(o, n);
    return new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  async u8(o) { return (await this.view(o, 1)).getUint8(0); }
  async u16(o) { return (await this.view(o, 2)).getUint16(0, this.le); }
  async u32(o) { return (await this.view(o, 4)).getUint32(0, this.le); }
  async i16(o) { return (await this.view(o, 2)).getInt16(0, this.le); }
  async u64(o) { return (await this.view(o, 8)).getBigUint64(0, this.le); }
  async num64(o) {
    const n = await this.u64(o);
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("File offset or size exceeds safe integer range");
    return Number(n);
  }
  async text(o, n) {
    this.need(o, n); this.textBudget(n);
    return decoder.decode(await this.read(o, n));
  }
  async z(o, end = this.byteLength, newline = false) {
    this.need(o, 0); end = Math.min(end, this.byteLength);
    const key = `${o}:${end}:${newline}`;
    if (this.names.has(key)) return this.names.get(key);
    const bytes = await this.read(o, Math.min(end - o, MAX_NAME_BYTES + 1));
    this.check();
    let p = 0;
    while (p < bytes.length && bytes[p] && (!newline || bytes[p] !== 10)) p++;
    if (p > MAX_NAME_BYTES) analysisLimit("individual name exceeds 4096 bytes");
    this.textBudget(p);
    const name = decoder.decode(bytes.subarray(0, p)); this.names.set(key, name); return name;
  }
}
const architecture = (n) =>
  ({
    3: "x86",
    62: "x86-64",
    40: "ARM",
    183: "AArch64",
    243: "RISC-V",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    0x14c: "x86",
    0x8664: "x86-64",
    0x1c0: "ARM",
    0x1c4: "ARM",
    0xaa64: "AArch64",
  })[n] || `Machine ${hex(n)}`;
function warn(out, message) {
  if (out.warnings.length < 100) out.warnings.push(message);
}
async function bounded(out, work) {
  try {
    return await work();
  } catch (e) {
    if (e.code === "ANALYSIS_LIMIT" || e.code === "SOURCE_READ" || e.code === "FILE_CHANGED" || e.name === "AbortError") throw e;
    warn(out, e.message);
    return null;
  }
}
function fileRange(r, out, offset, size, name) {
  if (!r.has(offset, size)) {
    warn(out, `${name}: file range is outside the input`);
    return null;
  }
  return offset;
}
function table(r, offset, count, stride, min) {
  if (count > MAX_ITEMS) analysisLimit("table record count exceeded");
  if (stride < min || !r.has(offset, count * stride))
    throw new Error("Invalid or truncated table");
}

export async function parseBinary(input, options = {}) {
  const source = pagedSource(input);
  const out = {
    format: "RAW",
    architecture: "Unknown",
    bits: null,
    endian: null,
    sections: [],
    symbols: [],
    members: [],
    fileSize: source.byteLength,
    memorySize: null,
    warnings: [],
  };
  const r = new Reader(source, options);
  await source.read(0, Math.min(64, source.byteLength), { signal: options.signal });
  r.check();
  try {
    await (async () => {
      if (source.byteLength >= 4 && (await r.u8(0)) === 0x7f && (await r.text(1, 3)) === "ELF") {
        out.format = "ELF";
        (await parseELF(r, out));
      } else if (
        source.byteLength >= 8 &&
        ((await r.text(0, 8)) === "!<arch>\n" || (await r.text(0, 8)) === "!<thin>\n")
      ) {
        out.format = "AR";
        (await parseAR(r, out));
      } else if (source.byteLength >= 2 && (await r.text(0, 2)) === "MZ") {
        out.format = "PE";
        (await parsePE(r, out));
      } else if (
        source.byteLength >= 4 &&
        [
          0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe,
          0xbebafeca, 0xcafebabf, 0xbfbafeca,
        ].includes((await r.u32(0)))
      ) {
        out.format = "Mach-O";
        warn(
          out,
          "Mach-O structure analysis is not supported; hex and strings remain available.",
        );
      } else if (
        source.byteLength >= 2 &&
        [0x14c, 0x8664, 0x1c0, 0x1c2, 0x1c4, 0xaa64, 0x5032, 0x5064].includes(
          (await r.u16(0)),
        )
      ) {
        out.format = "COFF";
        (await parseCOFF(r, out, 0, false));
      }
    })();
  } catch (e) {
    if (e.code === "SOURCE_READ" || e.code === "FILE_CHANGED" || e.name === "AbortError") throw e;
    warn(out, e.message);
  }
  r.check();
  return out;
}
function pushSymbol(out, r, symbol) {
  for (const [key, value] of Object.entries(symbol))
    if (key !== "name" && typeof value === "string") r.output(value);
  out.symbols.push(symbol);
}
async function parseELF(r, out) {
  const klass = (await r.u8(4)),
    encoding = (await r.u8(5));
  if (![1, 2].includes(klass) || ![1, 2].includes(encoding))
    throw new Error("Invalid ELF class or byte order");
  const wide = klass === 2;
  r.le = encoding === 1;
  out.bits = wide ? 64 : 32;
  out.endian = r.le ? "LE" : "BE";
  r.need(0, wide ? 64 : 52);
  out.architecture = architecture((await r.u16(18)));
  const elfType = (await r.u16(16));
  const u = async (o) => (wide ? (await r.num64(o)) : (await r.u32(o))),
    addr = async (o) => hex(wide ? (await r.u64(o)) : (await r.u32(o)));
  const phoff = (await u(wide ? 32 : 28)),
    shoff = (await u(wide ? 40 : 32)),
    phstride = (await r.u16(wide ? 54 : 42)),
    shstride = (await r.u16(wide ? 58 : 46));
  let phnum = (await r.u16(wide ? 56 : 44)),
    shnum = (await r.u16(wide ? 60 : 48)),
    names = (await r.u16(wide ? 62 : 50));
  if (shoff && (shnum === 0 || names === 0xffff || phnum === 0xffff))
    (await bounded(out, async () => {
      r.need(shoff, wide ? 64 : 40);
      if (shnum === 0) shnum = (await u(shoff + (wide ? 32 : 20)));
      if (names === 0xffff) names = (await r.u32(shoff + (wide ? 40 : 24)));
      if (phnum === 0xffff) phnum = (await r.u32(shoff + (wide ? 44 : 28)));
    }));
  const headers = [];
  if (shoff && shnum)
    (await bounded(out, async () => {
      table(r, shoff, shnum, shstride, wide ? 64 : 40);
      for (let i = 0; i < shnum; i++) {
        (await r.record());
        const p = shoff + i * shstride;
        headers.push({
          nameIndex: (await r.u32(p)),
          type: (await r.u32(p + 4)),
          flags: wide ? (await r.u64(p + 8)) : BigInt((await r.u32(p + 8))),
          address: (await addr(p + (wide ? 16 : 12))),
          offset: (await u(p + (wide ? 24 : 16))),
          size: (await u(p + (wide ? 32 : 20))),
          link: (await r.u32(p + (wide ? 40 : 24))),
          entrySize: (await u(p + (wide ? 56 : 36))),
        });
      }
      const namesHeader = headers[names];
      const namesEnd =
        namesHeader && r.has(namesHeader.offset, namesHeader.size)
          ? namesHeader.offset + namesHeader.size
          : 0;
      for (let i = 0; i < headers.length; i++) {
        (await r.record());
        const h = headers[i];
        let name = `[section ${i}]`;
        if (namesEnd && h.nameIndex < namesHeader.size)
          name = (await r.z(namesHeader.offset + h.nameIndex, namesEnd)) || name;
        h.name = name;
        const hasBytes = h.type !== 8 && h.type !== 0;
        out.sections.push({
          index: i,
          name: r.output(name),
          type:
            {
              0: "NULL",
              1: "PROGBITS",
              2: "SYMTAB",
              3: "STRTAB",
              4: "RELA",
              8: "NOBITS",
              9: "REL",
              11: "DYNSYM",
            }[h.type] || String(h.type),
          offset: hasBytes ? fileRange(r, out, h.offset, h.size, name) : null,
          fileSize: hasBytes ? h.size : 0,
          memorySize: h.flags & 2n ? h.size : 0,
          address: h.address,
          flags: [
            h.flags & 1n ? "W" : "",
            h.flags & 2n ? "A" : "",
            h.flags & 4n ? "X" : "",
          ].join(""),
        });
      }
    }));
  if (phoff && phnum)
    (await bounded(out, async () => {
      table(r, phoff, phnum, phstride, wide ? 56 : 32);
      const ranges = [];
      for (let i = 0; i < phnum; i++) {
        (await r.record());
        const p = phoff + i * phstride;
        if ((await r.u32(p)) !== 1) continue;
        const start = wide ? (await r.u64(p + 16)) : BigInt((await r.u32(p + 8))),
          length = wide ? (await r.u64(p + 40)) : BigInt((await r.u32(p + 20)));
        const fileOffset = (await u(p + (wide ? 8 : 4))),
          fileSize = (await u(p + (wide ? 32 : 16)));
        fileRange(r, out, fileOffset, fileSize, "PT_LOAD");
        if (BigInt(fileSize) > length)
          warn(out, "PT_LOAD file size exceeds memory size");
        ranges.push([start, start + length]);
      }
      ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      let memory = 0n,
        end = 0n;
      for (const [start, finish] of ranges) {
        if (finish > end) {
          memory += finish - (start > end ? start : end);
          end = finish;
        }
      }
      if (
        elfType !== 1 &&
        ranges.length &&
        memory <= BigInt(Number.MAX_SAFE_INTEGER)
      )
        out.memorySize = Number(memory);
      else if (memory > BigInt(Number.MAX_SAFE_INTEGER))
        warn(out, "ELF memory total exceeds safe integer range");
    }));
  for (const h of headers)
    if (h.type === 2 || h.type === 11)
      (await bounded(out, async () => {
        (await r.record());
        const strings = headers[h.link];
        if (!strings || !r.has(strings.offset, strings.size))
          throw new Error(`${h.name}: invalid symbol string table`);
        const stride = h.entrySize;
        if (!stride || h.size % stride)
          throw new Error(`${h.name}: invalid symbol entry size`);
        table(r, h.offset, h.size / stride, stride, wide ? 24 : 16);
        for (let p = h.offset; p < h.offset + h.size; p += stride) {
          (await r.record());
          const ni = (await r.u32(p)),
            info = (await r.u8(p + (wide ? 4 : 12))),
            si = (await r.u16(p + (wide ? 6 : 14)));
          if (!ni || ni >= strings.size) continue;
          const name = (await r.z(strings.offset + ni, strings.offset + strings.size));
          if (!name) continue;
          const value = wide ? (await r.u64(p + 8)) : BigInt((await r.u32(p + 4))),
            section = out.sections[si];
          let offset = null;
          if (section?.offset !== null && section && si !== 0 && si < 0xff00) {
            const delta =
              elfType === 1 ? value : value - BigInt(section.address);
            if (delta >= 0n && delta < BigInt(section.fileSize))
              offset = section.offset + Number(delta);
          }
          pushSymbol(out, r, {
            name: r.output(name),
            address: si === 0 ? null : (await addr(p + (wide ? 8 : 4))),
            offset,
            binding:
              { 0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE" }[
                info >> 4
              ] || String(info >> 4),
            visibility: {
              0: "DEFAULT",
              1: "INTERNAL",
              2: "HIDDEN",
              3: "PROTECTED",
            }[(await r.u8(p + (wide ? 5 : 13))) & 3],
            size: (await u(p + (wide ? 16 : 8))),
            section:
              { 0: "UND", 0xfff1: "ABS", 0xfff2: "COMMON" }[si] ||
              headers[si]?.name ||
              String(si),
            kind:
              {
                0: "NOTYPE",
                1: "OBJECT",
                2: "FUNC",
                3: "SECTION",
                4: "FILE",
                6: "TLS",
                10: "IFUNC",
              }[info & 15] || String(info & 15),
            source: h.type === 11 ? ".dynsym" : ".symtab",
          });
        }
      }));
}
async function parseAR(r, out) {
  if ((await r.text(0, 8)) === "!<thin>\n") {
    warn(
      out,
      "Thin archives reference external files; member inspection is not supported.",
    );
    return;
  }
  let p = 8,
    longNames = null,
    count = 0;
  while (p < r.byteLength) {
    (await r.record());
    if (++count > MAX_ITEMS) throw new Error("Archive member limit exceeded");
    r.need(p, 60);
    if ((await r.text(p + 58, 2)) !== "`\n")
      throw new Error(`Invalid archive member header at ${hex(p)}`);
    let name = (await r.text(p, 16)).trim();
    const sizeText = (await r.text(p + 48, 10)).trim(),
      dateText = (await r.text(p + 16, 12)).trim();
    if (!/^\d+$/.test(sizeText))
      throw new Error(`Invalid archive member size at ${hex(p)}`);
    const storedSize = Number(sizeText);
    let offset = p + 60,
      size = storedSize;
    r.need(offset, size);
    const service =
      name === "/" ||
      name === "//" ||
      name === "/SYM64/" ||
      name.startsWith("__.SYMDEF");
    if (name === "//") longNames = { offset, size };
    else if (/^\/\d+$/.test(name)) {
      const ni = Number(name.slice(1));
      if (longNames && ni < longNames.size) {
        name = (await r
          .z(longNames.offset + ni, longNames.offset + longNames.size, true))
          .replace(/\/$/, "");
      } else warn(out, "Archive long-name reference has no valid string table");
    } else if (name.startsWith("#1/")) {
      const text = name.slice(3);
      if (!/^\d+$/.test(text) || Number(text) > size)
        throw new Error("Invalid BSD archive filename length");
      const n = Number(text);
      if (n > MAX_NAME_BYTES) analysisLimit("individual name exceeds 4096 bytes");
      name = (await r.text(offset, n)).replace(/\0+$/, "");
      offset += n;
      size -= n;
    } else if (name.endsWith("/") && !service) name = name.slice(0, -1);
    out.members.push({
      name: r.output(name),
      offset,
      size,
      service: service || name.startsWith("__.SYMDEF"),
      date: /^\d+$/.test(dateText) ? Number(dateText) : null,
    });
    p += 60 + storedSize;
    if (p % 2) p++;
  }
}
async function coffSections(r, out, p, count) {
  table(r, p, count, 40, 40);
  const sections = [];
  for (let i = 0; i < count; i++) {
    (await r.record());
    const q = p + i * 40,
      name = (await r.z(q, q + 8)),
      virtualSize = (await r.u32(q + 8)),
      address = (await r.u32(q + 12)),
      size = (await r.u32(q + 16)),
      offset = (await r.u32(q + 20)),
      flags = (await r.u32(q + 36));
    const bss = !!(flags & 0x80) && !offset;
    const s = {
      index: i + 1,
      name,
      type: bss ? "BSS" : "SECTION",
      offset: bss ? null : fileRange(r, out, offset, size, name),
      fileSize: bss ? 0 : size,
      memorySize: virtualSize || size,
      address: hex(address),
      flags: [
        flags & 0x20000000 ? "X" : "",
        flags & 0x40000000 ? "R" : "",
        flags & 0x80000000 ? "W" : "",
      ].join(""),
    };
    r.output(s.name);
    out.sections.push(s);
    sections.push({ ...s, rva: address });
  }
  return sections;
}
async function parseCOFF(r, out, start = 0, pe = false) {
  r.need(start, 20);
  const machine = (await r.u16(start)),
    count = (await r.u16(start + 2)),
    symbolsOffset = (await r.u32(start + 8)),
    symbolCount = (await r.u32(start + 12)),
    optionalSize = (await r.u16(start + 16));
  out.architecture = architecture(machine);
  out.bits = [0x8664, 0xaa64, 0x5064].includes(machine) ? 64 : 32;
  out.endian = "LE";
  const sections = (await coffSections(r, out, start + 20 + optionalSize, count));
  if (symbolCount || symbolsOffset)
    (await bounded(out, async () => {
      table(r, symbolsOffset, symbolCount, 18, 18);
      const stringsOffset = symbolsOffset + symbolCount * 18;
      r.need(stringsOffset, 4);
      const stringsSize = (await r.u32(stringsOffset));
      if (stringsSize < 4) throw new Error("Invalid COFF string table size");
      r.need(stringsOffset, stringsSize);
      const nameAt = async (p) => {
        if ((await r.u32(p)) === 0) {
          const ni = (await r.u32(p + 4));
          if (ni < 4 || ni >= stringsSize) {
            warn(out, "Invalid COFF symbol name offset");
            return "";
          }
          return (await r.z(stringsOffset + ni, stringsOffset + stringsSize));
        }
        return (await r.z(p, p + 8));
      };
      for (const s of out.sections)
        if (/^\/\d+$/.test(s.name)) {
          const ni = Number(s.name.slice(1));
          if (ni >= 4 && ni < stringsSize)
            s.name = (await r.z(stringsOffset + ni, stringsOffset + stringsSize));
        }
      for (let i = 0; i < symbolCount; ) {
        (await r.record());
        const p = symbolsOffset + i * 18,
          name = (await nameAt(p)),
          value = (await r.u32(p + 8)),
          section = (await r.i16(p + 12)),
          type = (await r.u16(p + 14)),
          storage = (await r.u8(p + 16)),
          aux = (await r.u8(p + 17));
        if (i + aux >= symbolCount)
          throw new Error("Truncated COFF auxiliary symbol records");
        const target = out.sections[section - 1],
          offset =
            target && target.offset !== null && value < target.fileSize
              ? target.offset + value
              : null;
        if (name)
          pushSymbol(out, r, {
            name: r.output(name),
            address: section === 0 ? null : hex(value),
            offset,
            binding: null,
            visibility: null,
            size: null,
            section:
              out.sections[section - 1]?.name ||
              { 0: "UND", "-1": "ABS", "-2": "DEBUG" }[section] ||
              String(section),
            kind:
              type & 0x20
                ? "FUNC"
                : section > 0 &&
                    [2, 3].includes(storage) &&
                    !(storage === 3 && aux && name === target?.name)
                  ? "OBJECT"
                  : storage === 2
                    ? "EXTERNAL"
                    : storage === 3
                      ? "STATIC"
                      : `CLASS ${storage}`,
            source: "COFF",
          });
        i += 1 + aux;
      }
    }));
  return sections;
}
async function parsePE(r, out) {
  r.need(0, 64);
  const p = (await r.u32(60));
  r.need(p, 24);
  if ((await r.text(p, 4)) !== "PE\0\0") throw new Error("Invalid PE signature");
  const opt = p + 24,
    optSize = (await r.u16(p + 20));
  r.need(opt, optSize);
  const magic = (await r.u16(opt)),
    wide = magic === 0x20b;
  if (magic !== 0x10b && !wide)
    throw new Error("Unsupported PE optional header");
  const minimum = wide ? 112 : 96;
  if (optSize < minimum) throw new Error("Truncated PE optional header");
  const sections = (await parseCOFF(r, out, p + 4, true));
  out.bits = wide ? 64 : 32;
  const base = wide ? (await r.u64(opt + 24)) : BigInt((await r.u32(opt + 28)));
  out.memorySize = (await r.u32(opt + 56));
  for (const s of out.sections)
    s.address = hex(base + BigInt(s.rva ?? parseInt(s.address.slice(2), 16)));
  for (const symbol of out.symbols) {
    const section = sections.find((s) => s.name === symbol.section);
    if (section && symbol.address !== null)
      symbol.address = hex(base + BigInt(section.rva) + BigInt(symbol.address));
  }
  const headersSize = (await r.u32(opt + 60)),
    directoryCount = (await r.u32(opt + (wide ? 108 : 92))),
    dir = opt + minimum;
  const resolve = (rva, n = 1) => {
    if (rva < headersSize && n <= headersSize - rva && r.has(rva, n))
      return rva;
    const s = sections.find(
      (s) => s.offset !== null && rva >= s.rva && rva - s.rva < s.fileSize,
    );
    if (!s || n > s.fileSize - (rva - s.rva))
      throw new Error(`PE RVA ${hex(rva)} has no file bytes`);
    const q = s.offset + rva - s.rva;
    r.need(q, n);
    return q;
  };
  const str = async (rva) => {
    const q = resolve(rva);
    const s = sections.find(
      (s) => s.offset !== null && q >= s.offset && q < s.offset + s.fileSize,
    );
    return (await r.z(
      q,
      s ? s.offset + s.fileSize : Math.min(headersSize, r.byteLength),
    ));
  };
  const directory = async (i) => {
    if (i >= directoryCount || (i + 1) * 8 > optSize - minimum) return null;
    const rva = (await r.u32(dir + i * 8)),
      size = (await r.u32(dir + i * 8 + 4));
    return rva && size ? { rva, size } : null;
  };
  const exp = (await directory(0));
  if (exp)
    (await bounded(out, async () => {
      const q = resolve(exp.rva, 40),
        ordinalBase = (await r.u32(q + 16)),
        funcCount = (await r.u32(q + 20)),
        nameCount = (await r.u32(q + 24));
      if (funcCount > MAX_ITEMS || nameCount > MAX_ITEMS)
        throw new Error("PE export count exceeds limit");
      const funcs = resolve((await r.u32(q + 28)), funcCount * 4),
        names = nameCount ? resolve((await r.u32(q + 32)), nameCount * 4) : 0,
        ordinals = nameCount ? resolve((await r.u32(q + 36)), nameCount * 2) : 0,
        named = new Map();
      for (let i = 0; i < nameCount; i++) {
        (await r.record());
        const ordinal = (await r.u16(ordinals + i * 2));
        if (ordinal >= funcCount) {
          warn(out, "Invalid PE export ordinal");
          continue;
        }
        named.set(ordinal, (await str((await r.u32(names + i * 4)))));
      }
      for (let i = 0; i < funcCount; i++) {
        (await r.record());
        const target = (await r.u32(funcs + i * 4));
        if (!target) continue;
        const forwarded = target >= exp.rva && target - exp.rva < exp.size;
        pushSymbol(out, r, {
          name: r.output(named.get(i) || `Ordinal ${ordinalBase + i}`),
          address: forwarded ? null : hex(base + BigInt(target)),
          offset: forwarded ? null : (await bounded(out, async () => resolve(target))),
          binding: null,
          visibility: null,
          size: null,
          section: null,
          kind: forwarded ? "export-forwarder" : "export",
          source: forwarded ? (await str(target)) : "PE exports",
        });
      }
    }));
  const imp = (await directory(1));
  if (imp)
    (await bounded(out, async () => {
      const count = Math.min(Math.floor(imp.size / 20), MAX_ITEMS);
      let terminated = false;
      for (let i = 0; i < count; i++) {
        (await r.record());
        const q = resolve(imp.rva + i * 20, 20),
          original = (await r.u32(q)),
          timestamp = (await r.u32(q + 4)),
          chain = (await r.u32(q + 8)),
          nameRva = (await r.u32(q + 12)),
          first = (await r.u32(q + 16));
        if (!original && !timestamp && !chain && !nameRva && !first) {
          terminated = true;
          break;
        }
        const dll = (await str(nameRva)),
          thunk = original || first,
          width = wide ? 8 : 4;
        let end = false;
        for (let j = 0; j < MAX_ITEMS; j++) {
          (await r.record());
          const t = resolve(thunk + j * width, width),
            value = wide ? (await r.u64(t)) : BigInt((await r.u32(t)));
          if (!value) {
            end = true;
            break;
          }
          const ordinalFlag = wide ? 0x8000000000000000n : 0x80000000n;
          const name =
            value & ordinalFlag
              ? `Ordinal ${value & 0xffffn}`
              : value <= 0xffffffffn
                ? (await str(Number(value) + 2))
                : null;
          if (name === null) throw new Error("Invalid PE import name RVA");
          pushSymbol(out, r, {
            name: r.output(name),
            address: null,
            offset: null,
            binding: null,
            visibility: null,
            size: null,
            section: null,
            kind: "import",
            source: dll,
          });
        }
        if (!end) warn(out, "PE import thunk limit exceeded");
      }
      if (!terminated)
        warn(out, "PE import descriptors lack a terminator within directory");
    }));
}

const pause = () => new Promise((resolve) => setTimeout(resolve, 0));
export function parseSearchPattern(query, mode = "hex") {
  if (mode === "text") return new TextEncoder().encode(query);
  const compact = query.replace(/\s+/g, "");
  if (!compact || compact.length % 2 || !/^[0-9a-f]+$/i.test(compact))
    throw new Error("Enter complete hexadecimal byte pairs");
  return Uint8Array.from(compact.match(/../g), (s) => parseInt(s, 16));
}
export async function searchBytes(input, query, { mode = "hex", signal, maxMatches = 100000 } = {}) {
  const source = pagedSource(input), pattern = parseSearchPattern(query, mode), matches = [];
  const check = () => { cancelled(signal); source.check?.(signal); };
  check();
  if (!pattern.length) return matches;
  if (pattern.length > MAX_TEXT_BYTES) throw new Error("Search pattern exceeds 8 MiB");
  const prefix = new Uint32Array(pattern.length);
  for (let i = 1, j = 0; i < pattern.length; i++) {
    while (j && pattern[i] !== pattern[j]) j = prefix[j - 1];
    if (pattern[i] === pattern[j]) j++;
    prefix[i] = j;
    if ((i & 0x3ffff) === 0) { await pause(); check(); }
  }
  let j = 0;
  for (let offset = 0; offset < source.byteLength; offset += SCAN_BYTES) {
    check();
    const bytes = await source.read(offset, Math.min(SCAN_BYTES, source.byteLength - offset), { signal });
    check();
    for (let i = 0; i < bytes.length; i++) {
      while (j && bytes[i] !== pattern[j]) j = prefix[j - 1];
      if (bytes[i] === pattern[j]) j++;
      if (j === pattern.length) {
        matches.push(offset + i - j + 1); j = prefix[j - 1];
        if (matches.length >= Math.min(maxMatches, MAX_ITEMS)) return matches;
      }
    }
    await pause(); check();
  }
  return matches;
}
export async function extractStrings(input, { maxStrings = 100000, ...options } = {}) {
  const result = [];
  let startOffset = 0;
  do {
    const page = await scanStrings(input, { ...options, startOffset, maxStrings: Math.min(1000, maxStrings - result.length) });
    result.push(...page.strings);
    if (page.nextOffset === null || result.length >= maxStrings) return result;
    startOffset = page.nextOffset;
  } while (true);
}

// Symmetric sigma folding keeps case-insensitive filtering independent of chunk boundaries.
const foldStringFilter = (text) => text.toLowerCase().replace(/ς/g, "σ");

/** Sequential scan keeps UTF-8/codepoint and string state across fixed chunks. */
export async function scanStrings(input, {
  startOffset = 0, query = "", minLength = 4, encoding = "utf8", signal, maxStrings = 200,
} = {}) {
  const source = pagedSource(input);
  if (!Number.isSafeInteger(startOffset) || startOffset < 0 || startOffset > source.byteLength) throw new Error("Invalid string scan cursor");
  if (!Number.isInteger(minLength) || minLength < 1) throw new Error("Minimum string length must be positive");
  if (!Number.isInteger(maxStrings) || maxStrings < 1 || maxStrings > 1000) throw new Error("String pages must contain 1–1000 entries");
  if (!["ascii", "utf8"].includes(encoding)) throw new Error("Unsupported string encoding");
  if (query.length > MAX_NAME_BYTES) throw new Error("String query exceeds 4096 characters");
  const check = () => { cancelled(signal); source.check?.(signal); };
  const strings = [], needle = foldStringFilter(query), prefix = new Uint32Array(needle.length);
  for (let i = 1, j = 0; i < needle.length; i++) {
    while (j && needle[i] !== needle[j]) j = prefix[j - 1];
    if (needle[i] === needle[j]) j++;
    prefix[i] = j;
  }
  let start = -1, count = 0, preview = "", units = 0, matched = 0, matches = !needle, carry = new Uint8Array(0);
  function finish(end) {
    if (start >= 0 && count >= minLength && matches)
      strings.push({ offset: start, string: preview, byteLength: end - start, truncated: units > preview.length });
    start = -1; count = 0; preview = ""; units = 0; matched = 0; matches = !needle;
  }
  check();
  for (let offset = startOffset; offset < source.byteLength; offset += SCAN_BYTES) {
    const next = await source.read(offset, Math.min(SCAN_BYTES, source.byteLength - offset), { signal });
    check();
    const bytes = carry.length ? new Uint8Array(carry.length + next.length) : next;
    if (carry.length) { bytes.set(carry); bytes.set(next, carry.length); }
    const base = offset - carry.length, eof = offset + next.length === source.byteLength;
    let i = 0;
    for (; i < bytes.length; ) {
      const b = bytes[i];
      let width = 1, cp = b, valid = b >= 32 && b <= 126;
      if (!valid && encoding === "utf8" && b >= 0xc2 && b <= 0xf4) {
        width = b < 0xe0 ? 2 : b < 0xf0 ? 3 : 4;
        if (i + width > bytes.length && !eof) break;
        cp = b & ((1 << (7 - width)) - 1);
        valid = i + width <= bytes.length;
        for (let k = 1; valid && k < width; k++) {
          const c = bytes[i + k];
          if (c < 0x80 || c > 0xbf) valid = false;
          else cp = (cp << 6) | (c & 63);
        }
        valid = valid && cp >= (width === 2 ? 128 : width === 3 ? 2048 : 65536) && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) && !(cp >= 127 && cp <= 159);
      }
      if (valid) {
        if (start < 0) start = base + i;
        count++;
        const text = String.fromCodePoint(cp);
        units += text.length;
        if (preview.length < 4096) preview += text.slice(0, 4096 - preview.length);
        if (!matches) {
          const folded = foldStringFilter(text);
          for (let unit = 0; unit < folded.length && !matches; unit++) {
            while (matched && folded[unit] !== needle[matched]) matched = prefix[matched - 1];
            if (folded[unit] === needle[matched]) matched++;
            if (matched === needle.length) matches = true;
          }
        }
        i += width;
      } else {
        finish(base + i); i++;
        if (strings.length >= maxStrings) {
          check(); const cursor = base + i;
          return { strings, nextOffset: cursor < source.byteLength ? cursor : null };
        }
      }
    }
    carry = bytes.slice(i);
    await pause(); check();
  }
  finish(source.byteLength); check();
  return { strings, nextOffset: null };
}
