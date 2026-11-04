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
class Reader {
  constructor(bytes, le = true) {
    this.b = bytes;
    this.v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.le = le;
    this.records = 0;
    this.textBytes = 0;
    this.outputBytes = 0;
    this.names = new Map();
  }
  output(text) {
    this.outputBytes += text.length * 2;
    if (this.outputBytes > MAX_TEXT_BYTES)
      analysisLimit("expanded text budget exceeded");
    return text;
  }
  record() {
    if (++this.records > MAX_ITEMS) analysisLimit("record budget exceeded");
  }
  textBudget(n) {
    this.textBytes += n;
    if (this.textBytes > MAX_TEXT_BYTES) analysisLimit("text budget exceeded");
  }
  has(o, n) {
    return (
      Number.isSafeInteger(o) &&
      Number.isSafeInteger(n) &&
      o >= 0 &&
      n >= 0 &&
      o <= this.b.length &&
      n <= this.b.length - o
    );
  }
  need(o, n) {
    if (!this.has(o, n))
      throw new Error(
        `Truncated or invalid range at ${Number.isFinite(o) ? hex(o) : "?"}`,
      );
  }
  u8(o) {
    this.need(o, 1);
    return this.v.getUint8(o);
  }
  u16(o) {
    this.need(o, 2);
    return this.v.getUint16(o, this.le);
  }
  u32(o) {
    this.need(o, 4);
    return this.v.getUint32(o, this.le);
  }
  i16(o) {
    this.need(o, 2);
    return this.v.getInt16(o, this.le);
  }
  u64(o) {
    this.need(o, 8);
    return this.v.getBigUint64(o, this.le);
  }
  num64(o) {
    const n = this.u64(o);
    if (n > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("File offset or size exceeds safe integer range");
    return Number(n);
  }
  text(o, n) {
    this.need(o, n);
    this.textBudget(n);
    return decoder.decode(this.b.subarray(o, o + n));
  }
  z(o, end = this.b.length, newline = false) {
    this.need(o, 0);
    end = Math.min(end, this.b.length);
    const key = `${o}:${end}:${newline}`;
    if (this.names.has(key)) return this.names.get(key);
    let p = o;
    const limit = Math.min(end, o + MAX_NAME_BYTES);
    while (p < limit && this.b[p] && (!newline || this.b[p] !== 10)) p++;
    this.textBudget(p - o);
    if (p === limit && p < end && this.b[p])
      analysisLimit("individual name exceeds 4096 bytes");
    const name = decoder.decode(this.b.subarray(o, p));
    this.names.set(key, name);
    return name;
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
function bounded(out, work) {
  try {
    return work();
  } catch (e) {
    if (e.code === "ANALYSIS_LIMIT") throw e;
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

export function parseBinary(bytes) {
  if (!(bytes instanceof Uint8Array))
    throw new TypeError("Expected Uint8Array");
  const out = {
    format: "RAW",
    architecture: "Unknown",
    bits: null,
    endian: null,
    sections: [],
    symbols: [],
    members: [],
    fileSize: bytes.length,
    memorySize: null,
    warnings: [],
  };
  const r = new Reader(bytes);
  try {
    (() => {
      if (bytes.length >= 4 && bytes[0] === 0x7f && r.text(1, 3) === "ELF") {
        out.format = "ELF";
        parseELF(r, out);
      } else if (
        bytes.length >= 8 &&
        (r.text(0, 8) === "!<arch>\n" || r.text(0, 8) === "!<thin>\n")
      ) {
        out.format = "AR";
        parseAR(r, out);
      } else if (bytes.length >= 2 && r.text(0, 2) === "MZ") {
        out.format = "PE";
        parsePE(r, out);
      } else if (
        bytes.length >= 4 &&
        [
          0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe,
          0xbebafeca, 0xcafebabf, 0xbfbafeca,
        ].includes(r.u32(0))
      ) {
        out.format = "Mach-O";
        warn(
          out,
          "Mach-O structure analysis is not supported; hex and strings remain available.",
        );
      } else if (
        bytes.length >= 2 &&
        [0x14c, 0x8664, 0x1c0, 0x1c2, 0x1c4, 0xaa64, 0x5032, 0x5064].includes(
          r.u16(0),
        )
      ) {
        out.format = "COFF";
        parseCOFF(r, out, 0, false);
      }
    })();
  } catch (e) {
    warn(out, e.message);
  }
  return out;
}
function pushSymbol(out, r, symbol) {
  for (const [key, value] of Object.entries(symbol))
    if (key !== "name" && typeof value === "string") r.output(value);
  out.symbols.push(symbol);
}
function parseELF(r, out) {
  const klass = r.u8(4),
    encoding = r.u8(5);
  if (![1, 2].includes(klass) || ![1, 2].includes(encoding))
    throw new Error("Invalid ELF class or byte order");
  const wide = klass === 2;
  r.le = encoding === 1;
  out.bits = wide ? 64 : 32;
  out.endian = r.le ? "LE" : "BE";
  r.need(0, wide ? 64 : 52);
  out.architecture = architecture(r.u16(18));
  const elfType = r.u16(16);
  const u = (o) => (wide ? r.num64(o) : r.u32(o)),
    addr = (o) => hex(wide ? r.u64(o) : r.u32(o));
  const phoff = u(wide ? 32 : 28),
    shoff = u(wide ? 40 : 32),
    phstride = r.u16(wide ? 54 : 42),
    shstride = r.u16(wide ? 58 : 46);
  let phnum = r.u16(wide ? 56 : 44),
    shnum = r.u16(wide ? 60 : 48),
    names = r.u16(wide ? 62 : 50);
  if (shoff && (shnum === 0 || names === 0xffff || phnum === 0xffff))
    bounded(out, () => {
      r.need(shoff, wide ? 64 : 40);
      if (shnum === 0) shnum = u(shoff + (wide ? 32 : 20));
      if (names === 0xffff) names = r.u32(shoff + (wide ? 40 : 24));
      if (phnum === 0xffff) phnum = r.u32(shoff + (wide ? 44 : 28));
    });
  const headers = [];
  if (shoff && shnum)
    bounded(out, () => {
      table(r, shoff, shnum, shstride, wide ? 64 : 40);
      for (let i = 0; i < shnum; i++) {
        r.record();
        const p = shoff + i * shstride;
        headers.push({
          nameIndex: r.u32(p),
          type: r.u32(p + 4),
          flags: wide ? r.u64(p + 8) : BigInt(r.u32(p + 8)),
          address: addr(p + (wide ? 16 : 12)),
          offset: u(p + (wide ? 24 : 16)),
          size: u(p + (wide ? 32 : 20)),
          link: r.u32(p + (wide ? 40 : 24)),
          entrySize: u(p + (wide ? 56 : 36)),
        });
      }
      const namesHeader = headers[names];
      const namesEnd =
        namesHeader && r.has(namesHeader.offset, namesHeader.size)
          ? namesHeader.offset + namesHeader.size
          : 0;
      for (let i = 0; i < headers.length; i++) {
        r.record();
        const h = headers[i];
        let name = `[section ${i}]`;
        if (namesEnd && h.nameIndex < namesHeader.size)
          name = r.z(namesHeader.offset + h.nameIndex, namesEnd) || name;
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
    });
  if (phoff && phnum)
    bounded(out, () => {
      table(r, phoff, phnum, phstride, wide ? 56 : 32);
      const ranges = [];
      for (let i = 0; i < phnum; i++) {
        r.record();
        const p = phoff + i * phstride;
        if (r.u32(p) !== 1) continue;
        const start = wide ? r.u64(p + 16) : BigInt(r.u32(p + 8)),
          length = wide ? r.u64(p + 40) : BigInt(r.u32(p + 20));
        const fileOffset = u(p + (wide ? 8 : 4)),
          fileSize = u(p + (wide ? 32 : 16));
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
    });
  for (const h of headers)
    if (h.type === 2 || h.type === 11)
      bounded(out, () => {
        r.record();
        const strings = headers[h.link];
        if (!strings || !r.has(strings.offset, strings.size))
          throw new Error(`${h.name}: invalid symbol string table`);
        const stride = h.entrySize;
        if (!stride || h.size % stride)
          throw new Error(`${h.name}: invalid symbol entry size`);
        table(r, h.offset, h.size / stride, stride, wide ? 24 : 16);
        for (let p = h.offset; p < h.offset + h.size; p += stride) {
          r.record();
          const ni = r.u32(p),
            info = r.u8(p + (wide ? 4 : 12)),
            si = r.u16(p + (wide ? 6 : 14));
          if (!ni || ni >= strings.size) continue;
          const name = r.z(strings.offset + ni, strings.offset + strings.size);
          if (!name) continue;
          const value = wide ? r.u64(p + 8) : BigInt(r.u32(p + 4)),
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
            address: si === 0 ? null : addr(p + (wide ? 8 : 4)),
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
            }[r.u8(p + (wide ? 5 : 13)) & 3],
            size: u(p + (wide ? 16 : 8)),
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
      });
}
function parseAR(r, out) {
  if (r.text(0, 8) === "!<thin>\n") {
    warn(
      out,
      "Thin archives reference external files; member inspection is not supported.",
    );
    return;
  }
  let p = 8,
    longNames = null,
    count = 0;
  while (p < r.b.length) {
    r.record();
    if (++count > MAX_ITEMS) throw new Error("Archive member limit exceeded");
    r.need(p, 60);
    if (r.text(p + 58, 2) !== "`\n")
      throw new Error(`Invalid archive member header at ${hex(p)}`);
    let name = r.text(p, 16).trim();
    const sizeText = r.text(p + 48, 10).trim(),
      dateText = r.text(p + 16, 12).trim();
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
        name = r
          .z(longNames.offset + ni, longNames.offset + longNames.size, true)
          .replace(/\/$/, "");
      } else warn(out, "Archive long-name reference has no valid string table");
    } else if (name.startsWith("#1/")) {
      const text = name.slice(3);
      if (!/^\d+$/.test(text) || Number(text) > size)
        throw new Error("Invalid BSD archive filename length");
      const n = Number(text);
      name = r.text(offset, n).replace(/\0+$/, "");
      offset += n;
      size -= n;
    } else if (name.endsWith("/") && !service) name = name.slice(0, -1);
    out.members.push({
      name: r.output(name),
      offset,
      size,
      bytes: r.b.subarray(offset, offset + size),
      service: service || name.startsWith("__.SYMDEF"),
      date: /^\d+$/.test(dateText) ? Number(dateText) : null,
    });
    p += 60 + storedSize;
    if (p % 2) p++;
  }
}
function coffSections(r, out, p, count) {
  table(r, p, count, 40, 40);
  const sections = [];
  for (let i = 0; i < count; i++) {
    r.record();
    const q = p + i * 40,
      name = r.z(q, q + 8),
      virtualSize = r.u32(q + 8),
      address = r.u32(q + 12),
      size = r.u32(q + 16),
      offset = r.u32(q + 20),
      flags = r.u32(q + 36);
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
function parseCOFF(r, out, start = 0, pe = false) {
  r.need(start, 20);
  const machine = r.u16(start),
    count = r.u16(start + 2),
    symbolsOffset = r.u32(start + 8),
    symbolCount = r.u32(start + 12),
    optionalSize = r.u16(start + 16);
  out.architecture = architecture(machine);
  out.bits = [0x8664, 0xaa64, 0x5064].includes(machine) ? 64 : 32;
  out.endian = "LE";
  const sections = coffSections(r, out, start + 20 + optionalSize, count);
  if (symbolCount || symbolsOffset)
    bounded(out, () => {
      table(r, symbolsOffset, symbolCount, 18, 18);
      const stringsOffset = symbolsOffset + symbolCount * 18;
      r.need(stringsOffset, 4);
      const stringsSize = r.u32(stringsOffset);
      if (stringsSize < 4) throw new Error("Invalid COFF string table size");
      r.need(stringsOffset, stringsSize);
      const nameAt = (p) => {
        if (r.u32(p) === 0) {
          const ni = r.u32(p + 4);
          if (ni < 4 || ni >= stringsSize) {
            warn(out, "Invalid COFF symbol name offset");
            return "";
          }
          return r.z(stringsOffset + ni, stringsOffset + stringsSize);
        }
        return r.z(p, p + 8);
      };
      for (const s of out.sections)
        if (/^\/\d+$/.test(s.name)) {
          const ni = Number(s.name.slice(1));
          if (ni >= 4 && ni < stringsSize)
            s.name = r.z(stringsOffset + ni, stringsOffset + stringsSize);
        }
      for (let i = 0; i < symbolCount; ) {
        r.record();
        const p = symbolsOffset + i * 18,
          name = nameAt(p),
          value = r.u32(p + 8),
          section = r.i16(p + 12),
          type = r.u16(p + 14),
          storage = r.u8(p + 16),
          aux = r.u8(p + 17);
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
    });
  return sections;
}
function parsePE(r, out) {
  r.need(0, 64);
  const p = r.u32(60);
  r.need(p, 24);
  if (r.text(p, 4) !== "PE\0\0") throw new Error("Invalid PE signature");
  const opt = p + 24,
    optSize = r.u16(p + 20);
  r.need(opt, optSize);
  const magic = r.u16(opt),
    wide = magic === 0x20b;
  if (magic !== 0x10b && !wide)
    throw new Error("Unsupported PE optional header");
  const minimum = wide ? 112 : 96;
  if (optSize < minimum) throw new Error("Truncated PE optional header");
  const sections = parseCOFF(r, out, p + 4, true);
  out.bits = wide ? 64 : 32;
  const base = wide ? r.u64(opt + 24) : BigInt(r.u32(opt + 28));
  out.memorySize = r.u32(opt + 56);
  for (const s of out.sections)
    s.address = hex(base + BigInt(s.rva ?? parseInt(s.address.slice(2), 16)));
  for (const symbol of out.symbols) {
    const section = sections.find((s) => s.name === symbol.section);
    if (section && symbol.address !== null)
      symbol.address = hex(base + BigInt(section.rva) + BigInt(symbol.address));
  }
  const headersSize = r.u32(opt + 60),
    directoryCount = r.u32(opt + (wide ? 108 : 92)),
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
  const str = (rva) => {
    const q = resolve(rva);
    const s = sections.find(
      (s) => s.offset !== null && q >= s.offset && q < s.offset + s.fileSize,
    );
    return r.z(
      q,
      s ? s.offset + s.fileSize : Math.min(headersSize, r.b.length),
    );
  };
  const directory = (i) => {
    if (i >= directoryCount || (i + 1) * 8 > optSize - minimum) return null;
    const rva = r.u32(dir + i * 8),
      size = r.u32(dir + i * 8 + 4);
    return rva && size ? { rva, size } : null;
  };
  const exp = directory(0);
  if (exp)
    bounded(out, () => {
      const q = resolve(exp.rva, 40),
        ordinalBase = r.u32(q + 16),
        funcCount = r.u32(q + 20),
        nameCount = r.u32(q + 24);
      if (funcCount > MAX_ITEMS || nameCount > MAX_ITEMS)
        throw new Error("PE export count exceeds limit");
      const funcs = resolve(r.u32(q + 28), funcCount * 4),
        names = nameCount ? resolve(r.u32(q + 32), nameCount * 4) : 0,
        ordinals = nameCount ? resolve(r.u32(q + 36), nameCount * 2) : 0,
        named = new Map();
      for (let i = 0; i < nameCount; i++) {
        r.record();
        const ordinal = r.u16(ordinals + i * 2);
        if (ordinal >= funcCount) {
          warn(out, "Invalid PE export ordinal");
          continue;
        }
        named.set(ordinal, str(r.u32(names + i * 4)));
      }
      for (let i = 0; i < funcCount; i++) {
        r.record();
        const target = r.u32(funcs + i * 4);
        if (!target) continue;
        const forwarded = target >= exp.rva && target - exp.rva < exp.size;
        pushSymbol(out, r, {
          name: r.output(named.get(i) || `Ordinal ${ordinalBase + i}`),
          address: forwarded ? null : hex(base + BigInt(target)),
          offset: forwarded ? null : bounded(out, () => resolve(target)),
          binding: null,
          visibility: null,
          size: null,
          section: null,
          kind: forwarded ? "export-forwarder" : "export",
          source: forwarded ? str(target) : "PE exports",
        });
      }
    });
  const imp = directory(1);
  if (imp)
    bounded(out, () => {
      const count = Math.min(Math.floor(imp.size / 20), MAX_ITEMS);
      let terminated = false;
      for (let i = 0; i < count; i++) {
        r.record();
        const q = resolve(imp.rva + i * 20, 20),
          original = r.u32(q),
          timestamp = r.u32(q + 4),
          chain = r.u32(q + 8),
          nameRva = r.u32(q + 12),
          first = r.u32(q + 16);
        if (!original && !timestamp && !chain && !nameRva && !first) {
          terminated = true;
          break;
        }
        const dll = str(nameRva),
          thunk = original || first,
          width = wide ? 8 : 4;
        let end = false;
        for (let j = 0; j < MAX_ITEMS; j++) {
          r.record();
          const t = resolve(thunk + j * width, width),
            value = wide ? r.u64(t) : BigInt(r.u32(t));
          if (!value) {
            end = true;
            break;
          }
          const ordinalFlag = wide ? 0x8000000000000000n : 0x80000000n;
          const name =
            value & ordinalFlag
              ? `Ordinal ${value & 0xffffn}`
              : value <= 0xffffffffn
                ? str(Number(value) + 2)
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
    });
}

function abort(signal) {
  if (signal?.aborted) {
    const e = new Error("Analysis cancelled");
    e.name = "AbortError";
    throw e;
  }
}
const pause = () => new Promise((resolve) => setTimeout(resolve, 0));
export function parseSearchPattern(query, mode = "hex") {
  if (mode === "text") return new TextEncoder().encode(query);
  const compact = query.replace(/\s+/g, "");
  if (!compact || compact.length % 2 || !/^[0-9a-f]+$/i.test(compact))
    throw new Error("Enter complete hexadecimal byte pairs");
  return Uint8Array.from(compact.match(/../g), (s) => parseInt(s, 16));
}
export async function searchBytes(
  bytes,
  query,
  { mode = "hex", signal, maxMatches = 100000 } = {},
) {
  const pattern = parseSearchPattern(query, mode),
    matches = [];
  abort(signal);
  if (!pattern.length) return matches;
  // KMP keeps long repeated patterns linear and preserves overlapping matches.
  const prefix = new Uint32Array(pattern.length);
  for (let i = 1, j = 0; i < pattern.length; i++) {
    while (j && pattern[i] !== pattern[j]) j = prefix[j - 1];
    if (pattern[i] === pattern[j]) j++;
    prefix[i] = j;
  }
  for (let i = 0, j = 0; i < bytes.length; i++) {
    while (j && bytes[i] !== pattern[j]) j = prefix[j - 1];
    if (bytes[i] === pattern[j]) j++;
    if (j === pattern.length) {
      matches.push(i - j + 1);
      j = prefix[j - 1];
      if (matches.length >= maxMatches) return matches;
    }
    if ((i & 0x3ffff) === 0) {
      abort(signal);
      await pause();
      abort(signal);
    }
  }
  return matches;
}
export async function extractStrings(
  bytes,
  { minLength = 4, encoding = "utf8", signal, maxStrings = 100000 } = {},
) {
  if (!Number.isInteger(minLength) || minLength < 1)
    throw new Error("Minimum string length must be positive");
  if (!["ascii", "utf8"].includes(encoding))
    throw new Error("Unsupported string encoding");
  const result = [];
  let start = -1,
    count = 0;
  const finish = (end) => {
    if (start >= 0 && count >= minLength)
      result.push({
        offset: start,
        string: decoder.decode(bytes.subarray(start, end)),
      });
    start = -1;
    count = 0;
  };
  for (let i = 0; i < bytes.length; ) {
    if ((i & 0xffff) < 4) {
      abort(signal);
      await pause();
      abort(signal);
    }
    const b = bytes[i];
    let width = 1,
      cp = b,
      valid = b >= 32 && b <= 126;
    if (!valid && encoding === "utf8" && b >= 0xc2 && b <= 0xf4) {
      width = b < 0xe0 ? 2 : b < 0xf0 ? 3 : 4;
      cp = b & ((1 << (7 - width)) - 1);
      valid = i + width <= bytes.length;
      for (let k = 1; valid && k < width; k++) {
        const c = bytes[i + k];
        if (c < 0x80 || c > 0xbf) valid = false;
        else cp = (cp << 6) | (c & 63);
      }
      valid =
        valid &&
        cp >= (width === 2 ? 0x80 : width === 3 ? 0x800 : 0x10000) &&
        cp <= 0x10ffff &&
        !(cp >= 0xd800 && cp <= 0xdfff) &&
        !(cp >= 0x7f && cp <= 0x9f);
    }
    if (valid) {
      if (start < 0) start = i;
      count++;
      i += width;
    } else {
      finish(i);
      i++;
    }
    if (result.length >= maxStrings) return result;
  }
  finish(bytes.length);
  abort(signal);
  return result;
}

/** A bounded page of string previews. Cursor boundaries never split a UTF-8 string. */
export async function scanStrings(
  bytes,
  {
    startOffset = 0,
    query = "",
    minLength = 4,
    encoding = "utf8",
    signal,
    maxStrings = 200,
  } = {},
) {
  if (
    !Number.isInteger(startOffset) ||
    startOffset < 0 ||
    startOffset > bytes.length
  )
    throw new Error("Invalid string scan cursor");
  if (!Number.isInteger(minLength) || minLength < 1)
    throw new Error("Minimum string length must be positive");
  if (!Number.isInteger(maxStrings) || maxStrings < 1 || maxStrings > 1000)
    throw new Error("String pages must contain 1–1000 entries");
  if (!["ascii", "utf8"].includes(encoding))
    throw new Error("Unsupported string encoding");
  const strings = [],
    needle = query.toLowerCase();
  let start = -1,
    count = 0;
  async function emit(end) {
    if (start < 0 || count < minLength) return;
    const decode = new TextDecoder("utf-8");
    let preview = "",
      tail = "",
      matches = !needle,
      totalUnits = 0;
    for (let p = start; p < end; p += 65536) {
      abort(signal);
      const part = decode.decode(bytes.subarray(p, Math.min(end, p + 65536)), {
        stream: p + 65536 < end,
      });
      totalUnits += part.length;
      if (preview.length < 4096)
        preview += part.slice(0, 4096 - preview.length);
      if (!matches) {
        const text = tail + part.toLowerCase();
        matches = text.includes(needle);
        tail = needle.length > 1 ? text.slice(-(needle.length - 1)) : "";
      }
      if (p + 65536 < end) await pause();
    }
    if (matches)
      strings.push({
        offset: start,
        string: preview,
        byteLength: end - start,
        truncated: totalUnits > preview.length,
      });
  }
  for (let i = startOffset; i < bytes.length; ) {
    if ((i & 0xffff) < 4) {
      abort(signal);
      await pause();
      abort(signal);
    }
    const b = bytes[i];
    let width = 1,
      cp = b,
      valid = b >= 32 && b <= 126;
    if (!valid && encoding === "utf8" && b >= 0xc2 && b <= 0xf4) {
      width = b < 0xe0 ? 2 : b < 0xf0 ? 3 : 4;
      cp = b & ((1 << (7 - width)) - 1);
      valid = i + width <= bytes.length;
      for (let k = 1; valid && k < width; k++) {
        const c = bytes[i + k];
        if (c < 0x80 || c > 0xbf) valid = false;
        else cp = (cp << 6) | (c & 63);
      }
      valid =
        valid &&
        cp >= (width === 2 ? 128 : width === 3 ? 2048 : 65536) &&
        cp <= 0x10ffff &&
        !(cp >= 0xd800 && cp <= 0xdfff) &&
        !(cp >= 127 && cp <= 159);
    }
    if (valid) {
      if (start < 0) start = i;
      count++;
      i += width;
    } else {
      await emit(i);
      start = -1;
      count = 0;
      i++;
      if (strings.length >= maxStrings)
        return { strings, nextOffset: i < bytes.length ? i : null };
    }
  }
  await emit(bytes.length);
  abort(signal);
  return { strings, nextOffset: null };
}
