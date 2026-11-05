import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  parseBinary,
  searchBytes,
  extractStrings,
  scanStrings,
} from "../editor/binary-core.mjs";
const enc = new TextEncoder();
function fixture(length, le = true) {
  const b = new Uint8Array(length),
    v = new DataView(b.buffer);
  return {
    b,
    v,
    u16: (o, n) => v.setUint16(o, n, le),
    u32: (o, n) => v.setUint32(o, n, le),
    u64: (o, n) => v.setBigUint64(o, BigInt(n), le),
    text: (o, s) => b.set(enc.encode(s), o),
  };
}
function elf(wide, le) {
  const f = fixture(512, le),
    { b, text, u16, u32, u64 } = f;
  text(0, "\x7fELF");
  b[4] = wide ? 2 : 1;
  b[5] = le ? 1 : 2;
  b[6] = 1;
  u16(16, 1);
  u16(18, wide ? 62 : 3);
  const u = wide ? u64 : u32,
    sh = 128,
    stride = wide ? 64 : 40;
  u(wide ? 40 : 32, sh);
  u16(wide ? 58 : 46, stride);
  u16(wide ? 60 : 48, 4);
  u16(wide ? 62 : 50, 1);
  const section = (i, name, type, flags, offset, size, link = 0, entry = 0) => {
    const p = sh + i * stride;
    u32(p, name);
    u32(p + 4, type);
    u(p + 8, flags);
    u(p + (wide ? 16 : 12), 0x1000);
    u(p + (wide ? 24 : 16), offset);
    u(p + (wide ? 32 : 20), size);
    u32(p + (wide ? 40 : 24), link);
    u(p + (wide ? 56 : 36), entry);
  };
  text(400, "\0.shstrtab\0.bss\0.symtab\0zero\0");
  section(1, 1, 3, 0, 400, 28);
  section(2, 11, 8, 3, 0, 128);
  section(3, 16, 2, 0, 448, wide ? 24 : 16, 1, wide ? 24 : 16);
  u32(448, 24);
  if (wide) {
    b[452] = 2;
    u16(454, 2);
    u64(456, 0x1000);
    u64(464, 0);
  } else {
    u32(452, 0x1000);
    u32(456, 0);
    b[460] = 2;
    u16(462, 2);
  }
  return b;
}
test("ELF32/64 LE/BE sections, BSS, and zero symbol size", async () => {
  for (const wide of [false, true])
    for (const le of [false, true]) {
      const m = (await parseBinary(elf(wide, le)));
      assert.equal(m.format, "ELF");
      assert.deepEqual(m.warnings, []);
      assert.equal(m.endian, le ? "LE" : "BE");
      assert.equal(m.bits, wide ? 64 : 32);
      assert.equal(m.sections[2].offset, null);
      assert.equal(m.sections[2].fileSize, 0);
      assert.equal(m.sections[2].memorySize, 128);
      assert.equal(m.symbols[0].name, "zero");
      assert.equal(m.symbols[0].size, 0);
      assert.equal(m.symbols[0].address, "0x1000");
      assert.equal(m.symbols[0].offset, null);
      assert.equal(m.symbols[0].binding, "LOCAL");
      assert.equal(m.symbols[0].visibility, "DEFAULT");
      assert.equal(m.memorySize, null);
    }
});
test("ELF PT_LOAD memory includes zero initialized region", async () => {
  const b = elf(true, true),
    v = new DataView(b.buffer);
  v.setUint16(16, 2, true);
  v.setBigUint64(32, 64n, true);
  v.setUint16(54, 56, true);
  v.setUint16(56, 1, true);
  v.setUint32(64, 1, true);
  v.setBigUint64(104, 4096n, true);
  assert.equal((await parseBinary(b)).memorySize, 4096);
});
test("truncated and corrupt ELF are warnings, not throws", async () => {
  const b = elf(true, true);
  for (let n = 4; n < b.length; n++) {
    const m = (await parseBinary(b.subarray(0, n)));
    assert.equal(m.fileSize, n);
  }
  const v = new DataView(b.buffer);
  v.setUint16(58, 1, true);
  assert.ok((await parseBinary(b)).warnings.length);
});
function arMember(name, bytes, size = bytes.length) {
  const header =
    name.padEnd(16) +
    "0".padEnd(12) +
    "0".padEnd(6) +
    "0".padEnd(6) +
    "100644".padEnd(8) +
    String(size).padEnd(10) +
    "`\n";
  const h = enc.encode(header),
    r = new Uint8Array(h.length + bytes.length + (bytes.length % 2));
  r.set(h);
  r.set(bytes, h.length);
  if (bytes.length % 2) r[r.length - 1] = 10;
  return r;
}
function join(...parts) {
  const b = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    b.set(p, at);
    at += p.length;
  }
  return b;
}
test("AR GNU/BSD long names and service members preserve payload offsets", async () => {
  const b = join(
    enc.encode("!<arch>\n"),
    arMember("/", new Uint8Array(4)),
    arMember("//", enc.encode("a_long_name.o/\n")),
    arMember("/0", Uint8Array.of(1, 2)),
    arMember("#1/10", join(enc.encode("bsd_name.o"), Uint8Array.of(3, 4))),
  );
  const m = (await parseBinary(b));
  assert.deepEqual(m.warnings, []);
  assert.equal(m.members[0].service, true);
  assert.equal(m.members[1].service, true);
  assert.equal(m.members[2].name, "a_long_name.o");
  assert.equal(m.members[3].name, "bsd_name.o");
  assert.equal(m.members[3].size, 2);
  assert.equal("bytes" in m.members[3], false);
  assert.equal(b[m.members[3].offset], 3);
});
test("negative/truncated/bad AR headers return warnings without looping", async () => {
  for (const b of [
    join(enc.encode("!<arch>\n"), arMember("bad", new Uint8Array(), -60)),
    join(enc.encode("!<arch>\n"), arMember("bad", new Uint8Array(), 100)),
    enc.encode("!<arch>\nshort"),
  ]) {
    const m = (await parseBinary(b));
    assert.equal(m.format, "AR");
    assert.ok(m.warnings.length);
  }
});
function coff() {
  const f = fixture(160),
    { u16, u32, text } = f;
  u16(0, 0x8664);
  u16(2, 1);
  u32(8, 64);
  u32(12, 3);
  text(20, ".text");
  u32(36, 4);
  u32(40, 60);
  u32(56, 0x60000020);
  text(64, "func");
  u32(72, 0);
  u16(76, 1);
  u16(78, 0x20);
  f.b[80] = 2;
  f.b[81] = 1;
  u32(100, 0);
  u32(104, 4);
  u16(112, 0);
  f.b[116] = 2;
  u32(118, 16);
  text(122, "long_symbol\0");
  return f.b;
}
test("ordinary COFF skips aux records, resolves string names, keeps unknown sizes null", async () => {
  const m = (await parseBinary(coff()));
  assert.deepEqual(m.warnings, []);
  assert.equal(m.format, "COFF");
  assert.equal(m.symbols.length, 2);
  assert.equal(m.symbols[0].name, "func");
  assert.equal(m.symbols[0].size, null);
  assert.equal(m.symbols[0].offset, 60);
  assert.equal(m.memorySize, null);
  assert.equal(m.symbols[1].name, "long_symbol");
  assert.equal(m.symbols[1].address, null);
});
function pe(wide) {
  const f = fixture(2048),
    { b, u16, u32, u64, text } = f;
  text(0, "MZ");
  u32(60, 128);
  text(128, "PE\0\0");
  const c = 132,
    o = 152,
    optSize = wide ? 240 : 224,
    s = o + optSize;
  u16(c, wide ? 0x8664 : 0x14c);
  u16(c + 2, 1);
  u16(c + 16, optSize);
  u16(o, wide ? 0x20b : 0x10b);
  if (wide) u64(o + 24, 0x140000000n);
  else u32(o + 28, 0x400000);
  u32(o + 56, 8192);
  u32(o + 60, 512);
  u32(o + (wide ? 108 : 92), 16);
  const d = o + (wide ? 112 : 96);
  u32(d, 0x1100);
  u32(d + 4, 80);
  u32(d + 8, 0x1200);
  u32(d + 12, 40);
  text(s, ".rdata");
  u32(s + 8, 1536);
  u32(s + 12, 0x1000);
  u32(s + 16, 1536);
  u32(s + 20, 512);
  u32(s + 36, 0x40000040);
  const e = 768;
  u32(e + 16, 1);
  u32(e + 20, 1);
  u32(e + 24, 1);
  u32(e + 28, 0x1150);
  u32(e + 32, 0x1154);
  u32(e + 36, 0x1158);
  u32(848, 0x1400);
  u32(852, 0x1160);
  u16(856, 0);
  text(864, "exported\0");
  const im = 1024;
  u32(im, 0x1250);
  u32(im + 12, 0x1240);
  u32(im + 16, 0x1280);
  text(1088, "example.dll\0");
  if (wide) u64(1104, 0x12a0);
  else u32(1104, 0x12a0);
  u16(1184, 0);
  text(1186, "imported\0");
  return b;
}
test("PE32/PE32+ exports/imports with virtual addresses and unknown sizes", async () => {
  for (const wide of [false, true]) {
    const m = (await parseBinary(pe(wide)));
    assert.deepEqual(m.warnings, []);
    assert.equal(m.format, "PE");
    assert.equal(m.bits, wide ? 64 : 32);
    assert.equal(m.memorySize, 8192);
    assert.equal(m.symbols.find((s) => s.kind === "export").name, "exported");
    assert.equal(
      m.symbols.find((s) => s.kind === "export").address,
      wide ? "0x140001400" : "0x401400",
    );
    assert.equal(
      m.symbols.find((s) => s.kind === "import").source,
      "example.dll",
    );
    assert.equal(m.symbols.find((s) => s.kind === "import").size, null);
  }
});
test("corrupt PE/COFF never throw", async () => {
  for (const original of [pe(true), coff()])
    for (let n = 0; n < original.length; n += 7) {
      await assert.doesNotReject(async () => (await parseBinary(original.subarray(0, n))));
    }
});
test("Mach-O detected as unsupported, arbitrary bytes stay raw", async () => {
  assert.equal(
    (await parseBinary(Uint8Array.of(0xcf, 0xfa, 0xed, 0xfe))).format,
    "Mach-O",
  );
  assert.equal((await parseBinary(Uint8Array.of(1, 2, 3, 4))).format, "RAW");
});
test("supplied object/archive parse without warnings", async () => {
  for (const name of ["sample.o", "sample.a"]) {
    const b = await readFile(new URL(`../samples/${name}`, import.meta.url));
    assert.deepEqual((await parseBinary(b)).warnings, []);
  }
});
test("search contiguous and spaced hex, explicit text, overlaps and invalid input", async () => {
  const b = Uint8Array.of(0xde, 0xad, 0xde, 0xad);
  assert.deepEqual(await searchBytes(b, "DEAD"), [0, 2]);
  assert.deepEqual(await searchBytes(b, "de ad"), [0, 2]);
  assert.deepEqual(
    await searchBytes(enc.encode("aaaa"), "aaa", { mode: "text" }),
    [0, 1],
  );
  assert.deepEqual(
    await searchBytes(enc.encode("FACE"), "FACE", { mode: "text" }),
    [0],
  );
  await assert.rejects(searchBytes(b, "dea"), /pairs/);
});
test("UTF8/ASCII strings have byte offsets and valid unicode boundaries", async () => {
  const b = join(
    Uint8Array.of(0),
    enc.encode("Привет мир"),
    Uint8Array.of(0, 0xff),
    enc.encode("ASCII"),
    Uint8Array.of(0),
  );
  const utf = await extractStrings(b);
  assert.equal(utf[0].string, "Привет мир");
  assert.equal(utf[0].offset, 1);
  assert.equal(utf[1].string, "ASCII");
  const ascii = await extractStrings(b, { encoding: "ascii" });
  assert.deepEqual(
    ascii.map((s) => s.string),
    ["ASCII"],
  );
  const bad = join(
    enc.encode("abcd"),
    Uint8Array.of(0xed, 0xa0, 0x80),
    enc.encode("efgh"),
  );
  assert.deepEqual(
    (await extractStrings(bad)).map((s) => s.string),
    ["abcd", "efgh"],
  );
});
test("analysis supports abort and yields to event loop", async () => {
  const b = new Uint8Array(2 * 1024 * 1024),
    ac = new AbortController();
  setTimeout(() => ac.abort(), 0);
  await assert.rejects(searchBytes(b, "abcd", { signal: ac.signal }), {
    name: "AbortError",
  });
  const ac2 = new AbortController();
  setTimeout(() => ac2.abort(), 0);
  await assert.rejects(extractStrings(b, { signal: ac2.signal }), {
    name: "AbortError",
  });
});

test("ELF symbol offsets follow relocatable values versus executable addresses", async () => {
  for (const wide of [false, true]) {
    const b = elf(wide, true),
      v = new DataView(b.buffer),
      p = 128 + 2 * (wide ? 64 : 40);
    v.setUint32(p + 4, 1, true);
    if (wide) {
      v.setBigUint64(p + 24, 480n, true);
      v.setBigUint64(p + 32, 16n, true);
      v.setBigUint64(456, 4n, true);
    } else {
      v.setUint32(p + 16, 480, true);
      v.setUint32(p + 20, 16, true);
      v.setUint32(452, 4, true);
    }
    assert.equal((await parseBinary(b)).symbols[0].offset, 484);
    v.setUint16(16, 2, true);
    if (wide) v.setBigUint64(456, 0x1004n, true);
    else v.setUint32(452, 0x1004, true);
    assert.equal((await parseBinary(b)).symbols[0].offset, 484);
  }
});
test("overlapping ELF PT_LOAD virtual ranges count once", async () => {
  const b = elf(true, true),
    v = new DataView(b.buffer);
  v.setUint16(16, 2, true);
  v.setBigUint64(32, 64n, true);
  v.setUint16(54, 56, true);
  v.setUint16(56, 2, true);
  v.setUint32(64, 1, true);
  v.setBigUint64(80, 4096n, true);
  v.setBigUint64(104, 4096n, true);
  v.setUint32(120, 1, true);
  v.setBigUint64(136, 6144n, true);
  v.setBigUint64(160, 4096n, true);
  assert.equal((await parseBinary(b)).memorySize, 6144);
});

test("repeated ELF symbol tables respect a global expanded text budget", async () => {
  const f = fixture(65536),
    { b, u16, u32, u64, text } = f;
  text(0, "\x7fELF");
  b[4] = 2;
  b[5] = 1;
  u16(16, 1);
  u16(18, 62);
  u64(40, 64);
  u16(58, 64);
  u16(60, 64);
  u16(62, 1);
  const longName = "x".repeat(4095);
  text(40000, "\0" + longName + "\0");
  for (let i = 1; i < 64; i++) {
    const p = 64 + i * 64;
    u32(p + 4, i === 1 ? 3 : 2);
    u64(p + 24, i === 1 ? 40000 : 8192);
    u64(p + 32, i === 1 ? 4097 : 256 * 24);
    u32(p + 40, 1);
    u64(p + 56, 24);
  }
  for (let i = 0; i < 256; i++) u32(8192 + i * 24, 1);
  const m = (await parseBinary(b));
  assert.equal(m.fileSize, 65536);
  assert.ok(m.warnings.some((s) => /Analysis limited/.test(s)));
  assert.ok(m.symbols.length < 2000);
});
test("overlong metadata names stop analysis explicitly", async () => {
  const b = elf(true, true),
    big = new Uint8Array(10000);
  big.set(b);
  const v = new DataView(big.buffer);
  big.fill(65, 400, 9000);
  v.setBigUint64(128 + 64 + 32, 8600n, true);
  const m = (await parseBinary(big));
  assert.ok(m.warnings.some((s) => /individual name/.test(s)));
});
test("invalid PT_LOAD file range and memory mismatch produce warnings", async () => {
  const b = elf(true, true),
    v = new DataView(b.buffer);
  v.setUint16(16, 2, true);
  v.setBigUint64(32, 64n, true);
  v.setUint16(54, 56, true);
  v.setUint16(56, 1, true);
  v.setUint32(64, 1, true);
  v.setBigUint64(72, 500n, true);
  v.setBigUint64(96, 64n, true);
  v.setBigUint64(104, 32n, true);
  const m = (await parseBinary(b));
  assert.ok(m.warnings.some((s) => /file range/.test(s)));
  assert.ok(m.warnings.some((s) => /exceeds memory/.test(s)));
});

test("global record budget stops aliased symbol tables with short names", async () => {
  const f = fixture(70000),
    { b, u16, u32, u64, text } = f;
  text(0, "\x7fELF");
  b[4] = 2;
  b[5] = 1;
  u16(16, 1);
  u16(18, 62);
  u64(40, 64);
  u16(58, 64);
  u16(60, 64);
  u16(62, 1);
  text(65000, "\0x\0");
  for (let i = 1; i < 64; i++) {
    const p = 64 + i * 64;
    u32(p + 4, i === 1 ? 3 : 2);
    u64(p + 24, i === 1 ? 65000 : 8192);
    u64(p + 32, i === 1 ? 3 : 2048 * 24);
    u32(p + 40, 1);
    u64(p + 56, 24);
  }
  for (let i = 0; i < 2048; i++) u32(8192 + i * 24, 1);
  const m = (await parseBinary(b));
  assert.ok(m.warnings.some((s) => /record budget/.test(s)));
  assert.ok(m.symbols.length < 100000);
});
test("string cursor pages filter full unicode values and cap long previews", async () => {
  const { scanStrings } = await import("../editor/binary-core.mjs");
  const b = enc.encode("first\0Привет мир\0third\0fourth\0");
  const page = await scanStrings(b, { maxStrings: 2 });
  assert.deepEqual(
    page.strings.map((s) => s.string),
    ["first", "Привет мир"],
  );
  const next = await scanStrings(b, {
    maxStrings: 2,
    startOffset: page.nextOffset,
  });
  assert.deepEqual(
    next.strings.map((s) => s.string),
    ["third", "fourth"],
  );
  assert.equal(next.nextOffset, null);
  assert.equal((await scanStrings(b, { query: "МИР" })).strings[0].offset, 6);
  const big = enc.encode("x".repeat(140000) + "Needle\0");
  const found = await scanStrings(big, { query: "needle" });
  assert.equal(found.strings.length, 1);
  assert.equal(found.strings[0].string.length, 4096);
  assert.equal(found.strings[0].byteLength, 140006);
  assert.equal(found.strings[0].truncated, true);
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 0);
  await assert.rejects(scanStrings(big, { signal: ac.signal }), {
    name: "AbortError",
  });
});

test("object files open in Orca's byte editor by default", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../orca-plugin.json", import.meta.url), "utf8"),
  );
  const editor = manifest.contributes.customEditors.find(
    (item) => item.id === "binary-inspector",
  );
  assert.equal(editor.priority, "default");
  assert.equal(editor.contentKind, "bytes");
  for (const extension of [
    ".o",
    ".obj",
    ".a",
    ".lib",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".elf",
    ".out",
  ]) {
    assert.ok(editor.extensions.includes(extension), extension);
  }
  assert.equal(manifest.contributes.newFiles[0].extension, ".bin");
  for (const example of manifest.contributes.newFiles.filter(
    (item) => item.template,
  )) {
    assert.ok(
      (await readFile(new URL("../" + example.template, import.meta.url)))
        .length > 0,
      example.title,
    );
  }
});

test("UTF-8 text search preserves leading, trailing and whitespace-only queries", async () => {
  const bytes = enc.encode(" abc  def ");
  assert.deepEqual(await searchBytes(bytes, " abc ", { mode: "text" }), [0]);
  assert.deepEqual(await searchBytes(bytes, "  ", { mode: "text" }), [4]);
});

test("ranged ELF tables and terminated names straddle cache pages for all encodings", async () => {
  const { pagedSource } = await import("../editor/byte-source.mjs");
  for (const wide of [false, true]) for (const le of [false, true]) {
    const original = elf(wide, le), bytes = new Uint8Array(200000), view = new DataView(bytes.buffer);
    bytes.set(original.subarray(0, 128));
    const stride = wide ? 64 : 40, sections = 65530, names = 131068, symbols = 196607;
    bytes.set(original.subarray(128, 128 + stride * 4), sections);
    bytes.set(original.subarray(400, 428), names);
    bytes.set(original.subarray(448, 448 + (wide ? 24 : 16)), symbols);
    const put = (offset, value) => wide ? view.setBigUint64(offset, BigInt(value), le) : view.setUint32(offset, value, le);
    put(wide ? 40 : 32, sections);
    put(sections + stride + (wide ? 24 : 16), names);
    put(sections + 3 * stride + (wide ? 24 : 16), symbols);
    const requests = [];
    const source = pagedSource({ byteLength: bytes.length, version: 7, async read(offset, length) {
      requests.push([offset, length]); return bytes.slice(offset, offset + length);
    } });
    const parsed = await parseBinary(source);
    assert.equal(parsed.format, "ELF");
    assert.equal(parsed.fileSize, 200000);
    assert.equal(parsed.bits, wide ? 64 : 32);
    assert.equal(parsed.endian, le ? "LE" : "BE");
    assert.deepEqual(parsed.warnings, []);
    assert.deepEqual(parsed.sections.map(({ name, offset }) => ({ name, offset })), [
      { name: "[section 0]", offset: null },
      { name: ".shstrtab", offset: 131068 },
      { name: ".bss", offset: null },
      { name: ".symtab", offset: 196607 },
    ]);
    assert.equal(parsed.symbols.length, 1);
    assert.equal(parsed.symbols[0].name, "zero");
    assert.equal(parsed.symbols[0].address, "0x1000");
    assert.equal(parsed.symbols[0].size, 0);
    assert.ok(requests.some(([offset]) => offset >= 65536));
    assert.ok(requests.every(([, length]) => length <= 262144));
  }
});

test("ranged archive members retain coordinates and share the parser without payload copies", async () => {
  const { pagedSource, subSource } = await import("../editor/byte-source.mjs");
  const bytes = join(enc.encode("!<arch>\n"), arMember("padding/", new Uint8Array(65462)), arMember("object.o/", elf(true, false)));
  const reads = [];
  const source = pagedSource({ byteLength: bytes.length, version: 3, async read(offset, length) {
    reads.push([offset, length]); return bytes.slice(offset, offset + length);
  } });
  const archive = await parseBinary(source), member = archive.members[1];
  assert.equal(member.name, "object.o");
  assert.equal(member.offset, 65590);
  assert.equal(member.size, 512);
  assert.equal("bytes" in member, false);
  const parsed = await parseBinary(subSource(source, member.offset, member.size));
  assert.equal(parsed.symbols[0].name, "zero");
  assert.deepEqual(parsed.warnings, []);
  assert.ok(reads.every(([, length]) => length <= 65536));
});

test("KMP and UTF-8 string state survive sequential chunk boundaries and EOF", async () => {
  const { pagedSource, SCAN_BYTES } = await import("../editor/byte-source.mjs");
  const bytes = new Uint8Array(SCAN_BYTES * 2 + 9);
  bytes.set(enc.encode("xyxyxy"), SCAN_BYTES - 3);
  bytes.set(enc.encode("abc€😀tail"), SCAN_BYTES * 2 - 5);
  const source = pagedSource({ byteLength: bytes.length, version: 1, async read(offset, length) { return bytes.slice(offset, offset + length); } });
  assert.deepEqual(await searchBytes(source, "xyxy", { mode: "text" }), [SCAN_BYTES - 3, SCAN_BYTES - 1]);
  const first = await scanStrings(source, { maxStrings: 1 });
  assert.equal(first.strings[0].string, "xyxyxy");
  const second = await scanStrings(source, { startOffset: first.nextOffset, query: "😀tail" });
  assert.equal(second.strings[0].string, "abc€😀tail");
  assert.equal(second.strings[0].offset, SCAN_BYTES * 2 - 5);
  assert.equal(second.nextOffset, null);
  const incomplete = enc.encode("valid");
  assert.equal((await scanStrings(join(incomplete, Uint8Array.of(0xe2, 0x82)))).strings[0].string, "valid");
});

test("string filtering folds Greek final sigma symmetrically across chunk boundaries", async () => {
  const bytes = new Uint8Array(262160);
  // Σ begins in one scan chunk and ends in the next; ΟΣ is the recorded spelling.
  bytes.set(enc.encode("abΟΣcd"), 262139);
  const result = await scanStrings(bytes, { query: "ος" });
  assert.deepEqual(result.strings, [{ offset: 262139, string: "abΟΣcd", byteLength: 8, truncated: false }]);
  const reverse = await scanStrings(enc.encode("abοςcd"), { query: "ΟΣ" });
  assert.equal(reverse.strings[0].string, "abοςcd");
});
