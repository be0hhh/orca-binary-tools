import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";
import {
  parseBinary,
  searchBytes,
  scanStrings,
} from "../editor/binary-core.mjs";

const html = await readFile(
  new URL("../editor/index.html", import.meta.url),
  "utf8",
);
const source = (
  await readFile(new URL("../editor/ui.mjs", import.meta.url), "utf8")
).replace(
  /^import \{[^}]+\} from "\.\/binary-core\.mjs";/,
  "const { parseBinary, searchBytes, scanStrings } = window.testCore;",
);
const object = new Uint8Array(
  await readFile(new URL("../samples/sample.o", import.meta.url)),
);
const archive = new Uint8Array(
  await readFile(new URL("../samples/sample.a", import.meta.url)),
);
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

async function mount(bytes, { host = true } = {}) {
  const dom = new JSDOM(html, {
    runScripts: "outside-only",
    url: "https://plugin.invalid/editor/index.html",
  });
  const { window } = dom;
  window.testCore = { parseBinary, searchBytes, scanStrings };
  // The real core module shares the frame realm; use the same byte constructors here.
  window.Uint8Array = Uint8Array;
  window.ArrayBuffer = ArrayBuffer;
  window.DataView = DataView;
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  window.ResizeObserver = class {
    observe() {}
  };
  let replace;
  let options;
  const delivered = (value) =>
    options.decode({ bytes: new window.Uint8Array(value) });
  if (host)
    window.orca = {
      document: {
        session: async (decodeOptions) => {
          options = decodeOptions;
          return {
            value: delivered(bytes),
            onReplace(handler) {
              replace = handler;
            },
          };
        },
      },
    };
  window.fetch = async (url) => {
    const data = await readFile(
      new URL(`../${url.replace(/^\.\.\//, "")}`, import.meta.url),
    );
    return {
      ok: true,
      arrayBuffer: async () => new window.Uint8Array(data).buffer,
    };
  };
  window.eval(source);
  await tick();
  const $ = (id) => window.document.getElementById(id);
  return {
    dom,
    window,
    $,
    replace: async (value) => {
      replace(delivered(value));
      await tick();
    },
    close: () => window.close(),
  };
}
function active($) {
  return $("navigation").querySelector("[aria-current=page]")?.dataset.pane;
}
function filter(app, value) {
  app.$("tableFilter").value = value;
  app
    .$("tableFilter")
    .dispatchEvent(new app.window.Event("input", { bubbles: true }));
}
function selectPane(app, pane) {
  app.$("navigation").querySelector(`[data-pane=${pane}]`).click();
}
function coffWithoutSymbols() {
  const b = new Uint8Array(64),
    v = new DataView(b.buffer);
  v.setUint16(0, 0x8664, true);
  v.setUint16(2, 1, true);
  b.set(new TextEncoder().encode(".text"), 20);
  v.setUint32(36, 4, true);
  v.setUint32(40, 60, true);
  v.setUint32(56, 0x60000020, true);
  return b;
}
function peWithoutSymbols() {
  const b = new Uint8Array(356),
    v = new DataView(b.buffer);
  b.set([0x4d, 0x5a]);
  v.setUint32(60, 64, true);
  b.set([0x50, 0x45, 0, 0], 64);
  v.setUint16(68, 0x14c, true);
  v.setUint16(70, 1, true);
  v.setUint16(84, 224, true);
  v.setUint16(88, 0x10b, true);
  v.setUint32(88 + 56, 4096, true);
  b.set(new TextEncoder().encode(".text"), 312);
  v.setUint32(320, 4, true);
  v.setUint32(328, 4, true);
  v.setUint32(332, 352, true);
  return b;
}

test("actual session UI defaults to ELF symbols and hides unavailable archive navigation", async () => {
  const app = await mount(object);
  try {
    assert.equal(active(app.$), "symbols");
    assert.equal(app.$("pane-table").hidden, false);
    assert.ok(app.$("tableScroll").textContent.includes("_start"));
    assert.equal(
      app.$("navigation").querySelector("[data-pane=archive]"),
      null,
    );
    assert.match(app.$("fileSummary").textContent, /ELF.*on disk/);
  } finally {
    app.close();
  }
});

test("COFF and PE without symbols default directly to sections", async () => {
  for (const bytes of [coffWithoutSymbols(), peWithoutSymbols()]) {
    const app = await mount(bytes);
    try {
      assert.equal(active(app.$), "sections");
      assert.equal(
        app.$("navigation").querySelector("[data-pane=symbols]"),
        null,
      );
      assert.match(app.$("tableScroll").textContent, /\.text/);
    } finally {
      app.close();
    }
  }
});

test("unknown, Mach-O and malformed header bytes retain hex and show parser warnings", async () => {
  for (const bytes of [
    new Uint8Array([1, 2, 3, 4]),
    new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]),
    new Uint8Array([0x7f, 0x45, 0x4c, 0x46]),
  ]) {
    const app = await mount(bytes);
    try {
      assert.equal(active(app.$), "hex");
      assert.equal(app.$("pane-hex").hidden, false);
      assert.equal(
        app.$("navigation").querySelector("[data-pane=sections]"),
        null,
      );
      if (bytes[0] !== 1) assert.equal(app.$("notice").hidden, false);
    } finally {
      app.close();
    }
  }
});

test("empty host document is a compact hint with demos, no independent application chrome", async () => {
  const app = await mount(new Uint8Array());
  try {
    assert.equal(app.$("emptyState").hidden, false);
    assert.equal(app.$("navigation").hidden, true);
    assert.equal(app.$("metadata").hidden, true);
    assert.equal(
      app.window.document.querySelector(
        "header,footer,h1,input[type=file],#welcome,#pane-overview,#openFile,#dropHint",
      ),
      null,
    );
    assert.doesNotMatch(
      app.window.document.body.textContent,
      /Binary document|Open file|Drop a file/,
    );
    app.$("demoObject").click();
    await tick();
    await tick();
    assert.equal(active(app.$), "symbols");
  } finally {
    app.close();
  }
});

test("without an Orca document session the frame does not offer a standalone file-opening fallback", async () => {
  const app = await mount(new Uint8Array(), { host: false });
  try {
    assert.equal(app.$("emptyState").hidden, true);
    assert.equal(app.$("navigation").hidden, true);
    assert.equal(app.window.document.querySelector("input[type=file]"), null);
  } finally {
    app.close();
  }
});

test("archive opens members immediately and back restores filter, order, page and scroll", async () => {
  const app = await mount(archive);
  try {
    assert.equal(active(app.$), "archive");
    filter(app, "sample.o");
    app.$("tableScroll").querySelector("[data-sort=size]").click();
    app.$("tableScroll").scrollTop = 127;
    const count = app.$("tableCount").textContent;
    app.$("tableScroll").querySelector("[data-member]").click();
    assert.equal(active(app.$), "symbols");
    assert.equal(app.$("archiveBack").hidden, false);
    app.$("archiveBack").querySelector("button").click();
    assert.equal(active(app.$), "archive");
    assert.equal(app.$("tableFilter").value, "sample.o");
    assert.equal(app.$("tableCount").textContent, count);
    assert.equal(app.$("tableScroll").scrollTop, 127);
    assert.match(
      app.$("tableScroll").querySelector("[data-sort=size]").textContent,
      /↑/,
    );
    assert.match(app.$("pagination").textContent, /1–1 of 1/);
    assert.equal(app.$("archiveBack").hidden, true);
  } finally {
    app.close();
  }
});

test("archive back restores a later page rather than returning to the first members", async () => {
  const encoder = new TextEncoder();
  const chunks = [encoder.encode("!<arch>\n")];
  for (let index = 0; index < 205; index++) {
    const header = `${`member-${index}.o/`.padEnd(16)}${"0".padEnd(12)}${"0".padEnd(6)}${"0".padEnd(6)}${"100644".padEnd(8)}${String(object.length).padEnd(10)}\x60\n`;
    chunks.push(encoder.encode(header), object);
    if (object.length % 2) chunks.push(encoder.encode("\n"));
  }
  const bytes = new Uint8Array(
    chunks.reduce((length, chunk) => length + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const app = await mount(bytes);
  try {
    filter(app, "member-");
    app.$("tableScroll").querySelector("[data-sort=name]").click();
    app.$("nextPage").click();
    assert.match(app.$("pagination").textContent, /201–205 of 205/);
    app.$("tableScroll").scrollTop = 80;
    app.$("tableScroll").querySelector("[data-member]").click();
    app.$("archiveBack").querySelector("button").click();
    assert.equal(active(app.$), "archive");
    assert.equal(app.$("tableFilter").value, "member-");
    assert.match(app.$("pagination").textContent, /201–205 of 205/);
    assert.match(
      app.$("tableScroll").querySelector("[data-sort=name]").textContent,
      /↓/,
    );
    assert.equal(app.$("tableScroll").scrollTop, 80);
  } finally {
    app.close();
  }
});

test("document replacement aborts pending string scans and selects the new document default", async () => {
  const app = await mount(new Uint8Array(2 * 1024 * 1024).fill(65));
  try {
    selectPane(app, "strings");
    await app.replace(object);
    await tick();
    assert.equal(active(app.$), "symbols");
    assert.equal(app.$("statusTask").textContent, "");
    assert.match(app.$("tableScroll").textContent, /_start/);
  } finally {
    app.close();
  }
});

test("hex search keeps whitespace text queries and rejects replacement above64MiB without truncation", async () => {
  const app = await mount(new Uint8Array([65, 32, 66]));
  try {
    app.$("searchMode").value = "text";
    app.$("byteSearch").value = " ";
    app.$("findBytes").click();
    await tick();
    await tick();
    assert.match(app.$("matchCount").textContent, /1 \/ 1/);
    await app.replace(new Uint8Array(64 * 1024 * 1024 + 1));
    assert.match(app.$("notice").textContent, /exceeds the 64 MiB/);
    assert.match(app.$("fileSummary").textContent, /3 B on disk/);
  } finally {
    app.close();
  }
});

test("leaving Hex cancels a pending search without switching back from Strings", async () => {
  const app = await mount(new Uint8Array(8 * 1024 * 1024));
  try {
    app.$("byteSearch").value = "00";
    app.$("findBytes").click();
    selectPane(app, "strings");
    for (let i = 0; i < 20; i++) await tick();
    assert.equal(active(app.$), "strings");
    assert.equal(app.$("pane-hex").hidden, true);
    await app.replace(object);
  } finally {
    app.close();
  }
});

test("frame surface uses paired Orca card tokens and excludes removed chrome styling", async () => {
  const css = await readFile(
    new URL("../editor/ui.css", import.meta.url),
    "utf8",
  );
  assert.match(css, /--bg:\s*var\(--orca-card,/);
  assert.match(css, /--fg:\s*var\(--orca-card-foreground,/);
  assert.doesNotMatch(css, /\.welcome|\.metrics|\.toolbar\s*\{|footer\s*\{/);
});
