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

async function mount(bytes, { host = true, initialEvent } = {}) {
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
  const sortStats = { collators: 0, comparisons: 0 };
  const Collator = window.Intl.Collator;
  window.Intl.Collator = function (...args) {
    sortStats.collators++;
    const collator = new Collator(...args);
    return { compare(a, b) { sortStats.comparisons++; return collator.compare(a, b); } };
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
            value: initialEvent ? options.decode(initialEvent) : delivered(bytes),
            onReplace(handler) {
              replace = handler;
            },
          };
        },
      },
    };
  window.eval(source);
  await tick();
  await tick();
  const $ = (id) => window.document.getElementById(id);
  return {
    dom,
    window,
    sortStats,
    deliver: (value) => replace(delivered(value)),
    $,
    replace: async (value) => {
      replace(delivered(value));
      await tick();
      await tick();
    },
    close: () => {
      window.dispatchEvent(new window.Event("pagehide"));
      window.close();
    },
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
function chooseFile(app, file) {
  Object.defineProperty(app.$("filePicker"), "files", {
    configurable: true,
    value: file ? [file] : [],
  });
  app.$("filePicker").dispatchEvent(new app.window.Event("change"));
}
function selectedFile(name, bytes) {
  return {
    name,
    size: bytes.byteLength,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
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

test("empty host document offers only file selection without application chrome", async () => {
  const app = await mount(new Uint8Array());
  try {
    assert.equal(app.$("emptyState").hidden, false);
    assert.equal(app.$("navigation").hidden, true);
    assert.equal(app.$("metadata").hidden, false);
    assert.equal(app.$("openFile").hidden, false);
    assert.equal(app.$("openFile").disabled, false);
    assert.equal(app.$("filePicker").accept, "");
    assert.equal(
      app.window.document.querySelector(
        "header,footer,h1,#welcome,#pane-overview,#dropHint",
      ),
      null,
    );
    assert.doesNotMatch(
      app.window.document.body.textContent,
      /Binary document|Drop a file/,
    );
    assert.equal(app.$("demoObject"), null);
    assert.equal(app.$("demoArchive"), null);
  } finally {
    app.close();
  }
});

test("without an Orca document session the frame does not offer a standalone file-opening fallback", async () => {
  const app = await mount(new Uint8Array(), { host: false });
  try {
    assert.equal(app.$("emptyState").hidden, true);
    assert.equal(app.$("navigation").hidden, true);
    assert.equal(app.$("openFile").hidden, true);
    assert.equal(app.$("filePicker").disabled, true);
  } finally {
    app.close();
  }
});

test("malformed initial bytes finish loading with a readable error and file picker", async () => {
  const app = await mount(object, { initialEvent: { bytes: "invalid" } });
  try {
    assert.match(app.$("notice").textContent, /Could not read binary bytes/);
    assert.doesNotMatch(app.$("emptyHint").textContent, /Opening/);
    assert.equal(app.$("openFile").hidden, false);
    assert.equal(app.$("openFile").disabled, false);
  } finally {
    app.close();
  }
});

test("file selection reuses the inspector, keeps its name, and does not write the host document", async () => {
  const app = await mount(new Uint8Array());
  try {
    chooseFile(app, selectedFile("program-without-extension", object));
    await tick();
    assert.equal(active(app.$), "symbols");
    assert.match(app.$("tableScroll").textContent, /_start/);
    assert.match(app.$("fileSummary").textContent, /program-without-extension.*ELF/);
    assert.equal(app.$("filePicker").value, "");
    chooseFile(app, selectedFile("empty", new Uint8Array()));
    await tick();
    assert.match(app.$("fileSummary").textContent, /empty.*0 B on disk/);
    assert.equal(app.$("fileSummary").hidden, false);
    await app.replace(archive);
    assert.equal(active(app.$), "archive");
    assert.doesNotMatch(app.$("fileSummary").textContent, /program-without-extension|empty/);
  } finally {
    app.close();
  }
});

test("cancel, read errors and oversized selections preserve the previous inspection", async () => {
  const app = await mount(object);
  try {
    const summary = app.$("fileSummary").textContent;
    chooseFile(app, null);
    chooseFile(app, { name: "unreadable", size: 1, arrayBuffer: async () => { throw new Error("read refused"); } });
    await tick();
    assert.match(app.$("notice").textContent, /unreadable.*read refused/);
    chooseFile(app, { name: "large", size: 64 * 1024 * 1024 + 1, arrayBuffer: () => { assert.fail("oversized file must not be read"); } });
    await tick();
    assert.match(app.$("notice").textContent, /exceeds the 64 MiB/);
    assert.equal(app.$("fileSummary").textContent, summary);
    assert.equal(active(app.$), "symbols");
  } finally {
    app.close();
  }
});

test("new selections and host replacements supersede pending file reads", async () => {
  const app = await mount(object);
  try {
    let first;
    chooseFile(app, { name: "old", size: object.length, arrayBuffer: () => new Promise((resolve) => { first = resolve; }) });
    chooseFile(app, selectedFile("new", archive));
    await tick();
    first(object.buffer);
    await tick();
    assert.match(app.$("fileSummary").textContent, /new.*AR/);
    let second;
    chooseFile(app, { name: "pending", size: object.length, arrayBuffer: () => new Promise((resolve) => { second = resolve; }) });
    await app.replace(new Uint8Array([65, 66, 67]));
    second(object.buffer);
    await tick();
    assert.equal(active(app.$), "hex");
    assert.match(app.$("fileSummary").textContent, /3 B on disk/);
    assert.doesNotMatch(app.$("fileSummary").textContent, /pending/);
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
    const comparisons = app.sortStats.comparisons;
    assert.equal(app.sortStats.collators, 1);
    app.$("nextPage").click();
    assert.equal(app.sortStats.comparisons, comparisons);
    assert.equal(app.$("tableScroll").querySelector("tbody button"), null);
    assert.equal(app.$("tableScroll").querySelector("[data-member]").tagName, "A");
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

test("document replacement aborts old string scans while keeping the chosen view", async () => {
  const app = await mount(new Uint8Array(2 * 1024 * 1024).fill(65));
  try {
    selectPane(app, "strings");
    await app.replace(object);
    await tick();
    assert.equal(active(app.$), "strings");
    const deadline = Date.now() + 2000;
    while (app.$("statusTask").textContent && Date.now() < deadline) await tick();
    assert.equal(app.$("statusTask").textContent, "");
    assert.match(app.$("tableScroll").textContent, /_start/);
  } finally {
    app.close();
  }
});

test("host updates preserve the selected section, filter, and table position", async () => {
  const app = await mount(object);
  try {
    selectPane(app, "sections");
    filter(app, ".text");
    app.$("tableScroll").scrollTop = 73;
    await app.replace(object);
    assert.equal(active(app.$), "sections");
    assert.equal(app.$("tableFilter").value, ".text");
    assert.equal(app.$("tableScroll").scrollTop, 73);
    assert.match(app.$("tableScroll").textContent, /\.text/);
    assert.equal(app.$("openFile").hidden, true);
    assert.equal(app.$("findBytes"), null);
    assert.equal(app.$("tableScroll").querySelector("tbody button"), null);
    assert.equal(app.$("tableScroll").querySelector("a[data-jump]").getAttribute("href"), "#");
    app.$("tableScroll").querySelector("a[data-jump]").click();
    assert.equal(active(app.$), "hex");
  } finally {
    app.close();
  }
});

test("a pending large document cannot replace a newer automatic open", async () => {
  const app = await mount(object);
  try {
    app.deliver(new Uint8Array(2 * 1024 * 1024));
    assert.match(app.$("statusTask").textContent, /Opening/);
    app.deliver(archive);
    await tick();
    await tick();
    assert.equal(active(app.$), "archive");
    assert.match(app.$("fileSummary").textContent, /AR/);
    assert.equal(app.$("statusTask").textContent, "");
  } finally {
    app.close();
  }
});

test("an unavailable previous pane starts the new document without a stale filter", async () => {
  const app = await mount(object);
  try {
    filter(app, "_start");
    await app.replace(coffWithoutSymbols());
    assert.equal(active(app.$), "sections");
    assert.equal(app.$("tableFilter").value, "");
    assert.match(app.$("tableScroll").textContent, /\.text/);
  } finally {
    app.close();
  }
});

test("hex search keeps whitespace text queries and rejects replacement above64MiB without truncation", async () => {
  const app = await mount(new Uint8Array([65, 32, 66]));
  try {
    app.$("searchMode").value = "text";
    app.$("byteSearch").value = " ";
    app.$("byteSearch").dispatchEvent(new app.window.KeyboardEvent("keydown", { key: "Enter" }));
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
    app.$("byteSearch").dispatchEvent(new app.window.KeyboardEvent("keydown", { key: "Enter" }));
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

test("hex selection exposes exact offsets and values and supports file/row keyboard navigation", async () => {
  const bytes = new Uint8Array(67);
  bytes[66] = 0x7f;
  const app = await mount(bytes);
  try {
    const viewport = app.$("hexViewport");
    Object.defineProperty(viewport, "clientHeight", { value: 76 });
    viewport.style.lineHeight = "19px";
    const key = (value, ctrlKey = false) => viewport.dispatchEvent(
      new app.window.KeyboardEvent("keydown", { key: value, ctrlKey, bubbles: true }),
    );
    key("End", true);
    const selected = app.$("hexRows").querySelector('[aria-selected="true"]');
    assert.equal(selected.dataset.byte, "66");
    assert.match(selected.getAttribute("aria-label"), /0x00000042, hex 7F, decimal 127/);
    assert.equal(viewport.getAttribute("aria-activedescendant"), selected.id);
    assert.equal(viewport.getAttribute("aria-rowcount"), "5");
    assert.match(app.$("inspector").textContent, /0x00000042/);
    key("Home");
    assert.equal(viewport.getAttribute("aria-activedescendant"), "byte-64");
    key("Home", true);
    assert.equal(viewport.getAttribute("aria-activedescendant"), "byte-0");
    app.$("hexRows").querySelector('[data-byte="3"]').click();
    assert.equal(app.window.document.activeElement, viewport);
    key("ArrowRight");
    assert.equal(viewport.getAttribute("aria-activedescendant"), "byte-4");
  } finally {
    app.close();
  }
});

test("hex virtual scrolling reaches the last byte at different line heights and after geometry changes", async () => {
  const bytes = new Uint8Array(8 * 1024 * 1024 + 3);
  bytes[bytes.length - 1] = 0xab;
  const app = await mount(bytes);
  try {
    const viewport = app.$("hexViewport");
    Object.defineProperty(viewport, "clientHeight", { value: 320 });
    for (const height of [19, 27, 32]) {
      viewport.style.lineHeight = `${height}px`;
      viewport.dispatchEvent(new app.window.KeyboardEvent("keydown", { key: "Home", ctrlKey: true }));
      viewport.dispatchEvent(new app.window.KeyboardEvent("keydown", { key: "End", ctrlKey: true }));
      const last = app.$("hexRows").querySelector(`[data-byte="${bytes.length - 1}"]`);
      assert.ok(last, `last byte rendered at ${height}px line height`);
      assert.equal(last.textContent, "AB");
      assert.equal(last.getAttribute("aria-selected"), "true");
      assert.match(app.$("inspector").textContent, /0x00800002/);
      assert.ok(app.$("hexRows").children.length < 40, "only visible rows are painted");
      const spacerHeight = parseFloat(app.$("hexSpacer").style.height);
      const scale = (Math.ceil(bytes.length / 16) * height - 320) / (spacerHeight - 320);
      const rowTop = parseFloat(app.$("hexRows").style.top)
        + (Number(last.closest('[role="row"]').getAttribute("aria-rowindex")) - Number(app.$("hexRows").firstElementChild.getAttribute("aria-rowindex"))) * height;
      assert.ok(rowTop >= viewport.scrollTop && rowTop + height <= viewport.scrollTop + 320);
      assert.ok(scale > 1, "large file uses the compressed scrollbar");
    }
    viewport.scrollTop = 0;
    viewport.dispatchEvent(new app.window.Event("scroll"));
    assert.equal(viewport.hasAttribute("aria-activedescendant"), false, "no dangling descendant when selection is offscreen");
  } finally {
    app.close();
  }
});
