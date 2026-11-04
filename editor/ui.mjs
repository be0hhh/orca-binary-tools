import { parseBinary, searchBytes, scanStrings } from "./binary-core.mjs";

const $ = (id) => document.getElementById(id);
const hasDocumentSession = typeof window.orca?.document?.session === "function";
const LIMIT = 64 * 1024 * 1024;
const PAGE_SIZE = 200;
const ROW_BYTES = 16;
const ROW_HEIGHT = 23;
const SECTIONS = ["sections", "symbols", "archive", "hex", "strings"];
const TITLES = {
  sections: "Sections",
  symbols: "Symbols",
  archive: "Archive objects",
  hex: "Hex",
  strings: "Strings",
};
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (ch) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        ch
      ],
  );
const hex = (value) =>
  `0x${Number(value).toString(16).toUpperCase().padStart(8, "0")}`;
const compact = (value) => {
  if (value == null) return "—";
  if (value < 1024) return `${value} B`;
  const unit = Math.min(3, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** unit).toFixed(2)} ${["B", "KiB", "MiB", "GiB"][unit]}`;
};
const sizeCell = (value) =>
  value == null
    ? "—"
    : `<span title="${esc(value.toLocaleString())} bytes">${esc(compact(value))}</span>`;
let current = null;
let parents = [];
let loadGeneration = 0;
let searchGeneration = 0;
let stringsGeneration = 0;
let searchController = null;
let stringsController = null;
let ui = freshUI();

function freshUI() {
  return {
    pane: "hex",
    filter: "",
    kind: "all",
    sort: "name",
    descending: false,
    page: 0,
    offset: 0,
    scroll: 0,
    inspector: innerWidth > 600,
    matches: [],
    matchIndex: -1,
    matchLength: 0,
    query: "",
    searchMode: "hex",
    strings: null,
    stringsNext: null,
    stringsCursors: [0],
    stringsQuery: null,
    stringsLoading: false,
  };
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").hidden = !message;
  $("notice").classList.toggle("error", error);
}
function stopTasks() {
  searchController?.abort();
  stringsController?.abort();
  searchGeneration++;
  stringsGeneration++;
  $("statusTask").textContent = "";
}
function makeCurrent(bytes, name) {
  let parsed;
  try {
    parsed = parseBinary(bytes);
  } catch (error) {
    parsed = {
      format: "RAW",
      architecture: "Unknown",
      bits: null,
      endian: null,
      fileSize: bytes.length,
      memorySize: null,
      sections: [],
      symbols: [],
      members: [],
      warnings: [`Could not parse structure: ${error.message}`],
    };
  }
  return { bytes, name, parsed };
}
function loadBytes(input, name = "", options = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength > LIMIT) {
    notice(
      "This file exceeds the 64 MiB inspection limit. No data was truncated or opened.",
      true,
    );
    return false;
  }
  loadGeneration++;
  stopTasks();
  if (!options.keepParents) parents = [];
  current = makeCurrent(bytes, name);
  ui = freshUI();
  const p = current.parsed;
  ui.pane =
    p.format === "AR" && p.members.length
      ? "archive"
      : ["ELF", "PE", "COFF"].includes(p.format) && p.symbols.length
        ? "symbols"
        : ["ELF", "PE", "COFF"].includes(p.format) && p.sections.length
          ? "sections"
          : "hex";
  $("tableFilter").value = "";
  $("symbolKind").value = "all";
  $("byteSearch").value = "";
  $("searchMode").value = "hex";
  $("offsetInput").value = "";
  $("hexViewport").scrollTop = 0;
  notice(current.parsed.warnings.join(" · "));
  render();
  return true;
}
function render() {
  renderNavigation();
  renderMetadata();
  $("emptyState").hidden = !hasDocumentSession || !!current?.bytes.length;
  for (const id of ["pane-table", "pane-hex"]) $(id).hidden = true;
  if (!current?.bytes.length) return;
  if (ui.pane === "hex") {
    $("pane-hex").hidden = false;
    renderHex();
    renderInspector();
  } else {
    $("pane-table").hidden = false;
    renderTable();
  }
}
function renderMetadata() {
  $("metadata").hidden = !current?.bytes.length;
  if (!current?.bytes.length) return;
  const p = current.parsed;
  const info = [
    p.format,
    p.architecture !== "Unknown" ? p.architecture : null,
    p.bits ? `${p.bits}-bit` : null,
    `${compact(p.fileSize)} on disk`,
    p.memorySize == null ? null : `${compact(p.memorySize)} image`,
  ].filter(Boolean);
  $("fileSummary").textContent = info.join(" · ");
  $("fileSummary").title =
    `${p.fileSize.toLocaleString()} bytes on disk. ${p.memorySize == null ? "No loaded image size declared." : `${p.memorySize.toLocaleString()} bytes declared by load headers, not process RAM.`}`;
  $("archiveBack").innerHTML =
    parents
      .map(
        (entry, index) =>
          `<button data-parent="${index}" title="Return to ${esc(entry.current.name || "archive")}">← ${esc(entry.current.name || "Archive")}</button>`,
      )
      .join("") +
    (parents.length
      ? `<span class="member-name" title="${esc(current.name)}">${esc(current.name)}</span>`
      : "");
  $("archiveBack").hidden = !parents.length;
}
function allowedSections() {
  if (!current?.bytes.length) return [];
  const p = current.parsed;
  return SECTIONS.filter((key) =>
    key === "sections"
      ? p.sections.length > 0
      : key === "symbols"
        ? p.symbols.length > 0
        : key === "archive"
          ? p.members.length > 0
          : true,
  );
}
function renderNavigation() {
  const available = allowedSections();
  $("navigation").hidden = !available.length;
  $("compactNavigation").hidden = !available.length;
  $("navigation").innerHTML = allowedSections()
    .map(
      (key) =>
        `<button data-pane="${key}" class="${ui.pane === key ? "active" : ""}" ${ui.pane === key ? 'aria-current="page"' : ""}>${TITLES[key]}</button>`,
    )
    .join("");
  $("compactNavigation").innerHTML = allowedSections()
    .map(
      (key) =>
        `<option value="${key}" ${ui.pane === key ? "selected" : ""}>${TITLES[key]}</option>`,
    )
    .join("");
}
function switchPane(pane) {
  if (!allowedSections().includes(pane)) return;
  if (ui.pane === "hex") {
    ui.scroll = $("hexViewport").scrollTop;
    if (pane !== "hex") {
      searchController?.abort();
      searchGeneration++;
      $("statusTask").textContent = "";
    }
  }
  if (ui.pane === "strings" && pane !== "strings") {
    stringsController?.abort();
    stringsGeneration++;
    ui.stringsLoading = false;
    $("statusTask").textContent = "";
  }
  if (pane === "strings") {
    stringsController?.abort();
    stringsGeneration++;
    ui.stringsLoading = false;
    ui.strings = null;
    ui.stringsNext = null;
    ui.stringsCursors = [0];
  }
  ui.pane = pane;
  ui.page = 0;
  ui.filter = "";
  ui.sort = pane === "strings" ? "offset" : "name";
  ui.descending = false;
  $("tableFilter").value = "";
  $("symbolKind").value = ui.kind;
  render();
  if (pane === "hex") {
    $("hexViewport").scrollTop = ui.scroll;
    renderHex();
  }
  if (
    pane === "strings" &&
    (ui.strings === null || ui.stringsQuery !== ui.filter) &&
    !ui.stringsLoading
  )
    void analyzeStrings();
}
function columns() {
  if (ui.pane === "sections")
    return [
      ["name", "Name"],
      ["type", "Type"],
      ["fileSize", "On disk"],
      ["memorySize", "In memory"],
      ["address", "Address"],
      ["offset", "File offset"],
      ["flags", "Flags"],
    ];
  if (ui.pane === "symbols")
    return [
      ["name", "Name"],
      ["kind", "Kind"],
      ["binding", "Binding"],
      ["visibility", "Visibility"],
      ["section", "Section"],
      ["address", "Address"],
      ["size", "Size"],
      ["offset", "File offset"],
      ["source", "Source"],
    ];
  if (ui.pane === "archive")
    return [
      ["name", "Object"],
      ["size", "On disk"],
      ["offset", "File offset"],
      ["service", "Type"],
      ["date", "Timestamp"],
    ];
  return [
    ["offset", "File offset"],
    ["string", "String"],
  ];
}
function tableRows() {
  const p = current.parsed;
  let rows =
    ui.pane === "sections"
      ? p.sections
      : ui.pane === "symbols"
        ? p.symbols
        : ui.pane === "archive"
          ? p.members
          : ui.strings || [];
  if (ui.pane === "strings") return { rows, total: rows.length };
  const q = ui.filter.toLocaleLowerCase();
  const total = rows.length;
  rows = rows.filter(
    (row) =>
      (!q ||
        String(row.name ?? row.string ?? "")
          .toLocaleLowerCase()
          .includes(q)) &&
      (ui.pane !== "symbols" ||
        ui.kind === "all" ||
        symbolCategory(row) === ui.kind),
  );
  rows = [...rows].sort((a, b) => {
    let x = a[ui.sort],
      y = b[ui.sort],
      comparison;
    if (x == null || y == null)
      comparison = x == null ? (y == null ? 0 : 1) : -1;
    else if (typeof x === "number" && typeof y === "number") comparison = x - y;
    else if (ui.sort === "address" && /^0x/i.test(x) && /^0x/i.test(y))
      comparison = BigInt(x) < BigInt(y) ? -1 : BigInt(x) > BigInt(y) ? 1 : 0;
    else
      comparison = String(x).localeCompare(String(y), undefined, {
        numeric: true,
      });
    return ui.descending ? -comparison : comparison;
  });
  return { rows, total };
}
function symbolCategory(symbol) {
  if (["FUNC", "IFUNC"].includes(symbol.kind)) return "function";
  if (["OBJECT", "TLS"].includes(symbol.kind)) return "data";
  if (symbol.kind === "import") return "import";
  if (symbol.kind.startsWith("export")) return "export";
  return "other";
}
function symbolOffset(symbol) {
  return symbol.offset ?? null;
}
function renderTable() {
  $("symbolKind").hidden = ui.pane !== "symbols";
  $("tableFilter").placeholder =
    ui.pane === "strings" ? "Filter strings…" : "Filter by name…";
  const { rows, total } = tableRows();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  if (ui.pane !== "strings") ui.page = Math.min(ui.page, pages - 1);
  $("tableCount").textContent =
    ui.pane === "strings"
      ? `${rows.length} on page ${ui.page + 1}${ui.stringsLoading ? " · scanning…" : ui.stringsNext == null ? " · end" : " · more available"}`
      : `${rows.length.toLocaleString()} / ${total.toLocaleString()}`;
  const cols = columns();
  const pageRows =
    ui.pane === "strings"
      ? rows
      : rows.slice(ui.page * PAGE_SIZE, (ui.page + 1) * PAGE_SIZE);
  const body = pageRows
    .map((row) => {
      const cells = cols
        .map(([key]) => {
          const value = row[key];
          let result;
          if (["fileSize", "memorySize", "size"].includes(key))
            result = sizeCell(value);
          else if (key === "offset") result = value == null ? "—" : hex(value);
          else if (key === "service") result = value ? "Metadata" : "Object";
          else if (key === "date")
            result =
              value === 0
                ? "Deterministic"
                : value == null
                  ? "—"
                  : esc(new Date(value * 1000).toLocaleString());
          else
            result =
              esc(value ?? "—") +
              (key === "string" && row.truncated
                ? " <span class=muted>… [preview; view bytes for full string]</span>"
                : "");
          return `<td class="${key === "name" ? "name" : key === "string" ? "string-value mono" : ["offset", "address", "size", "fileSize", "memorySize"].includes(key) ? "number" : ""}">${result}</td>`;
        })
        .join("");
      const offset = ui.pane === "symbols" ? symbolOffset(row) : row.offset;
      const actions =
        ui.pane === "archive"
          ? `<button data-member="${current.parsed.members.indexOf(row)}">Inspect</button>`
          : offset == null
            ? ""
            : `<button data-jump="${offset}"${ui.pane === "strings" ? ` data-length="${row.byteLength ?? new TextEncoder().encode(row.string).length}"` : ""}>View bytes</button>`;
      return `<tr>${cells}<td><div class="row-actions">${actions}</div></td></tr>`;
    })
    .join("");
  $("tableScroll").innerHTML =
    `<table><thead><tr>${cols.map(([key, title]) => `<th aria-sort="${ui.sort === key ? (ui.descending ? "descending" : "ascending") : "none"}"><button ${ui.pane === "strings" ? "disabled" : `data-sort="${key}"`}>${title}${ui.sort === key ? (ui.descending ? " ↓" : " ↑") : ""}</button></th>`).join("")}<th>Action</th></tr></thead><tbody>${body}</tbody></table>${rows.length ? "" : `<div class="empty">${ui.stringsLoading ? "Extracting strings…" : ui.filter ? "No matching results." : ui.pane === "symbols" ? "No symbols available. This file may be stripped or contain no symbol table." : "No entries in this file."}</div>`}`;
  if (ui.pane === "strings") {
    $("pagination").innerHTML =
      `<span>Page ${ui.page + 1} · file order</span><button id="previousPage" ${ui.page === 0 || ui.stringsLoading ? "disabled" : ""}>Previous</button><button id="nextPage" ${ui.stringsNext == null || ui.stringsLoading ? "disabled" : ""}>Next</button>`;
    return;
  }
  $("pagination").innerHTML =
    `<span>${rows.length ? `${ui.page * PAGE_SIZE + 1}–${Math.min((ui.page + 1) * PAGE_SIZE, rows.length)} of ${rows.length.toLocaleString()}` : "0 entries"}</span><button id="previousPage" ${ui.page === 0 ? "disabled" : ""}>Previous</button><button id="nextPage" ${ui.page >= pages - 1 ? "disabled" : ""}>Next</button>`;
}
function isMatch(offset) {
  const matches = ui.matches;
  let low = 0,
    high = matches.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (matches[mid] <= offset) low = mid + 1;
    else high = mid - 1;
  }
  return high >= 0 && offset < matches[high] + ui.matchLength;
}
function hexGeometry() {
  const totalHeight =
    Math.ceil((current?.bytes.length || 0) / ROW_BYTES) * ROW_HEIGHT;
  // Chromium caps layout heights. Compress the scrollbar while retaining real row pixels.
  const height = Math.min(totalHeight, 8_000_000);
  const viewportHeight = $("hexViewport").clientHeight;
  const scale = Math.max(
    1,
    (totalHeight - viewportHeight) / Math.max(1, height - viewportHeight),
  );
  return { height, scale };
}
function renderHex() {
  if (!current) return;
  const bytes = current.bytes,
    viewport = $("hexViewport");
  const total = Math.ceil(bytes.length / ROW_BYTES);
  const geometry = hexGeometry();
  const logicalScroll = viewport.scrollTop * geometry.scale;
  const start = Math.max(0, Math.floor(logicalScroll / ROW_HEIGHT) - 4);
  const end = Math.min(
    total,
    start + Math.ceil(viewport.clientHeight / ROW_HEIGHT) + 9,
  );
  $("hexSpacer").style.height = `${geometry.height}px`;
  $("hexRows").style.top =
    `${viewport.scrollTop + start * ROW_HEIGHT - logicalScroll}px`;
  let html = "";
  for (let row = start; row < end; row++) {
    const base = row * ROW_BYTES;
    let byteHtml = "",
      asciiHtml = "";
    for (let index = 0; index < ROW_BYTES; index++) {
      const offset = base + index,
        b = bytes[offset];
      if (offset >= bytes.length) {
        byteHtml += '<span class="hex-byte">&nbsp;</span>';
        continue;
      }
      const state = `${ui.offset === offset ? " selected" : ""}${isMatch(offset) ? " match" : ""}`;
      byteHtml += `<span class="hex-byte${b === 0 ? " zero" : b < 32 || b === 127 ? " control" : b > 126 ? " high" : ""}${state}" data-byte="${offset}" title="${hex(offset)} · ${b}">${b.toString(16).toUpperCase().padStart(2, "0")}</span>`;
      asciiHtml += `<span class="ascii-char${state}" data-byte="${offset}">${b >= 32 && b <= 126 ? esc(String.fromCharCode(b)) : "·"}</span>`;
    }
    html += `<div class="hex-row"><span class="hex-address">${hex(base)}</span><div class="hex-values">${byteHtml}</div><div class="hex-ascii">${asciiHtml}</div></div>`;
  }
  $("hexRows").innerHTML = html;
  $("inspector").hidden = !ui.inspector;
  $("toggleInspector").setAttribute("aria-expanded", String(ui.inspector));
  $("matchCount").textContent = ui.matches.length
    ? `${ui.matchIndex + 1} / ${ui.matches.length.toLocaleString()}`
    : "";
}
function inspectorRow(label, value) {
  return `<div class="inspector-row"><span>${label}</span><span>${esc(value)}</span></div>`;
}
function renderInspector() {
  if (!current?.bytes.length) return;
  const data = current.bytes,
    offset = ui.offset,
    view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const b = data[offset];
  let html = `<h2>Data inspector</h2><div class="muted mono">${hex(offset)}</div><h3>8-bit</h3>${inspectorRow("Hex", b.toString(16).toUpperCase().padStart(2, "0"))}${inspectorRow("Binary", b.toString(2).padStart(8, "0"))}${inspectorRow("Unsigned", b)}${inspectorRow("Signed", view.getInt8(offset))}${inspectorRow("ASCII", b >= 32 && b <= 126 ? String.fromCharCode(b) : "—")}`;
  for (const [bits, suffix] of [
    [16, "Int16"],
    [32, "Int32"],
    [64, "BigInt64"],
  ]) {
    const enough = offset + bits / 8 <= data.length;
    const unsigned = suffix.replace("Int", "Uint");
    html += `<h3>${bits}-bit integers</h3>`;
    for (const [label, little] of [
      ["LE", true],
      ["BE", false],
    ]) {
      html += inspectorRow(
        `Unsigned ${label}`,
        enough ? view[`get${unsigned}`](offset, little).toString() : "—",
      );
      html += inspectorRow(
        `Signed ${label}`,
        enough ? view[`get${suffix}`](offset, little).toString() : "—",
      );
    }
  }
  html += "<h3>Floating point</h3>";
  for (const bits of [32, 64])
    for (const [label, little] of [
      ["LE", true],
      ["BE", false],
    ])
      html += inspectorRow(
        `Float${bits} ${label}`,
        offset + bits / 8 <= data.length
          ? String(view[`getFloat${bits}`](offset, little))
          : "—",
      );
  $("inspector").innerHTML = html;
}
function jump(offset, length = 0) {
  if (
    !current ||
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset >= current.bytes.length
  ) {
    notice("This location has no bytes in the current file.", true);
    return;
  }
  if (ui.pane !== "hex") switchPane("hex");
  ui.offset = offset;
  if (length) {
    ui.matches = [offset];
    ui.matchIndex = 0;
    ui.matchLength = length;
  }
  const viewport = $("hexViewport"),
    top = Math.floor(offset / ROW_BYTES) * ROW_HEIGHT;
  const geometry = hexGeometry();
  const logicalScroll = viewport.scrollTop * geometry.scale;
  if (
    top < logicalScroll ||
    top + ROW_HEIGHT > logicalScroll + viewport.clientHeight
  )
    viewport.scrollTop = Math.max(0, top - ROW_HEIGHT * 3) / geometry.scale;
  ui.scroll = viewport.scrollTop;
  renderHex();
  renderInspector();
}
function inspectMember(index) {
  const member = current?.parsed.members[index];
  if (!member) return;
  const snapshot = {
    current,
    ui: {
      ...ui,
      scroll: $("hexViewport").scrollTop,
      tableScroll: $("tableScroll").scrollTop,
    },
    notice: $("notice").textContent,
  };
  parents.push(snapshot);
  loadBytes(
    member.bytes ??
      current.bytes.subarray(member.offset, member.offset + member.size),
    member.name,
    { keepParents: true },
  );
}
function returnParent(index) {
  loadGeneration++;
  const target = parents[index];
  if (!target) return;
  stopTasks();
  parents = parents.slice(0, index);
  current = target.current;
  ui = target.ui;
  $("tableFilter").value = ui.filter;
  $("symbolKind").value = ui.kind;
  $("byteSearch").value = ui.query;
  $("searchMode").value = ui.searchMode;
  ui.stringsLoading = false;
  notice(target.notice);
  render();
  $("hexViewport").scrollTop = ui.scroll;
  $("tableScroll").scrollTop = ui.tableScroll || 0;
  if (ui.pane === "hex") renderHex();
  if (ui.pane === "strings" && ui.strings === null) void analyzeStrings();
}
async function runSearch() {
  if (!current) return;
  searchController?.abort();
  searchController = new AbortController();
  const signal = searchController.signal,
    generation = ++searchGeneration;
  const mode = $("searchMode").value;
  const query =
    mode === "hex" ? $("byteSearch").value.trim() : $("byteSearch").value;
  ui.query = query;
  ui.searchMode = mode;
  ui.matches = [];
  ui.matchIndex = -1;
  if (!query) {
    ui.matchLength = 0;
    $("statusTask").textContent = "";
    renderHex();
    return;
  }
  notice(current.parsed.warnings.join(" · "));
  $("statusTask").textContent = "Searching…";
  try {
    const matches = await searchBytes(current.bytes, query, {
      mode,
      signal,
      maxMatches: 100000,
    });
    if (signal.aborted || generation !== searchGeneration) return;
    ui.matches = matches;
    ui.matchIndex = matches.length ? 0 : -1;
    ui.matchLength =
      mode === "hex"
        ? query.replace(/\s/g, "").length / 2
        : new TextEncoder().encode(query).length;
    $("statusTask").textContent = matches.length
      ? `${matches.length.toLocaleString()} matches${matches.length === 100000 ? " (limit reached; narrow the query)" : ""}`
      : "No matches";
    if (matches.length) jump(matches[0]);
    else renderHex();
  } catch (error) {
    if (!signal.aborted && generation === searchGeneration) {
      notice(error.message, true);
      $("statusTask").textContent = "";
      renderHex();
    }
  }
}
async function analyzeStrings() {
  if (!current) return;
  stringsController?.abort();
  stringsController = new AbortController();
  const signal = stringsController.signal,
    generation = ++stringsGeneration;
  ui.stringsLoading = true;
  ui.strings = [];
  const query = ui.filter;
  const cursor = ui.stringsCursors[ui.page] ?? 0;
  $("statusTask").textContent = "Scanning UTF-8 strings…";
  if (ui.pane === "strings") renderTable();
  try {
    const result = await scanStrings(current.bytes, {
      startOffset: cursor,
      query,
      minLength: 4,
      encoding: "utf8",
      signal,
      maxStrings: PAGE_SIZE,
    });
    if (signal.aborted || generation !== stringsGeneration) return;
    ui.strings = result.strings;
    ui.stringsNext = result.nextOffset;
    ui.stringsQuery = query;
    ui.stringsLoading = false;
    $("statusTask").textContent = "";
    if (ui.pane === "strings") renderTable();
  } catch (error) {
    if (!signal.aborted && generation === stringsGeneration) {
      ui.stringsLoading = false;
      notice(error.message, true);
      $("statusTask").textContent = "";
    }
  }
}
async function demo(name) {
  const generation = ++loadGeneration;
  try {
    const response = await fetch(`../samples/${name}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const bytes = await response.arrayBuffer();
    if (generation === loadGeneration) loadBytes(bytes, name);
  } catch (error) {
    if (generation === loadGeneration)
      notice(`Could not open demonstration: ${error.message}`, true);
  }
}
$("navigation").addEventListener("click", (event) => {
  const button = event.target.closest("[data-pane]");
  if (button) switchPane(button.dataset.pane);
});
$("compactNavigation").addEventListener("change", (event) =>
  switchPane(event.target.value),
);
$("archiveBack").addEventListener("click", (event) => {
  const button = event.target.closest("[data-parent]");
  if (button) returnParent(Number(button.dataset.parent));
});
$("tableScroll").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  if (button.dataset.sort) {
    ui.descending = ui.sort === button.dataset.sort ? !ui.descending : false;
    ui.sort = button.dataset.sort;
    ui.page = 0;
    renderTable();
  } else if (button.dataset.member != null)
    inspectMember(Number(button.dataset.member));
  else if (button.dataset.jump != null)
    jump(Number(button.dataset.jump), Number(button.dataset.length || 0));
});
$("pagination").addEventListener("click", (event) => {
  if (event.target.disabled) return;
  if (event.target.id === "previousPage") ui.page--;
  else if (event.target.id === "nextPage") {
    if (ui.pane === "strings")
      ui.stringsCursors = [
        ...ui.stringsCursors.slice(0, ui.page + 1),
        ui.stringsNext,
      ];
    ui.page++;
  } else return;
  if (ui.pane === "strings") void analyzeStrings();
  else renderTable();
  $("tableScroll").scrollTop = 0;
});
$("tableFilter").addEventListener("input", (event) => {
  ui.filter = event.target.value;
  ui.page = 0;
  if (ui.pane === "strings") {
    ui.stringsCursors = [0];
    ui.stringsNext = null;
    void analyzeStrings();
  } else renderTable();
});
$("symbolKind").addEventListener("change", (event) => {
  ui.kind = event.target.value;
  ui.page = 0;
  renderTable();
});
$("hexViewport").addEventListener(
  "scroll",
  () => {
    ui.scroll = $("hexViewport").scrollTop;
    if (ui.pane === "hex") renderHex();
  },
  { passive: true },
);
$("hexRows").addEventListener("click", (event) => {
  const byte = event.target.closest("[data-byte]");
  if (byte) {
    ui.offset = Number(byte.dataset.byte);
    renderHex();
    renderInspector();
  }
});
$("hexViewport").addEventListener("keydown", (event) => {
  const delta = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -16, ArrowDown: 16 }[
    event.key
  ];
  if (delta != null && current?.bytes.length) {
    event.preventDefault();
    jump(Math.max(0, Math.min(current.bytes.length - 1, ui.offset + delta)));
  }
});
$("toggleInspector").addEventListener("click", () => {
  ui.inspector = !ui.inspector;
  renderHex();
});
$("findBytes").addEventListener("click", () => void runSearch());
$("byteSearch").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void runSearch();
  }
});
$("searchMode").addEventListener("change", (event) => {
  $("byteSearch").placeholder =
    event.target.value === "hex" ? "7F 45 4C 46" : "Search UTF-8 text…";
});
function nextMatch(direction) {
  if (!ui.matches.length) return;
  ui.matchIndex =
    (ui.matchIndex + direction + ui.matches.length) % ui.matches.length;
  jump(ui.matches[ui.matchIndex]);
}
$("previousMatch").addEventListener("click", () => nextMatch(-1));
$("nextMatch").addEventListener("click", () => nextMatch(1));
$("offsetInput").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  const raw = event.target.value.trim();
  if (!/^(?:0x[\da-f]+|\d+)$/i.test(raw)) {
    notice(
      "Enter a decimal offset or a hexadecimal offset beginning with 0x.",
      true,
    );
    return;
  }
  jump(Number(raw));
});
$("demoObject").addEventListener("click", () => void demo("sample.o"));
$("demoArchive").addEventListener("click", () => void demo("sample.a"));
new ResizeObserver(() => {
  if (ui.pane === "hex") renderHex();
}).observe($("hexViewport"));
render();
if (hasDocumentSession) {
  const normalize = (event) => {
    if (event?.bytes instanceof ArrayBuffer) return { bytes: event.bytes };
    if (ArrayBuffer.isView(event?.bytes))
      return {
        bytes: event.bytes.buffer.slice(
          event.bytes.byteOffset,
          event.bytes.byteOffset + event.bytes.byteLength,
        ),
      };
    return { error: "invalid-bytes" };
  };
  window.orca.document
    .session({
      decode: normalize,
      encode: (value) => ({ kind: "bytes", bytes: value.bytes }),
    })
    .then((session) => {
      const replace = (value) => {
        if (value?.bytes) {
          loadGeneration++;
          loadBytes(value.bytes);
        }
      };
      replace(session.value);
      session.onReplace(replace);
    })
    .catch((error) =>
      notice(`Could not load the Orca document: ${error.message}.`, true),
    );
}
