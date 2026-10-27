// Self-contained XLSX (OOXML) reader and network-flow normalizer for the browser prototype.

// No CDN, remote requests, executable macros or original evidence persistence.

function normalizeXlsxPath(path) {
  const parts = [];
  for (const part of path.replace(/\\/g, "/").replace(/^\/+/, "").split("/")) {
    if (part === "..") parts.pop();
    else if (part && part !== ".") parts.push(part);
  }
  return parts.join("/");
}

async function openXlsxZip(file) {
  const raw = new Uint8Array(await file.arrayBuffer());
  const dv = new DataView(raw.buffer);
  if (raw.length < 22 || dv.getUint32(0, true) !== 0x04034b50) throw new Error("Not a valid Excel .xlsx ZIP workbook.");
  let eocd = -1;
  for (let i = raw.length - 22; i >= Math.max(0, raw.length - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("Excel workbook ZIP directory is missing.");
  const count = dv.getUint16(eocd + 10, true);
  let offset = dv.getUint32(eocd + 16, true);
  const entries = new Map();
  let expanded = 0;
  const decoder = new TextDecoder("utf-8");
  for (let i = 0; i < count; i++) {
    if (offset + 46 > raw.length || dv.getUint32(offset, true) !== 0x02014b50) throw new Error("Corrupted Excel workbook directory.");
    const flags = dv.getUint16(offset + 8, true);
    const method = dv.getUint16(offset + 10, true);
    const compressed = dv.getUint32(offset + 20, true);
    const uncompressed = dv.getUint32(offset + 24, true);
    const filenameLength = dv.getUint16(offset + 28, true);
    const extraLength = dv.getUint16(offset + 30, true);
    const commentLength = dv.getUint16(offset + 32, true);
    const localOffset = dv.getUint32(offset + 42, true);
    if (offset + 46 + filenameLength + extraLength + commentLength > raw.length) throw new Error("Corrupted workbook entry.");
    const name = normalizeXlsxPath(decoder.decode(raw.subarray(offset + 46, offset + 46 + filenameLength)));
    if (name && !name.endsWith("/")) {
      if (uncompressed > 32 * 1024 * 1024) throw new Error("Workbook XML part exceeds the 32 MB safety limit.");
      expanded += uncompressed;
      if (expanded > 96 * 1024 * 1024) throw new Error("Workbook exceeds the 96 MB decompressed safety limit.");
      entries.set(name, {flags, method, compressed, uncompressed, localOffset});
    }
    offset += 46 + filenameLength + extraLength + commentLength;
  }
  return async function read(path) {
    const entry = entries.get(normalizeXlsxPath(path));
    if (!entry) return null;
    if (entry.flags & 1) throw new Error("Password-protected Excel files cannot be parsed in this prototype.");
    if (entry.localOffset + 30 > raw.length || dv.getUint32(entry.localOffset, true) !== 0x04034b50) throw new Error("Invalid ZIP entry offset.");
    const start = entry.localOffset + 30 + dv.getUint16(entry.localOffset + 26, true) + dv.getUint16(entry.localOffset + 28, true);
    if (start + entry.compressed > raw.length) throw new Error("Truncated Excel workbook.");
    const compressedData = raw.subarray(start, start + entry.compressed);
    let output;
    if (entry.method === 0) output = compressedData;
    else if (entry.method === 8) {
      if (!("DecompressionStream" in window)) throw new Error("Browser cannot decompress .xlsx files; use an up-to-date browser.");
      output = new Uint8Array(await new Response(new Blob([compressedData]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer());
    } else throw new Error("Unsupported Excel ZIP compression method.");
    if (output.length !== entry.uncompressed) throw new Error("Workbook ZIP entry failed size validation.");
    return decoder.decode(output);
  };
}

function xlsxXml(text) {
  if (!text) return null;
  const xml = new DOMParser().parseFromString(text, "application/xml");
  if (xml.getElementsByTagName("parsererror").length) throw new Error("Malformed Excel workbook XML.");
  return xml;
}

function xlsxNodes(node, tag) {
  return Array.from(node.getElementsByTagNameNS("*", tag));
}

function xlsxCellValue(c, strings, dateStyles, date1904) {
  const type = c.getAttribute("t");
  const v = xlsxNodes(c, "v")[0]?.textContent ?? "";
  if (type === "s") return strings[Number(v)] ?? "";
  if (type === "inlineStr") return xlsxNodes(c, "is")[0] ? xlsxNodes(xlsxNodes(c, "is")[0], "t").map(t => t.textContent).join("") : "";
  if (type === "b") return v === "1" ? "TRUE" : "FALSE";
  if (type === "e") return v;
  if (type === "str") return v;
  if (dateStyles.has(Number(c.getAttribute("s") || 0)) && v !== "" && !Number.isNaN(Number(v))) {
    const ms = Date.UTC(date1904 ? 1904 : 1899, date1904 ? 0 : 11, date1904 ? 1 : 30) + Number(v) * 86400000;
    const d = new Date(ms);
    return Number.isFinite(d.getTime()) ? d.toISOString() : v;
  }
  return v;
}

async function parseSpreadsheet(file) {
  if (file.size > 35 * 1024 * 1024) throw new Error("Workbook exceeds the 35 MB prototype upload limit.");
  const read = await openXlsxZip(file);
  const wb = xlsxXml(await read("xl/workbook.xml"));
  if (!wb) throw new Error("Missing workbook.xml; this file is not an Excel .xlsx workbook.");
  const date1904 = xlsxNodes(wb, "workbookPr")[0]?.getAttribute("date1904") === "1";
  const relationships = new Map();
  const relXml = xlsxXml(await read("xl/_rels/workbook.xml.rels"));
  if (relXml) for (const rel of xlsxNodes(relXml, "Relationship")) {
    const target = rel.getAttribute("Target") || "";
    if (/^(https?:|file:)/i.test(target)) continue;
    relationships.set(rel.getAttribute("Id"), normalizeXlsxPath(target.startsWith("/") ? target : "xl/" + target));
  }
  const shared = [];
  const sharedXml = xlsxXml(await read("xl/sharedStrings.xml"));
  if (sharedXml) for (const si of xlsxNodes(sharedXml, "si")) shared.push(xlsxNodes(si, "t").map(t => t.textContent).join(""));
  const dateStyles = new Set();
  const styles = xlsxXml(await read("xl/styles.xml"));
  if (styles) {
    const custom = new Map();
    for (const f of xlsxNodes(styles, "numFmt")) custom.set(Number(f.getAttribute("numFmtId")), f.getAttribute("formatCode") || "");
    const cellXfs = xlsxNodes(styles, "cellXfs")[0];
    if (cellXfs) xlsxNodes(cellXfs, "xf").forEach((xf, i) => {
      const n = Number(xf.getAttribute("numFmtId") || "0");
      if ((n >= 14 && n <= 22) || (n >= 45 && n <= 47) || (custom.has(n) && /[ymdhs]/i.test((custom.get(n) || "").replace(/"[^"]*"/g, "").replace(/\\./g, "")))) dateStyles.add(i);
    });
  }
  const output = [];
  const sheets = xlsxNodes(wb, "sheet");
  let limited = false;
  for (let s = 0; s < sheets.length; s++) {
    const sheet = sheets[s];
    const rId = sheet.getAttribute("r:id") || sheet.getAttributeNS("http://schemas.openxmlformats.org/officeDocument/2006/relationships", "id");
    const path = relationships.get(rId);
    if (!path) continue;
    const doc = xlsxXml(await read(path));
    if (!doc) continue;
    const parsedRows = [];
    for (const row of xlsxNodes(doc, "row")) {
      const values = [];
      for (const cell of xlsxNodes(row, "c")) {
        const ref = cell.getAttribute("r") || "";
        const letters = /^[A-Za-z]+/.exec(ref)?.[0] || "";
        let col = 0;
        for (const ch of letters.toUpperCase()) col = col * 26 + ch.charCodeAt(0) - 64;
        col = col ? col - 1 : values.length;
        if (col > 199) continue;
        values[col] = xlsxCellValue(cell, shared, dateStyles, date1904);
      }
      if (values.some(v => String(v ?? "").trim() !== "")) parsedRows.push(values);
      if (parsedRows.length >= 15002) {limited = true; break;}
    }
    if (!parsedRows.length) continue;
    const known = /source|destination|dest|src|dst|bytes|packet|protocol|port|address|start|time|date|country|client|server|host|flow/i;
    let headerIdx = parsedRows.findIndex(r => r.filter(v => String(v ?? "").trim()).length >= 2);
    if (headerIdx < 0) continue;
    let bestScore = -1;
    for (let i = 0; i < Math.min(12, parsedRows.length); i++) {
      const row = parsedRows[i];
      const fields = row.filter(v => String(v ?? "").trim());
      if (fields.length < 2) continue;
      const matches = fields.filter(v => known.test(String(v))).length;
      const score = matches * 3 + Math.min(fields.length, 20) / 100 - i / 1000;
      if (matches >= 2 && score > bestScore) { bestScore = score; headerIdx = i; }
    }
    const seen = new Map();
    const headers = parsedRows[headerIdx].map((v, i) => {
      const name = String(v ?? "").trim() || `Column ${i + 1}`;
      const count = (seen.get(name) || 0) + 1;
      seen.set(name, count);
      return count > 1 ? `${name} (${count})` : name;
    });
    for (let i = headerIdx + 1; i < parsedRows.length; i++) {
      const row = parsedRows[i];
      const record = {};
      let hasData = false;
      for (let c = 0; c < Math.min(row.length, 200); c++) {
        const value = row[c];
        if (value === undefined || String(value).trim() === "") continue;
        record[headers[c] || `Column ${c + 1}`] = value;
        hasData = true;
      }
      if (hasData) {
        if (sheets.length > 1) record._sheet = sheet.getAttribute("name") || `Sheet ${s + 1}`;
        output.push(record);
      }
      if (output.length >= 15000) { limited = true; break; }
    }
    if (limited) break;
  }
  if (!output.length) throw new Error("No tabular rows found in this workbook. Ensure the worksheet has a header row and data rows.");
  return {parser: "Excel (.xlsx)", records: output, warning: limited ? "Import limited to 15,000 rows; use CSV for larger exports." : ""};
}

function recordFacts(record) {
  const fields = {};
  for (const [key, value] of Object.entries(record)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (value !== null && value !== undefined && value !== "" && fields[normalized] === undefined) fields[normalized] = String(value).trim();
  }
  const field = (...names) => names.map(name => fields[name]).find(v => v !== undefined) || "";
  const src = field("sourceip", "sourceipaddress", "srcip", "srcipaddress", "sourceaddress", "srcaddress", "clientip", "localip", "sourceipv4", "source", "src");
  const dst = field("destinationip", "destinationipaddress", "destip", "dstip", "destinationaddress", "dstaddress", "remoteip", "serverip", "destinationipv4", "destination", "dest", "dst");
  const srcPort = field("sourceport", "srcport", "clientport", "localport");
  const dstPort = field("destinationport", "destport", "dstport", "remoteport", "serverport");
  const protocol = field("protocol", "ipprotocol", "transportprotocol", "transport", "proto");
  const country = field("destinationcountry", "destcountry", "dstcountry", "remotecountry", "geolocation", "country");
  const bytesRaw = field("totalbytes", "bytestransferred", "transferredbytes", "bytecount", "bytes", "octets");
  const packetsRaw = field("totalpackets", "packetcount", "packets");
  const numeric = x => /^\d[\d,]*(?:\.\d+)?$/.test(x) ? Number(x.replace(/,/g, "")) : null;
  return {src:src.slice(0,100),dst:dst.slice(0,100),srcPort:srcPort.slice(0,12),dstPort:dstPort.slice(0,12),protocol:protocol.slice(0,50),country:country.slice(0,100),bytes:numeric(bytesRaw),packets:numeric(packetsRaw)};
}

function flowSummary(f) {
  if (!f.src && !f.dst) return "";
  const source = (f.src || "Unknown source") + (f.srcPort ? ":" + f.srcPort : "");
  const dest = (f.dst || "Unknown destination") + (f.dstPort ? ":" + f.dstPort : "");
  const pieces = [source + " → " + dest];
  if (f.protocol) pieces.push(f.protocol);
  if (f.bytes !== null) pieces.push(Number(f.bytes).toLocaleString() + " bytes");
  if (f.packets !== null) pieces.push(Number(f.packets).toLocaleString() + " packets");
  if (f.country) pieces.push("reported country: " + f.country);
  return pieces.join(" | ");
}