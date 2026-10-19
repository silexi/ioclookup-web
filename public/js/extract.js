// Indicator extraction. Runs entirely in the browser; nothing here talks to the network.
//
// extract(text, { tlds }) -> [{ type, value, raw }]
//   type: ipv4 | ipv6 | domain | url | email | md5 | sha1 | sha256 | cve
//   value: normalized (refanged, lowercased where case does not matter)
//   raw: the text as it appeared, so the UI can show what was matched
//
// Defanged forms are accepted: hxxp(s)://, [.] (.) {.} [dot] (dot), [:] [://], [@] [at].

export const TYPES = ["url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "cve"];

// A small fallback so extraction works before the full IANA list is loaded.
const FALLBACK_TLDS = new Set(
  ("com net org info biz io co ai app dev xyz top site online club shop store tech cloud live me tv cc ru cn uk de fr nl tr br in jp kr it es pl ua ir su us ca au eu ch se no fi dk be at cz ro hu gr pt il sg hk tw vn id my th ph za mx ar cl gov edu mil int arpa onion")
    .split(" "),
);

export function refang(text) {
  return text
    .replace(/\bhxxp(s?)(:\/\/|\[:\/\/\]|\[:\]\/\/)/gi, "http$1://")
    .replace(/\bh\[tt\]p(s?):\/\//gi, "http$1://")
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[:\]/g, ":")
    .replace(/\s?(\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s?/gi, ".")
    .replace(/\s?(\[@\]|\(@\)|\[at\]|\(at\))\s?/gi, "@");
}

const TRAIL = /[.,;:!?)\]}>'"]+$/;

function validIPv4(s) {
  const p = s.split(".");
  return p.length === 4 && p.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255 && (o === "0" || !o.startsWith("0")));
}

function validIPv6(s) {
  if (!s.includes(":") || s.length < 3) return false;
  try {
    // the URL parser is a strict IPv6 validator and normalizer
    return new URL(`http://[${s}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

function normIPv6(s) {
  return new URL(`http://[${s}]/`).hostname.slice(1, -1);
}

function validDomain(d, tlds) {
  if (d.length > 253 || !d.includes(".")) return false;
  const labels = d.split(".");
  if (labels.some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) return false;
  const tld = labels[labels.length - 1];
  return /^[a-z]{2,24}$/.test(tld) || /^xn--[a-z0-9-]+$/.test(tld) ? tlds.has(tld) : false;
}

export function extract(input, opts = {}) {
  const tlds = opts.tlds || FALLBACK_TLDS;
  const text = refang(String(input || ""));
  const out = [];
  const seen = new Set();
  const add = (type, value, raw) => {
    const key = `${type}\u0000${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ type, value, raw });
  };
  const taken = []; // [start, end) ranges already claimed by URLs and emails
  const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);

  for (const m of text.matchAll(/\bhttps?:\/\/[^\s"'<>`]+/gi)) {
    const raw = m[0].replace(TRAIL, "");
    let u;
    try { u = new URL(raw); } catch { continue; }
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (!(validIPv4(host) || validIPv6(host) || validDomain(host.toLowerCase(), tlds))) continue;
    add("url", raw, raw);
    taken.push([m.index, m.index + raw.length]);
    if (validIPv4(host)) add("ipv4", host, host);
    else if (validIPv6(host)) add("ipv6", normIPv6(host), host);
    else add("domain", host.toLowerCase(), host);
  }

  for (const m of text.matchAll(/\b[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi)) {
    if (overlaps(m.index, m.index + m[0].length)) continue;
    const domain = m[1].toLowerCase();
    if (!validDomain(domain, tlds)) continue;
    add("email", m[0].toLowerCase(), m[0]);
    taken.push([m.index, m.index + m[0].length]);
    add("domain", domain, m[1]);
  }

  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) add("cve", m[0].toUpperCase(), m[0]);

  for (const m of text.matchAll(/\b[a-f0-9]{32,64}\b/gi)) {
    const v = m[0].toLowerCase();
    const type = { 32: "md5", 40: "sha1", 64: "sha256" }[v.length];
    if (type) add(type, v, m[0]);
  }

  for (const m of text.matchAll(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)/g)) {
    if (overlaps(m.index, m.index + m[0].length)) continue;
    if (validIPv4(m[0])) add("ipv4", m[0], m[0]);
  }

  for (const m of text.matchAll(/(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi)) {
    if (overlaps(m.index, m.index + m[0].length)) continue;
    if (/^[0-9:]+$/.test(m[0]) && !m[0].includes("::")) continue; // times like 12:30:45
    if (validIPv6(m[0])) add("ipv6", normIPv6(m[0]), m[0]);
  }

  for (const m of text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b/gi)) {
    if (overlaps(m.index, m.index + m[0].length)) continue;
    const d = m[0].toLowerCase();
    if (validIPv4(d)) continue;
    if (validDomain(d, tlds)) add("domain", d, m[0]);
  }

  return out.sort((a, b) => TYPES.indexOf(a.type) - TYPES.indexOf(b.type));
}

// Private, loopback, link-local, documentation and similar ranges: never sent to lookups.
export function isNonRoutableIPv4(ip) {
  const [a, b, c] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
}
