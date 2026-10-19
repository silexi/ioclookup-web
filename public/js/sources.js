// Lookups with the user's own API keys (BYOK).
//
// Each source sends the indicator to a third party, so lookups only run when the user asks.
// Sources that allow browser requests are called directly. The others go through /api/p/,
// a pass-through in this site's Worker that forwards the key and stores nothing (src/worker.js).
//
// query() returns { status: "listed" | "not_listed" | "info" | "error", summary, link }.
// "info" is for sources that describe an address (open ports, hostnames) rather than list it as bad.
// Sources with noKey: true need no key and are queried directly from the browser.

const enc = encodeURIComponent;
const b64url = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function proxied(provider, path, key, { method = "GET", body, query = "" } = {}) {
  const r = await fetch(`/api/p/${provider}/${path}${query ? "?" + query : ""}`, {
    method,
    headers: { "x-user-key": key, ...(body ? { "content-type": "text/plain" } : {}) },
    body,
  });
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* not JSON */ }
  return { ok: r.ok, status: r.status, data };
}

const err = (msg) => ({ status: "error", summary: msg, link: "" });

// USOM descriptions, from https://siberguvenlik.gov.tr/api/address-description/index
const USOM_DESC = { PH: "phishing", BP: "banking phishing", MD: "malware distribution domain", MI: "malware distribution IP", MU: "malware distribution URL", MC: "malware command and control", SA: "attack source (scanning, brute force)" };
const stripUrl = (v) => v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/\/$/, "").toLowerCase();

// Lists that may be used but not republished. They are matched by this site's Worker (/api/match):
// the indicators are sent there on Look up and only matching entries come back (src/worker.js).
export const SERVER_SOURCES = [
  { id: "cins", name: "CINS Army", server: true, noKey: true, proxied: true, home: "https://cinsscore.com/", types: ["ipv4"] },
];

export async function matchOnServer(type, values) {
  const r = await fetch("/api/match", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type, values }) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).hits; // [{ value, hits: [[source id, detail], ...] }]
}

export const SOURCES = [
  {
    // Türkiye's national CERT list (Siber Güvenlik Başkanlığı, formerly USOM). Its public API accepts
    // browser requests, so each indicator is queried directly; nothing is copied to this site.
    id: "usom",
    name: "USOM (Siber Güvenlik Başkanlığı)",
    noKey: true,
    types: ["ipv4", "domain", "url"],
    proxied: false,
    minIntervalMs: 300,
    async query(ioc) {
      // The url parameter matches substrings, so results are filtered to exact matches here.
      const r = await fetch(`https://siberguvenlik.gov.tr/api/address/index?url=${enc(ioc.value)}&pageSize=100`);
      if (!r.ok) return err(`HTTP ${r.status}`);
      const d = await r.json();
      const want = ioc.type === "url" ? stripUrl(ioc.value) : ioc.value.toLowerCase();
      const hits = (d.models || []).filter((m) => stripUrl(String(m.url || "")) === want);
      if (!hits.length) return { status: "not_listed", summary: "", link: "" };
      const h = hits[0];
      return { status: "listed", summary: `${USOM_DESC[h.desc] || h.desc}, ${String(h.date).slice(0, 10)}`, link: "https://siberguvenlik.gov.tr/zararli-baglantilar" };
    },
  },
  {
    id: "internetdb",
    name: "Shodan InternetDB",
    noKey: true,
    // Free for non-commercial use (https://blog.shodan.io/introducing-the-internetdb-api/). Remove if the site starts charging.
    types: ["ipv4"],
    proxied: false,
    minIntervalMs: 250,
    async query(ioc) {
      const r = await fetch(`https://internetdb.shodan.io/${enc(ioc.value)}`);
      if (r.status === 404) return { status: "not_listed", summary: "no data", link: "" };
      if (!r.ok) return err(`HTTP ${r.status}`);
      const d = await r.json();
      const parts = [];
      if (d.ports?.length) parts.push(`ports ${d.ports.slice(0, 12).join(", ")}${d.ports.length > 12 ? ", ..." : ""}`);
      if (d.vulns?.length) parts.push(`${d.vulns.length} known CVE(s)`);
      if (d.tags?.length) parts.push(`tags: ${d.tags.join(", ")}`);
      if (d.hostnames?.length) parts.push(`hostnames: ${d.hostnames.slice(0, 3).join(", ")}`);
      return { status: "info", summary: parts.join("; ") || "no open ports seen", link: `https://www.shodan.io/host/${enc(ioc.value)}` };
    },
  },
  {
    id: "threatfox",
    name: "abuse.ch ThreatFox",
    keyLabel: "abuse.ch Auth-Key",
    keyUrl: "https://auth.abuse.ch/",
    types: ["ipv4", "domain", "url", "md5", "sha1", "sha256"],
    proxied: true,
    async query(ioc, key) {
      const r = await proxied("threatfox", "", key, { method: "POST", body: JSON.stringify({ query: "search_ioc", search_term: ioc.value, exact_match: true }) });
      if (!r.ok || !r.data) return err(`HTTP ${r.status}`);
      if (r.data.query_status === "no_result") return { status: "not_listed", summary: "", link: "" };
      if (r.data.query_status !== "ok") return err(String(r.data.query_status || r.data.error || "error"));
      const d = r.data.data || [];
      const fam = [...new Set(d.map((x) => x.malware_printable).filter(Boolean))].slice(0, 3).join(", ");
      return { status: "listed", summary: `${d.length} IOC record(s)${fam ? ": " + fam : ""}`, link: d[0] ? `https://threatfox.abuse.ch/ioc/${d[0].id}/` : "" };
    },
  },
  {
    id: "urlhaus",
    name: "abuse.ch URLhaus",
    keyLabel: "abuse.ch Auth-Key",
    keyUrl: "https://auth.abuse.ch/",
    sharesKeyWith: "threatfox",
    types: ["url", "domain", "ipv4", "md5", "sha256"],
    proxied: true,
    async query(ioc, key) {
      const [path, field] = ioc.type === "url" ? ["url", "url"] : ioc.type === "md5" ? ["payload", "md5_hash"] : ioc.type === "sha256" ? ["payload", "sha256_hash"] : ["host", "host"];
      const r = await proxied("urlhaus", path, key, { method: "POST", body: `${field}=${enc(ioc.value)}` });
      if (!r.ok || !r.data) return err(`HTTP ${r.status}`);
      if (r.data.query_status === "no_results") return { status: "not_listed", summary: "", link: "" };
      if (r.data.query_status !== "ok") return err(String(r.data.query_status));
      const n = r.data.url_count ?? r.data.urls?.length ?? 1;
      return { status: "listed", summary: path === "payload" ? `payload seen (${r.data.signature || "no signature"})` : `${n} malicious URL record(s)`, link: r.data.urlhaus_reference || "" };
    },
  },
  {
    id: "abuseipdb",
    name: "AbuseIPDB",
    keyLabel: "AbuseIPDB API key",
    keyUrl: "https://www.abuseipdb.com/account/api",
    types: ["ipv4", "ipv6"],
    proxied: true,
    async query(ioc, key) {
      const r = await proxied("abuseipdb", "check", key, { query: `ipAddress=${enc(ioc.value)}&maxAgeInDays=90` });
      if (!r.ok || !r.data?.data) return err(`HTTP ${r.status}`);
      const d = r.data.data;
      const score = d.abuseConfidenceScore ?? 0;
      return { status: score > 0 || d.totalReports > 0 ? "listed" : "not_listed", summary: `confidence ${score}%, ${d.totalReports ?? 0} reports in 90 days`, link: `https://www.abuseipdb.com/check/${enc(ioc.value)}` };
    },
  },
  {
    id: "virustotal",
    name: "VirusTotal",
    keyLabel: "VirusTotal API key",
    keyUrl: "https://www.virustotal.com/gui/my-apikey",
    types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
    proxied: true,
    minIntervalMs: 15500, // public API: 4 requests per minute
    async query(ioc, key) {
      const path = ioc.type.startsWith("ip") ? `ip_addresses/${ioc.value}` : ioc.type === "domain" ? `domains/${ioc.value}` : ioc.type === "url" ? `urls/${b64url(ioc.value)}` : `files/${ioc.value}`;
      const r = await proxied("virustotal", path, key);
      if (r.status === 404) return { status: "not_listed", summary: "not in VirusTotal", link: "" };
      if (!r.ok || !r.data?.data) return err(`HTTP ${r.status}`);
      const s = r.data.data.attributes?.last_analysis_stats || {};
      const bad = (s.malicious || 0) + (s.suspicious || 0);
      const total = Object.values(s).reduce((a, b) => a + b, 0);
      const gui = ioc.type.startsWith("ip") ? "ip-address" : ioc.type === "domain" ? "domain" : ioc.type === "url" ? "url" : "file";
      const id = ioc.type === "url" ? r.data.data.id : ioc.value;
      return { status: bad > 0 ? "listed" : "not_listed", summary: `${bad}/${total} engines flagged`, link: `https://www.virustotal.com/gui/${gui}/${id}` };
    },
  },
  {
    id: "otx",
    name: "AlienVault OTX",
    keyLabel: "OTX API key",
    keyUrl: "https://otx.alienvault.com/api",
    types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve"],
    proxied: false,
    async query(ioc, key) {
      const section = { ipv4: "IPv4", ipv6: "IPv6", domain: "domain", url: "url", md5: "file", sha1: "file", sha256: "file", cve: "cve" }[ioc.type];
      const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/${section}/${enc(ioc.value)}/general`, { headers: { "X-OTX-API-KEY": key } });
      if (r.status === 404) return { status: "not_listed", summary: "", link: "" };
      if (!r.ok) return err(`HTTP ${r.status}`);
      const d = await r.json();
      const n = d.pulse_info?.count ?? 0;
      return { status: n > 0 ? "listed" : "not_listed", summary: `${n} pulse(s)`, link: `https://otx.alienvault.com/indicator/${section.toLowerCase()}/${enc(ioc.value)}` };
    },
  },
];

export function sourcesFor(type, keys) {
  return SOURCES.filter((s) => s.types.includes(type) && (s.noKey || keyFor(s, keys)));
}

export function keyFor(source, keys) {
  return keys[source.id] || (source.sharesKeyWith ? keys[source.sharesKeyWith] : "") || "";
}
