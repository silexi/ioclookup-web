// Hunting queries built from the extracted indicators, so they can be searched for in a SIEM.
// Nothing here talks to the network. Field names follow each platform's common schema:
// Microsoft Sentinel / Defender XDR tables, Splunk CIM data models, QRadar event and flow
// properties, Elastic Common Schema, and Sigma's generic log sources.

import { isNonRoutableIPv4 } from "./extract.js";

export const PLATFORMS = [
  { id: "kql", name: "Microsoft Sentinel (KQL)" },
  { id: "spl", name: "Splunk (SPL, CIM)" },
  { id: "aql", name: "QRadar (AQL)" },
  { id: "elastic", name: "Elastic (KQL, ECS)" },
  { id: "sigma", name: "Sigma" },
];

// Indicators grouped the way the queries use them. Private and reserved IPv4 addresses are left
// out: in a report they are almost always examples, and in a SIEM they match ordinary traffic.
export function group(iocs) {
  const g = { ip: [], domain: [], url: [], md5: [], sha1: [], sha256: [], email: [], skipped: 0 };
  const seen = new Set();
  for (const i of iocs) {
    const k = `${i.type}|${i.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (i.type === "ipv4" && isNonRoutableIPv4(i.value)) { g.skipped++; continue; }
    if (i.type === "ipv4" || i.type === "ipv6") g.ip.push(i.value);
    else if (g[i.type]) g[i.type].push(i.value);
  }
  return g;
}

const dq = (v) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const sq = (v) => `'${v.replace(/'/g, "''")}'`;
const list = (vals, quote) => vals.map(quote).join(", ");
const any = (g) => g.ip.length + g.domain.length + g.url.length + g.md5.length + g.sha1.length + g.sha256.length + g.email.length > 0;

function kql(g, days) {
  const lets = [];
  const parts = [];
  const t = `TimeGenerated > ago(${days}d)`;
  if (g.ip.length) {
    lets.push(`let ioc_ip = dynamic([${list(g.ip, dq)}]);`);
    parts.push(
      `(CommonSecurityLog | where ${t} and (SourceIP in (ioc_ip) or DestinationIP in (ioc_ip)))`,
      `(DeviceNetworkEvents | where ${t} and RemoteIP in (ioc_ip))`,
      `(SigninLogs | where ${t} and IPAddress in (ioc_ip))`,
    );
  }
  if (g.domain.length) {
    lets.push(`let ioc_domain = dynamic([${list(g.domain, dq)}]);`);
    parts.push(
      `(DnsEvents | where ${t} and Name has_any (ioc_domain))`,
      `(DeviceNetworkEvents | where ${t} and RemoteUrl has_any (ioc_domain))`,
      `(CommonSecurityLog | where ${t} and (DestinationHostName has_any (ioc_domain) or RequestURL has_any (ioc_domain)))`,
    );
  }
  if (g.url.length) {
    lets.push(`let ioc_url = dynamic([${list(g.url, dq)}]);`);
    parts.push(
      `(CommonSecurityLog | where ${t} and RequestURL has_any (ioc_url))`,
      `(DeviceNetworkEvents | where ${t} and RemoteUrl has_any (ioc_url))`,
    );
  }
  const hashes = [...g.md5, ...g.sha1, ...g.sha256];
  if (hashes.length) {
    lets.push(`let ioc_hash = dynamic([${list(hashes.map((h) => h.toLowerCase()), dq)}]);`);
    for (const table of ["DeviceFileEvents", "DeviceProcessEvents", "DeviceImageLoadEvents"]) {
      parts.push(`(${table} | where ${t} and (SHA256 in~ (ioc_hash) or SHA1 in~ (ioc_hash) or MD5 in~ (ioc_hash)))`);
    }
  }
  if (g.email.length) {
    lets.push(`let ioc_email = dynamic([${list(g.email, dq)}]);`);
    parts.push(`(EmailEvents | where ${t} and (SenderFromAddress in~ (ioc_email) or SenderMailFromAddress in~ (ioc_email) or RecipientEmailAddress in~ (ioc_email)))`);
  }
  return [
    ...lets,
    "// isfuzzy=true skips tables that do not exist in this workspace instead of failing.",
    "union isfuzzy=true",
    parts.map((p) => "  " + p).join(",\n"),
    "| summarize Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Type",
  ].join("\n");
}

function spl(g, days) {
  const q = [];
  const e = `earliest=-${days}d`;
  const tstats = (dm, where, by) => `| tstats count min(_time) as first_seen max(_time) as last_seen from datamodel=${dm} where ${e} (${where}) by ${by}`;
  const inList = (field, vals) => `${field} IN (${list(vals, dq)})`;
  if (g.ip.length) q.push(tstats("Network_Traffic", `${inList("All_Traffic.src_ip", g.ip)} OR ${inList("All_Traffic.dest_ip", g.ip)}`, "All_Traffic.src_ip All_Traffic.dest_ip index sourcetype"));
  if (g.domain.length) q.push(tstats("Network_Resolution", inList("DNS.query", g.domain), "DNS.query DNS.src index sourcetype"));
  if (g.url.length) q.push(tstats("Web", inList("Web.url", g.url), "Web.url Web.src index sourcetype"));
  if (g.domain.length) q.push(tstats("Web", inList("Web.dest", g.domain), "Web.dest Web.src index sourcetype"));
  const hashes = [...g.md5, ...g.sha1, ...g.sha256];
  if (hashes.length) {
    q.push(tstats("Endpoint.Processes", inList("Processes.process_hash", hashes), "Processes.process_hash Processes.dest index sourcetype"));
    q.push(tstats("Endpoint.Filesystem", inList("Filesystem.file_hash", hashes), "Filesystem.file_hash Filesystem.dest index sourcetype"));
  }
  if (g.email.length) q.push(tstats("Email", `${inList("All_Email.src_user", g.email)} OR ${inList("All_Email.recipient", g.email)}`, "All_Email.src_user All_Email.recipient index sourcetype"));
  return q.join("\n\n");
}

function aql(g, days) {
  const q = [];
  const last = `LAST ${days} DAYS`;
  if (g.ip.length) {
    const ips = list(g.ip, sq);
    q.push(`SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS "Time", LOGSOURCENAME(logsourceid) AS "Log source", QIDNAME(qid) AS "Event", sourceip, destinationip, username\nFROM events\nWHERE sourceip IN (${ips}) OR destinationip IN (${ips})\n${last}`);
    q.push(`SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS "Time", sourceip, destinationip, destinationport, protocolid\nFROM flows\nWHERE sourceip IN (${ips}) OR destinationip IN (${ips})\n${last}`);
  }
  // Domains, URLs, hashes and addresses have no standard event property in QRadar; the payload
  // search works everywhere but is slow, so narrow the time range or log sources if needed.
  const text = [...g.domain, ...g.url, ...g.md5, ...g.sha1, ...g.sha256, ...g.email];
  if (text.length) {
    const cond = text.map((v) => `UTF8(payload) ILIKE ${sq("%" + v + "%")}`).join("\n   OR ");
    q.push(`/* Payload search: slow on large ranges. Replace with your custom properties (for example URL or file hash) where they exist. */\nSELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS "Time", LOGSOURCENAME(logsourceid) AS "Log source", QIDNAME(qid) AS "Event", sourceip, destinationip\nFROM events\nWHERE ${cond}\n${last}`);
  }
  return q.join("\n\n");
}

function elastic(g) {
  const or = (field, vals) => `${field} : (${vals.map(dq).join(" or ")})`;
  const c = [];
  if (g.ip.length) c.push(or("source.ip", g.ip), or("destination.ip", g.ip));
  if (g.domain.length) c.push(or("dns.question.name", g.domain), or("url.domain", g.domain), or("destination.domain", g.domain));
  if (g.url.length) c.push(or("url.full", g.url));
  if (g.md5.length) c.push(or("file.hash.md5", g.md5), or("process.hash.md5", g.md5));
  if (g.sha1.length) c.push(or("file.hash.sha1", g.sha1), or("process.hash.sha1", g.sha1));
  if (g.sha256.length) c.push(or("file.hash.sha256", g.sha256), or("process.hash.sha256", g.sha256));
  if (g.email.length) c.push(or("email.from.address", g.email), or("email.to.address", g.email));
  return c.join("\nor ");
}

function sigma(g, days) {
  const yamlList = (vals) => vals.map((v) => `            - '${v.replace(/'/g, "''")}'`).join("\n");
  const rule = (title, logsource, selection) => [
    `title: ${title}`,
    "status: experimental",
    "description: Indicators extracted with ioclookup.com. Review before deploying.",
    ...(globalThis.crypto?.randomUUID ? [`id: ${crypto.randomUUID()}`] : []),
    `date: ${new Date().toISOString().slice(0, 10)}`,
    "logsource:",
    ...Object.entries(logsource).map(([k, v]) => `    ${k}: ${v}`),
    "detection:",
    ...selection,
    "    condition: 1 of selection_*",
    "level: high",
  ].join("\n");
  const sel = (name, field, vals) => [`    selection_${name}:`, `        ${field}:`, yamlList(vals)];
  const rules = [];
  if (g.ip.length) rules.push(rule("Connection to IP addresses from an indicator list", { category: "firewall" }, [...sel("dst", "dst_ip", g.ip), ...sel("src", "src_ip", g.ip)]));
  if (g.domain.length) rules.push(rule("DNS query for domains from an indicator list", { category: "dns" }, sel("query", "query|endswith", g.domain)));
  if (g.domain.length || g.url.length) {
    const s = [];
    if (g.domain.length) s.push(...sel("host", "cs-host|endswith", g.domain));
    const paths = [...new Set(g.url.map((u) => u.replace(/^[a-z]+:\/\/[^/]+/i, "")).filter((p) => p.length > 1))];
    if (paths.length) s.push(...sel("url", "c-uri|contains", paths));
    if (s.length) rules.push(rule("Proxy request to hosts or paths from an indicator list", { category: "proxy" }, s));
  }
  const hashes = [...g.md5.map((h) => `MD5=${h}`), ...g.sha1.map((h) => `SHA1=${h}`), ...g.sha256.map((h) => `SHA256=${h}`)];
  if (hashes.length) rules.push(rule("Process started from a file hash in an indicator list", { category: "process_creation", product: "windows" }, sel("hash", "Hashes|contains", hashes)));
  return rules.join("\n---\n");
}

export function buildQuery(platform, iocs, days = 30) {
  const g = group(iocs);
  if (!any(g)) return { text: "", skipped: g.skipped };
  const fn = { kql, spl, aql, elastic, sigma }[platform];
  return { text: fn(g, days), skipped: g.skipped };
}
