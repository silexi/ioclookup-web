// ioclookup.com Worker.
//
// Static files are served by the assets binding. The Worker handles two paths:
// - /api/p/<provider>/...: a pass-through for lookup APIs that do not allow browser requests (no CORS).
// - /api/match: matches indicators against lists that may be used but not republished
//   for now only CINS Army). Those lists are built into /_private/, which this Worker refuses to serve publicly;
//   only the entries that match the submitted indicators are returned.
//
// What the proxy does and does not do:
// - Only fixed upstream endpoints per provider (below). It is not an open proxy.
// - The user's API key arrives in a request header and is forwarded in the provider's header.
//   It is not stored and not logged. This file contains no console.log on purpose.
// - Only same-origin requests are accepted, so other sites cannot use it as a relay.
// - Cookies and other request headers are not forwarded.

export const PROVIDERS = {
  threatfox: {
    method: "POST",
    upstream: () => "https://threatfox-api.abuse.ch/api/v1/",
    path: /^$/,
    keyHeader: "Auth-Key",
    contentType: "application/json",
  },
  urlhaus: {
    method: "POST",
    upstream: (p) => `https://urlhaus-api.abuse.ch/v1/${p}/`,
    path: /^(url|host|payload)$/,
    keyHeader: "Auth-Key",
    contentType: "application/x-www-form-urlencoded",
  },
  abuseipdb: {
    method: "GET",
    upstream: (p, q) => `https://api.abuseipdb.com/api/v2/check?${q}`,
    path: /^check$/,
    query: /^ipAddress=[0-9a-fA-F.:%]+&maxAgeInDays=\d{1,3}$/,
    keyHeader: "Key",
    accept: "application/json",
  },
  virustotal: {
    method: "GET",
    upstream: (p) => `https://www.virustotal.com/api/v3/${p}`,
    path: /^(ip_addresses|domains|files|urls)\/[A-Za-z0-9._:\-]{1,512}$/,
    keyHeader: "x-apikey",
  },
};

const MAX_BODY = 8 * 1024;

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

export async function handleProxy(request, url, fetchFn = fetch) {
  const m = url.pathname.match(/^\/api\/p\/([a-z]+)\/?(.*)$/);
  const p = m && PROVIDERS[m[1]];
  if (!p) return json(404, { error: "unknown provider" });
  if (request.method !== p.method) return json(405, { error: "method not allowed" });
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if ((origin && origin !== url.origin) || (site && site !== "same-origin")) return json(403, { error: "cross-site request" });
  const sub = decodeURIComponent(m[2] || "");
  if (!p.path.test(sub)) return json(400, { error: "path not allowed" });
  const query = url.search.replace(/^\?/, "");
  if (p.query ? !p.query.test(query) : query) return json(400, { error: "query not allowed" });
  const key = request.headers.get("x-user-key") || "";
  if (!key || key.length > 200 || /[\r\n]/.test(key)) return json(400, { error: "missing or invalid key" });

  const headers = { [p.keyHeader]: key, "user-agent": "ioclookup.com (user key)" };
  if (p.accept) headers.accept = p.accept;
  let body;
  if (p.method === "POST") {
    body = await request.text();
    if (body.length > MAX_BODY) return json(413, { error: "body too large" });
    headers["content-type"] = p.contentType;
  }
  let upstream;
  try {
    upstream = await fetchFn(p.upstream(sub, query), { method: p.method, headers, body, redirect: "manual" });
  } catch {
    return json(502, { error: "upstream unreachable" });
  }
  const text = await upstream.text();
  return new Response(text.slice(0, 512 * 1024), {
    status: upstream.status,
    headers: { "content-type": upstream.headers.get("content-type") || "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

const MATCH_TYPES = new Set(["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]);
const SHARDS = 16;
const MAX_MATCH_BODY = 64 * 1024;
const MAX_VALUES = 1000;
const shardCache = new Map(); // "<type>/<n>" -> { at, data }

// FNV-1a 32-bit over UTF-8, the same function scripts/build_feeds.py uses to shard the lists.
export function fnv1a(s) {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(s)) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
  return h;
}

async function loadShard(env, origin, type, n) {
  const key = `${type}/${n}`;
  const hit = shardCache.get(key);
  if (hit && Date.now() - hit.at < 10 * 60 * 1000) return hit.data;
  const r = await env.ASSETS.fetch(new Request(`${origin}/_private/${key}.json`));
  const data = r.ok ? await r.json() : {};
  shardCache.set(key, { at: Date.now(), data });
  return data;
}

function sameOrigin(request, url) {
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  return !((origin && origin !== url.origin) || (site && site !== "same-origin"));
}

export async function handleMatch(request, url, env) {
  if (request.method !== "POST") return json(405, { error: "method not allowed" });
  if (!sameOrigin(request, url)) return json(403, { error: "cross-site request" });
  const text = await request.text();
  if (text.length > MAX_MATCH_BODY) return json(413, { error: "body too large" });
  let body;
  try { body = JSON.parse(text); } catch { return json(400, { error: "invalid JSON" }); }
  const type = body?.type;
  if (!MATCH_TYPES.has(type) || !Array.isArray(body.values) || body.values.length > MAX_VALUES) return json(400, { error: "invalid request" });
  const lower = type !== "url" && type !== "ipv4" && type !== "ipv6";
  const values = [...new Set(body.values.filter((v) => typeof v === "string" && v.length <= 2048).map((v) => (lower ? v.toLowerCase() : v)))];
  const byShard = new Map();
  for (const v of values) {
    const n = fnv1a(v) % SHARDS;
    if (!byShard.has(n)) byShard.set(n, []);
    byShard.get(n).push(v);
  }
  const hits = [];
  await Promise.all([...byShard].map(async ([n, vs]) => {
    const data = await loadShard(env, url.origin, type, n);
    for (const v of vs) if (Object.prototype.hasOwnProperty.call(data, v)) hits.push({ value: v, hits: data[v] });
  }));
  return json(200, { type, hits });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/p/")) return handleProxy(request, url);
    if (url.pathname === "/api/match") return handleMatch(request, url, env);
    if (url.pathname.startsWith("/_private/")) return new Response("Not found", { status: 404 });
    return env.ASSETS.fetch(request);
  },
};
