// ioclookup.com Worker.
//
// Static files are served by the assets binding. The Worker only handles /api/p/<provider>/...,
// a pass-through for lookup APIs that do not allow browser requests (no CORS headers).
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/p/")) return handleProxy(request, url);
    return env.ASSETS.fetch(request);
  },
};
