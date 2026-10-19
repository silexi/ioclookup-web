// node tests/worker.test.mjs
import assert from "node:assert/strict";
import { handleProxy } from "../src/worker.js";

let n = 0;
const calls = [];
const fakeFetch = async (url, init) => { calls.push({ url, init }); return new Response('{"query_status":"ok"}', { status: 200, headers: { "content-type": "application/json" } }); };
const req = (path, { method = "GET", headers = {}, body } = {}) => {
  const url = new URL("https://ioclookup.com" + path);
  return [new Request(url, { method, headers: { origin: "https://ioclookup.com", "sec-fetch-site": "same-origin", "x-user-key": "K", ...headers }, body }), url];
};
const run = async (name, fn) => { await fn(); n++; };

await run("threatfox forwards key and body", async () => {
  const r = await handleProxy(...req("/api/p/threatfox/", { method: "POST", body: '{"query":"search_ioc"}', headers: { cookie: "s=1" } }), fakeFetch);
  assert.equal(r.status, 200);
  const c = calls.at(-1);
  assert.equal(c.url, "https://threatfox-api.abuse.ch/api/v1/");
  assert.equal(c.init.headers["Auth-Key"], "K");
  assert.equal(c.init.headers.cookie, undefined);
  assert.equal(c.init.body, '{"query":"search_ioc"}');
  assert.equal(r.headers.get("cache-control"), "no-store");
});

await run("abuseipdb only exact query shape", async () => {
  let r = await handleProxy(...req("/api/p/abuseipdb/check?ipAddress=1.2.3.4&maxAgeInDays=90"), fakeFetch);
  assert.equal(r.status, 200);
  assert.equal(calls.at(-1).url, "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90");
  r = await handleProxy(...req("/api/p/abuseipdb/check?ipAddress=1.2.3.4&maxAgeInDays=90&verbose=1"), fakeFetch);
  assert.equal(r.status, 400);
});

await run("virustotal path allowlist", async () => {
  assert.equal((await handleProxy(...req("/api/p/virustotal/domains/evil.ru"), fakeFetch)).status, 200);
  assert.equal((await handleProxy(...req("/api/p/virustotal/users/me"), fakeFetch)).status, 400);
  assert.equal((await handleProxy(...req("/api/p/virustotal/domains/..%2F..%2Fusers"), fakeFetch)).status, 400);
});

await run("rejects cross-site, missing key, unknown provider, wrong method", async () => {
  const before = calls.length;
  assert.equal((await handleProxy(...req("/api/p/threatfox/", { method: "POST", body: "{}", headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" } }), fakeFetch)).status, 403);
  assert.equal((await handleProxy(...req("/api/p/threatfox/", { method: "POST", body: "{}", headers: { "x-user-key": "" } }), fakeFetch)).status, 400);
  assert.equal((await handleProxy(...req("/api/p/shodan/x"), fakeFetch)).status, 404);
  assert.equal((await handleProxy(...req("/api/p/threatfox/"), fakeFetch)).status, 405);
  assert.equal((await handleProxy(...req("/api/p/urlhaus/admin", { method: "POST", body: "a=b" }), fakeFetch)).status, 400);
  assert.equal(calls.length, before, "nothing forwarded");
});

await run("body size limit", async () => {
  assert.equal((await handleProxy(...req("/api/p/threatfox/", { method: "POST", body: "x".repeat(9000) }), fakeFetch)).status, 413);
});

await run("no logging in worker source", async () => {
  const { readFileSync } = await import("node:fs");
  assert.doesNotMatch(readFileSync(new URL("../src/worker.js", import.meta.url), "utf8"), /console\.(log|info|warn|error|debug)\(/);
});

console.log(`ok: ${n} tests passed`);
