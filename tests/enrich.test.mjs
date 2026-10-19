// node tests/enrich.test.mjs
import assert from "node:assert/strict";
import { extract } from "../public/js/extract.js";
import { buildQuery, group, PLATFORMS } from "../public/js/queries.js";
import { pivotsFor } from "../public/js/pivots.js";
import { ipv4ToU32, findInShard, asnFor } from "../public/js/asn.js";

let n = 0;
const t = async (name, fn) => { await fn(); n++; };

const sample = extract(`C2 185.220.101.4 and 10.0.0.5, beacon to hxxps://login-micro[.]com/auth?id=1
dropper d41d8cd98f00b204e9800998ecf8427e sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sender it-support@evil[.]ru, CVE-2024-3400, 2001:db8::1, it's "quoted.com"`);

await t("grouping drops private IPv4 and duplicates", () => {
  const g = group([...sample, ...sample]);
  assert.deepEqual(g.ip, ["185.220.101.4", "2001:db8::1"]);
  assert.equal(g.skipped, 1);
  assert.ok(g.domain.includes("login-micro.com") && g.domain.includes("evil.ru"));
});

await t("every platform produces a query that names each indicator", () => {
  for (const p of PLATFORMS) {
    const { text, skipped } = buildQuery(p.id, sample, 7);
    assert.equal(skipped, 1);
    for (const v of ["185.220.101.4", "login-micro.com", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]) assert.ok(text.includes(v), `${p.id} misses ${v}`);
    assert.ok(!text.includes("10.0.0.5"), `${p.id} includes a private address`);
  }
});

await t("platform specifics", () => {
  const kql = buildQuery("kql", sample, 7).text;
  assert.match(kql, /union isfuzzy=true/);
  assert.match(kql, /TimeGenerated > ago\(7d\)/);
  assert.match(buildQuery("spl", sample, 7).text, /datamodel=Network_Traffic where earliest=-7d/);
  const aql = buildQuery("aql", sample, 7).text;
  assert.match(aql, /sourceip IN \('185\.220\.101\.4', '2001:db8::1'\)/);
  assert.match(aql, /LAST 7 DAYS/);
  const sigma = buildQuery("sigma", sample, 7).text;
  assert.equal(sigma.split("\n---\n").length, 4); // firewall, dns, proxy, process_creation
  assert.match(sigma, /- 'SHA256=e3b0c442/);
  assert.match(buildQuery("elastic", sample).text, /destination\.ip : \("185\.220\.101\.4" or "2001:db8::1"\)/);
});

await t("quotes are escaped", () => {
  const iocs = [{ type: "url", value: `http://a.com/x'y"z` }];
  assert.match(buildQuery("aql", iocs).text, /x''y"z/);
  assert.match(buildQuery("kql", iocs).text, /x'y\\"z/);
});

await t("nothing to search gives an empty query", () => {
  assert.equal(buildQuery("kql", extract("CVE-2024-3400 and 192.168.1.1")).text, "");
});

await t("pivot links", () => {
  const ip = pivotsFor({ type: "ipv4", value: "1.2.3.4" });
  assert.ok(ip.some((p) => p.url === "https://www.shodan.io/host/1.2.3.4"));
  assert.ok(ip.some((p) => p.url === "https://tracker.viriback.com/index.php?q=1.2.3.4"));
  assert.deepEqual(pivotsFor({ type: "cve", value: "CVE-2024-3400" }).map((p) => p.name), ["NVD", "CVE.org"]);
});

await t("asn lookup", async () => {
  assert.equal(ipv4ToU32("255.255.255.255"), 0xFFFFFFFF);
  assert.equal(ipv4ToU32("1.0.0.1"), 16777217);
  const sh = { s: [16777216, 16777472], e: [16777471, 16777727], a: [13335, 64500], names: { 13335: ["CLOUDFLARENET", "US"], 64500: ["X", "TR"] } };
  assert.deepEqual(findInShard(sh, ipv4ToU32("1.0.0.1")), { asn: 13335, name: "CLOUDFLARENET", country: "US" });
  assert.equal(findInShard(sh, ipv4ToU32("1.0.2.0")), null);
  let calls = 0;
  const fetchFn = async (u) => { calls++; assert.equal(u, "/x/1.json"); return { ok: true, json: async () => sh }; };
  assert.equal((await asnFor("1.0.1.9", { base: "/x/", fetchFn })).asn, 64500);
  await asnFor("1.0.0.9", { base: "/x/", fetchFn });
  assert.equal(calls, 1); // shard cached
  assert.equal(await asnFor("9.9.9.9", { base: "/x/", fetchFn, octets: [1] }), null);
  assert.equal(calls, 1); // missing shard never requested
});

console.log(`ok: ${n} tests passed`);
