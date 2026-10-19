// node tests/extract.test.mjs
import assert from "node:assert/strict";
import { extract, refang, isNonRoutableIPv4 } from "../public/js/extract.js";

let n = 0;
const t = (name, fn) => { fn(); n++; };
const vals = (text, type) => extract(text).filter((x) => x.type === type).map((x) => x.value);

t("refang", () => {
  assert.equal(refang("hxxps://evil[.]example[.]com/a"), "https://evil.example.com/a");
  assert.equal(refang("1.2.3[.]4 and user[@]mail(.)ru"), "1.2.3.4 and user@mail.ru");
  assert.equal(refang("hxxp[://]bad[dot]com"), "http://bad.com");
});

t("urls and their hosts", () => {
  const r = extract("see hxxps://login-microsoft[.]com/auth?x=1, then http://93.184.216.34:8080/p.");
  assert.deepEqual(r.filter((x) => x.type === "url").map((x) => x.value), ["https://login-microsoft.com/auth?x=1", "http://93.184.216.34:8080/p"]);
  assert.deepEqual(vals("hxxps://login-microsoft[.]com/a", "domain"), ["login-microsoft.com"]);
  assert.deepEqual(vals("http://93.184.216.34:8080/p", "ipv4"), ["93.184.216.34"]);
});

t("ipv4 validation", () => {
  assert.deepEqual(vals("8.8.8.8 999.1.1.1 1.2.3 01.2.3.4 10.0.0.256", "ipv4"), ["8.8.8.8"]);
  assert.deepEqual(vals("version 1.2.3.4.5", "ipv4"), []);
});

t("ipv6", () => {
  assert.deepEqual(vals("c2 at 2001:db8::1 and 2001:0db8:0000:0000:0000:0000:0000:0002", "ipv6"), ["2001:db8::1", "2001:db8::2"]);
  assert.deepEqual(vals("at 12:30:45 today", "ipv6"), []);
});

t("domains need a real TLD", () => {
  assert.deepEqual(vals("evil.ru, payload.exe, config.json, sub.domain.co.uk", "domain"), ["evil.ru", "sub.domain.co.uk"]);
  assert.deepEqual(vals("custom.tld", "domain", { tlds: new Set(["tld"]) }), []);
  assert.deepEqual(extract("custom.tld", { tlds: new Set(["tld"]) }).map((x) => x.value), ["custom.tld"]);
});

t("emails", () => {
  const r = extract("from: Attacker@Evil.ru");
  assert.deepEqual(r.map((x) => [x.type, x.value]), [["domain", "evil.ru"], ["email", "attacker@evil.ru"]]);
});

t("hashes by length", () => {
  const md5 = "d41d8cd98f00b204e9800998ecf8427e", sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  const sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
  assert.deepEqual(extract(`${md5} ${sha1} ${sha256} ${"a".repeat(50)}`).map((x) => x.type), ["md5", "sha1", "sha256"]);
  assert.equal(vals(sha256, "sha256")[0], sha256.toLowerCase());
});

t("cve", () => assert.deepEqual(vals("patch cve-2024-3400 and CVE-2021-44228", "cve"), ["CVE-2024-3400", "CVE-2021-44228"]));

t("dedup and order", () => {
  const r = extract("1.1.1.1 1.1.1.1 evil.ru http://evil.ru/x");
  assert.deepEqual(r.map((x) => x.type), ["url", "domain", "ipv4"]);
});

t("non-routable", () => {
  for (const ip of ["10.1.2.3", "192.168.1.1", "172.20.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.2.10", "198.51.100.7", "203.0.113.9", "224.0.0.1"]) assert.ok(isNonRoutableIPv4(ip), ip);
  for (const ip of ["8.8.8.8", "192.0.3.1", "172.32.0.1", "198.51.101.1"]) assert.ok(!isNonRoutableIPv4(ip), ip);
});

t("large input stays fast", () => {
  const blob = ("noise text 1.2.3.4 evil[.]com hxxp://x[.]ru/a d41d8cd98f00b204e9800998ecf8427e ").repeat(15000);
  const t0 = performance.now();
  extract(blob);
  const ms = performance.now() - t0;
  assert.ok(ms < 2000, `took ${ms}ms for ${blob.length} chars`);
});

console.log(`ok: ${n} tests passed`);
