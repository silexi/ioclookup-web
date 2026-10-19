// Browser test. Start `npx wrangler dev --port 8795` with sample data first.
// BASE=http://127.0.0.1:8795 PLAYWRIGHT_MODULE=/path/to/playwright node tests/e2e.mjs
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const BASE = process.env.BASE || "http://127.0.0.1:8795";
const OUT = process.env.SHOTS || "";

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: "en-US" });
const page = await ctx.newPage();
const errors = [];
const external = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("pageerror", (e) => errors.push(String(e)));
page.on("request", (r) => { if (!r.url().startsWith(BASE)) external.push(r.url()); });

await page.goto(BASE + "/");
await page.waitForFunction(() => document.getElementById("feedList").textContent.includes("records"));
await page.fill("#input", "Phish from hxxps://login-microsoft[.]com/auth via 185.220.0.5 and 10.0.0.1, exploit CVE-2024-3400, hash d41d8cd98f00b204e9800998ecf8427e, contact bad@evil.ru, relay 2.1.2.3, dropper bad7.example.com, scanner 77.88.0.5, implant 45.9.1.1");
await page.waitForFunction(() => document.querySelectorAll("#results tbody tr").length >= 7);
// feed files for the pasted types load after the first render
await page.waitForFunction(() => /listed in Tor exit nodes/.test(document.querySelector("#results").textContent) && /PAN-OS/.test(document.querySelector("#results").textContent));
const rows = await page.$$eval("#results tbody tr", (trs) => trs.map((tr) => [...tr.children].map((td) => td.textContent.trim())));
const find = (v) => rows.find((r) => r[1].startsWith(v));
assert.ok(find("https://login-microsoft.com/auth"));
assert.match(find("185.220.0.5")[2], /listed in Tor exit nodes/);
assert.match(find("CVE-2024-3400")[2], /PAN-OS/);
assert.match(find("10.0.0.1")[2], /private or reserved address/);
assert.match(find("d41d8cd98f00b204e9800998ecf8427e")[2], /not in TweetFeed/);
assert.match(find("bad@evil.ru")[2], /no published feed/);
await page.waitForFunction(() => document.querySelector("#results").textContent.includes("listed in TweetFeed"));
assert.match((await page.$$eval("#results tbody tr", (trs) => trs.map((tr) => tr.textContent))).find((x) => x.includes("bad7.example.com")), /listed in TweetFeed@user2, 2026-10-0\d/);
// keyless source (InternetDB) makes lookup available, keyed services are offered
assert.ok(!(await page.isDisabled("#lookupBtn")));
assert.match(await page.textContent("#lookupNote"), /USOM.*Shodan InternetDB.*Add API keys/);
// ASN context and pivot links
await page.waitForFunction(() => [...document.querySelectorAll("#results td.value")].some((td) => /AS645\d\d EXAMPLE-AS/.test(td.textContent)));
assert.match(find("185.220.0.5")[1], /Open in: VirusTotal · AbuseIPDB · Shodan/);
assert.doesNotMatch(find("10.0.0.1")[1], /Open in/);
assert.equal(await page.getAttribute('#results a:text("NVD")', "href"), "https://nvd.nist.gov/vuln/detail/CVE-2024-3400");
// hunting queries
assert.ok(await page.isVisible("#hunt"));
let q = await page.inputValue("#huntText");
assert.match(q, /union isfuzzy=true/);
assert.ok(q.includes("185.220.0.5") && !q.includes("10.0.0.1"));
assert.match(await page.textContent("#huntNote"), /1 private or reserved/);
await page.click('#huntTabs button[data-platform="aql"]');
await page.fill("#huntDays", "7");
await page.dispatchEvent("#huntDays", "change");
q = await page.inputValue("#huntText");
assert.match(q, /LAST 7 DAYS/);
if (OUT) await page.screenshot({ path: `${OUT}/ioc-en.png`, fullPage: true });

// keys dialog: session only by default
await page.click("#keysBtn");
await page.fill('#keyFields input[data-id="otx"]', "test-otx-key");
await page.click('#keysDialog button[value="save"]');
await page.waitForFunction(() => !!sessionStorage.getItem("ioclookup_keys"));
assert.equal(await page.evaluate(() => localStorage.getItem("ioclookup_keys")), null);
assert.match(await page.evaluate(() => sessionStorage.getItem("ioclookup_keys")), /test-otx-key/);
assert.ok(!(await page.isDisabled("#lookupBtn")));
assert.match(await page.textContent("#lookupNote"), /AlienVault OTX/);

// nothing left the page before an explicit lookup
assert.deepEqual(external, []);

// server-side matching: the private lists are never served, only matches come back
assert.equal((await page.request.get(BASE + "/_private/ipv4/0.json")).status(), 404);
assert.match(await page.textContent("#lookupNote"), /this site's server \(matched against CINS Army;/);
await page.route((u) => !u.href.startsWith(BASE), (r) => r.abort());
await page.click("#lookupBtn");
await page.waitForFunction(() => /CINS Army: listed/.test(document.querySelector("#results").textContent));
const after = await page.$$eval("#results tbody tr", (trs) => trs.map((tr) => tr.textContent));
assert.match(after.find((x) => x.includes("77.88.0.5")), /CINS Army: listed/);
assert.match(after.find((x) => x.includes("185.220.0.5")), /CINS Army: not listed/);
await page.unroute(() => true);

await page.click("[data-lang=tr]");
assert.match(await page.textContent("#lookupBtn"), /Sorgula/);
assert.match(await page.textContent("#hunt h2"), /Arama sorguları/);
if (OUT) await page.screenshot({ path: `${OUT}/ioc-tr.png`, fullPage: true });
await page.setViewportSize({ width: 375, height: 800 });
const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
assert.ok(overflow <= 0, `overflow ${overflow}`);
if (OUT) await page.screenshot({ path: `${OUT}/ioc-mobile.png`, fullPage: true });
assert.deepEqual(errors.filter((e) => !e.includes("net::ERR_FAILED")), []); // ERR_FAILED: external lookups aborted on purpose
await browser.close();
console.log("ok: e2e passed");
