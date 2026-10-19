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
await page.fill("#input", "Phish from hxxps://login-microsoft[.]com/auth via 185.220.0.5 and 10.0.0.1, exploit CVE-2024-3400, hash d41d8cd98f00b204e9800998ecf8427e, contact bad@evil.ru");
await page.waitForFunction(() => document.querySelectorAll("#results tbody tr").length >= 7);
const rows = await page.$$eval("#results tbody tr", (trs) => trs.map((tr) => [...tr.children].map((td) => td.textContent.trim())));
const find = (v) => rows.find((r) => r[1] === v);
assert.ok(find("https://login-microsoft.com/auth"));
assert.match(find("185.220.0.5")[2], /listed in Tor exit nodes/);
assert.match(find("CVE-2024-3400")[2], /PAN-OS/);
assert.match(find("10.0.0.1")[2], /not in/);
assert.match(find("d41d8cd98f00b204e9800998ecf8427e")[2], /no published feed/);
assert.ok(await page.isDisabled("#lookupBtn"), "no keys, no lookup");
assert.match(await page.textContent("#lookupNote"), /Add API keys/);
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

await page.click("[data-lang=tr]");
assert.match(await page.textContent("#lookupBtn"), /Anahtarlarımla sorgula/);
if (OUT) await page.screenshot({ path: `${OUT}/ioc-tr.png`, fullPage: true });
await page.setViewportSize({ width: 375, height: 800 });
const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
assert.ok(overflow <= 0, `overflow ${overflow}`);
if (OUT) await page.screenshot({ path: `${OUT}/ioc-mobile.png`, fullPage: true });
assert.deepEqual(errors, []);
await browser.close();
console.log("ok: e2e passed");
