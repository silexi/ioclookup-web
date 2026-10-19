import { extract, isNonRoutableIPv4 } from "./extract.js";
import { loadFeeds, ensureTypes, feedsForType, matchLocal } from "./match.js";
import { SOURCES, sourcesFor, keyFor } from "./sources.js";
import { PLATFORMS, buildQuery } from "./queries.js";
import { pivotsFor } from "./pivots.js";
import { asnFor } from "./asn.js";

const STALE_HOURS = 48;
const KEYS = "ioclookup_keys";
const LANG = "ioclookup_lang";

const T = {
  en: {
    keys: "API keys", lead: "Paste an alert, an email, a report or a log. Indicators are extracted in your browser. Nothing you paste is sent anywhere unless you run a lookup.",
    inputLabel: "Text to scan", clear: "Clear", lookup: "Look up",
    counts: (n, by) => n ? `${n} indicators: ${by}` : "No indicators found yet.",
    noKeys: "Add API keys to also look indicators up in services such as ThreatFox, URLhaus, AbuseIPDB, VirusTotal and OTX.",
    lookupNote: (srcs) => `Lookup sends each indicator to: ${srcs}. Private and reserved IP addresses are never sent.`,
    type: "Type", value: "Indicator", local: "Published feeds", external: "Your lookups",
    noLocal: (names) => `not in ${names}`, noFeed: "no published feed for this type", inFeed: "listed in",
    listed: "listed", notListed: "not listed", error: "error", pending: "waiting", running: "querying", skipped: "not sent (private address)",
    notClean: "Not being listed is not the same as being safe. It only means these sources have no record.",
    sourcesTitle: "Sources", sourcesIntro: "Published feeds are downloaded once a day and matched in your browser. Only feeds whose license allows redistribution are published. Other services are queried with your own key, only when you ask.",
    feedLine: (f) => `${f.name}: ${f.count.toLocaleString("en-US")} records, license ${f.license}`,
    updated: "updated", stale: (h) => `Feed data is ${h} hours old. The list shows the last successful update.`,
    keysTitle: "API keys", keysIntro: "Keys stay in this browser. Services that do not accept browser requests are reached through this site's pass-through, which forwards the key and stores nothing (source code linked below).",
    remember: "Remember keys in this browser (otherwise they are forgotten when the tab closes)", cancel: "Cancel", save: "Save", getKey: "get a key",
    viaProxy: "via this site's pass-through", direct: "directly from your browser",
    asn: (a) => `AS${a.asn} ${a.name}${a.country ? " · " + a.country : ""}`, open: "Open in:",
    huntTitle: "Hunting queries", huntIntro: (d) => `Search your own logs for these indicators over the last ${d} days. Field and table names follow each platform's common schema; adjust them to your environment.`,
    huntSplunk: "Run each search on its own.", huntSkipped: (n) => `${n} private or reserved address(es) left out.`, huntNone: "No indicators that can be searched for in logs.",
    copy: "Copy", copied: "Copied", days: "Days",
    source: "Source code", loadError: "Feed data could not be loaded. Extraction still works.",
  },
  tr: {
    keys: "API anahtarları", lead: "Bir alarm, e-posta, rapor ya da log yapıştırın. Göstergeler tarayıcınızda çıkarılır. Sorgu çalıştırmadığınız sürece yapıştırdığınız hiçbir şey bir yere gönderilmez.",
    inputLabel: "Taranacak metin", clear: "Temizle", lookup: "Sorgula",
    counts: (n, by) => n ? `${n} gösterge: ${by}` : "Henüz gösterge bulunmadı.",
    noKeys: "ThreatFox, URLhaus, AbuseIPDB, VirusTotal ve OTX gibi servislerde de sorgulamak için API anahtarı ekleyin.",
    lookupNote: (srcs) => `Sorgu her göstergeyi şu servislere gönderir: ${srcs}. Özel ve ayrılmış IP adresleri hiçbir zaman gönderilmez.`,
    type: "Tür", value: "Gösterge", local: "Yayımlanan feed'ler", external: "Sorgularınız",
    noLocal: (names) => `${names} içinde yok`, noFeed: "bu tür için yayımlanan feed yok", inFeed: "listede:",
    listed: "listede", notListed: "listede yok", error: "hata", pending: "bekliyor", running: "sorgulanıyor", skipped: "gönderilmedi (özel adres)",
    notClean: "Listede olmamak güvenli olmak demek değildir. Yalnızca bu kaynaklarda kayıt olmadığını gösterir.",
    sourcesTitle: "Kaynaklar", sourcesIntro: "Yayımlanan feed'ler günde bir kez indirilir ve tarayıcınızda eşleştirilir. Yalnızca lisansı yeniden dağıtıma izin veren feed'ler yayımlanır. Diğer servisler, siz istediğinizde, kendi anahtarınızla sorgulanır.",
    feedLine: (f) => `${f.name}: ${f.count.toLocaleString("tr-TR")} kayıt, lisans ${f.license}`,
    updated: "güncelleme", stale: (h) => `Feed verisi ${h} saatlik. Liste son başarılı güncellemeyi gösteriyor.`,
    keysTitle: "API anahtarları", keysIntro: "Anahtarlar bu tarayıcıda kalır. Tarayıcıdan gelen isteği kabul etmeyen servislere bu sitenin aktarıcısı üzerinden gidilir; aktarıcı anahtarı iletir, hiçbir şey saklamaz (kaynak kodu aşağıda).",
    remember: "Anahtarları bu tarayıcıda hatırla (aksi halde sekme kapanınca silinir)", cancel: "İptal", save: "Kaydet", getKey: "anahtar al",
    viaProxy: "bu sitenin aktarıcısı üzerinden", direct: "doğrudan tarayıcınızdan",
    asn: (a) => `AS${a.asn} ${a.name}${a.country ? " · " + a.country : ""}`, open: "Aç:",
    huntTitle: "Arama sorguları", huntIntro: (d) => `Bu göstergeleri son ${d} gündeki kendi loglarınızda arayın. Tablo ve alan adları her platformun ortak şemasına göre; ortamınıza göre düzenleyin.`,
    huntSplunk: "Her aramayı ayrı çalıştırın.", huntSkipped: (n) => `${n} özel ya da ayrılmış adres dışarıda bırakıldı.`, huntNone: "Loglarda aranabilecek gösterge yok.",
    copy: "Kopyala", copied: "Kopyalandı", days: "Gün",
    source: "Kaynak kodu", loadError: "Feed verisi yüklenemedi. Gösterge çıkarma yine çalışır.",
  },
};
let lang = "en";
const t = (k, ...a) => { const v = T[lang][k]; return typeof v === "function" ? v(...a) : v; };
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

let db = null;
let asnInfo = new Map(); // ip -> { asn, name, country } | null
let huntPlatform = "kql";
let huntDays = 30;
let iocs = [];
let lookups = new Map(); // `${source}|${type}|${value}` -> result
const store = (s) => { try { return window[s]; } catch { return null; } };

function readKeys() {
  for (const s of [store("localStorage"), store("sessionStorage")]) {
    try { const v = s && s.getItem(KEYS); if (v) return JSON.parse(v); } catch { /* ignore */ }
  }
  return {};
}
function writeKeys(keys, remember) {
  const [keep, drop] = remember ? [store("localStorage"), store("sessionStorage")] : [store("sessionStorage"), store("localStorage")];
  try { drop && drop.removeItem(KEYS); keep && keep.setItem(KEYS, JSON.stringify(keys)); } catch { /* storage disabled */ }
}
let keys = readKeys();

function scan() {
  iocs = extract($("input").value, { tlds: db?.tlds || undefined });
  render();
  enrichAsn();
  if (db) ensureTypes(db, [...new Set(iocs.map((i) => i.type))]).then(render);
}

async function enrichAsn() {
  const octets = db?.meta?.asn?.octets;
  if (!octets) return;
  const todo = iocs.filter((i) => i.type === "ipv4" && !asnInfo.has(i.value) && !isNonRoutableIPv4(i.value));
  if (!todo.length) return;
  await Promise.all(todo.map(async (i) => asnInfo.set(i.value, await asnFor(i.value, { octets }).catch(() => null))));
  render();
}

function render() {
  const by = {};
  for (const i of iocs) by[i.type] = (by[i.type] || 0) + 1;
  $("counts").textContent = t("counts", iocs.length, Object.entries(by).map(([k, v]) => `${v} ${k}`).join(", "));
  for (const id of ["exportCsv", "exportJson"]) $(id).disabled = !iocs.length;
  const usable = SOURCES.filter((s) => s.noKey || keyFor(s, keys));
  $("lookupBtn").disabled = !iocs.length || !usable.length;
  const keyed = usable.some((s) => !s.noKey);
  $("lookupNote").textContent = t("lookupNote", [...new Set(usable.map((s) => s.name))].join(", ")) + (keyed ? "" : " " + t("noKeys"));
  renderHunt();

  const box = $("results");
  box.textContent = "";
  if (!iocs.length) return;
  const table = el("table");
  const head = el("tr");
  for (const h of [t("type"), t("value"), t("local"), t("external")]) head.append(el("th", "", h));
  const thead = el("thead"); thead.append(head); table.append(thead);
  const body = el("tbody");
  for (const ioc of iocs) {
    const tr = el("tr");
    tr.append(el("td", "type", ioc.type));
    const v = el("td", "value"); v.append(el("code", "", ioc.value));
    const a = asnInfo.get(ioc.value);
    if (a) v.append(el("div", "meta", t("asn", a)));
    const pv = ioc.type === "ipv4" && isNonRoutableIPv4(ioc.value) ? [] : pivotsFor(ioc);
    if (pv.length) {
      const line = el("div", "pivots meta", t("open") + " ");
      pv.forEach((p, k) => { const link = el("a", "", p.name); link.href = p.url; link.target = "_blank"; link.rel = "noopener noreferrer"; line.append(link); if (k < pv.length - 1) line.append(" · "); });
      v.append(line);
    }
    tr.append(v);
    const loc = el("td");
    if (db) {
      const hits = matchLocal(db, ioc);
      const feeds = feedsForType(db, ioc.type);
      if (hits.length) for (const h of hits) {
        const b = el("div", "hit", `${t("inFeed")} ${h.name}`);
        if (h.detail || h.link) {
          const m = el("div", "meta", h.detail);
          if (h.link) { const a = el("a", "", h.detail ? " ↗" : "↗"); a.href = h.link; a.target = "_blank"; a.rel = "noopener noreferrer"; m.append(a); }
          b.append(m);
        }
        loc.append(b);
      }
      else loc.append(el("span", "meta", feeds.length ? t("noLocal", feeds.map((f) => f.name).join(", ")) : t("noFeed")));
    }
    tr.append(loc);
    const ext = el("td");
    for (const s of sourcesFor(ioc.type, keys)) {
      const r = lookups.get(`${s.id}|${ioc.type}|${ioc.value}`);
      if (!r) continue;
      const line = el("div", `ext ${r.status}`);
      line.append(el("strong", "", s.name + ": "));
      line.append(document.createTextNode(r.status === "info" ? r.summary : t(r.status === "not_listed" ? "notListed" : r.status) + (r.summary ? ` (${r.summary})` : "")));
      if (r.link) { const a = el("a", "", "↗"); a.href = r.link; a.target = "_blank"; a.rel = "noopener noreferrer"; line.append(" ", a); }
      ext.append(line);
    }
    tr.append(ext);
    body.append(tr);
  }
  table.append(body);
  const wrap = el("div", "tablewrap");
  wrap.append(table);
  box.append(wrap);
  box.append(el("p", "meta", t("notClean")));
}

function renderHunt() {
  const box = $("hunt");
  box.hidden = !iocs.length;
  if (!iocs.length) return;
  $("huntIntro").textContent = t("huntIntro", huntDays);
  for (const b of $("huntTabs").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.platform === huntPlatform));
  const { text, skipped } = buildQuery(huntPlatform, iocs, huntDays);
  $("huntText").value = text || t("huntNone");
  $("huntCopy").disabled = !text;
  $("huntNote").textContent = [huntPlatform === "spl" && text ? t("huntSplunk") : "", skipped ? t("huntSkipped", skipped) : ""].filter(Boolean).join(" ");
}

async function lookupAll() {
  $("lookupBtn").disabled = true;
  const lastCall = {};
  for (const ioc of iocs) {
    for (const s of sourcesFor(ioc.type, keys)) {
      const id = `${s.id}|${ioc.type}|${ioc.value}`;
      if (lookups.has(id) && lookups.get(id).status !== "error") continue;
      if (ioc.type === "ipv4" && isNonRoutableIPv4(ioc.value)) { lookups.set(id, { status: "skipped", summary: "", link: "" }); continue; }
      if (s.minIntervalMs && lastCall[s.id]) {
        const wait = lastCall[s.id] + s.minIntervalMs - Date.now();
        if (wait > 0) { lookups.set(id, { status: "pending", summary: "", link: "" }); render(); await new Promise((r) => setTimeout(r, wait)); }
      }
      lookups.set(id, { status: "running", summary: "", link: "" });
      render();
      try { lookups.set(id, await s.query(ioc, keyFor(s, keys))); } catch (e) { lookups.set(id, { status: "error", summary: String(e.message || e), link: "" }); }
      lastCall[s.id] = Date.now();
      render();
    }
  }
  render();
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a"); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function rows() {
  return iocs.map((i) => ({
    type: i.type, value: i.value,
    asn: asnInfo.get(i.value) ? `AS${asnInfo.get(i.value).asn} ${asnInfo.get(i.value).name}` : "",
    feeds: db ? matchLocal(db, i).map((h) => h.feed).join(";") : "",
    lookups: SOURCES.map((s) => lookups.get(`${s.id}|${i.type}|${i.value}`)).map((r, k) => r ? `${SOURCES[k].id}:${r.status}` : "").filter(Boolean).join(";"),
  }));
}
const csvCell = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

function renderSources() {
  const box = $("feedList");
  box.textContent = "";
  if (!db) return;
  const ul = el("ul");
  if (db.meta.asn) {
    const m = db.meta.asn;
    const li = el("li", "", `AS: ${m.ranges.toLocaleString(lang === "tr" ? "tr-TR" : "en-US")} IPv4 ranges, license ${m.license} · `);
    const a = el("a", "", m.attribution); a.href = m.home; a.rel = "noopener"; li.append(a);
    li.append(el("span", "meta", ` · ${t("updated")} ${new Date(m.fetched).toISOString().slice(0, 16).replace("T", " ")} UTC`));
    ul.append(li);
  }
  for (const f of db.meta.feeds) {
    const li = el("li", "", t("feedLine", f) + " · ");
    const a = el("a", "", f.attribution); a.href = f.home; a.rel = "noopener"; li.append(a);
    li.append(el("span", "meta", ` · ${t("updated")} ${new Date(f.fetched).toISOString().slice(0, 16).replace("T", " ")} UTC`));
    ul.append(li);
  }
  for (const s of SOURCES) {
    const li = el("li", "", `${s.name}: ${s.proxied ? t("viaProxy") : t("direct")}`);
    ul.append(li);
  }
  box.append(ul);
  const h = Math.floor((Date.now() - new Date(db.meta.generated).getTime()) / 3600000);
  $("staleWarn").hidden = h < STALE_HOURS;
  $("staleWarn").textContent = t("stale", h);
}

function openKeys() {
  const box = $("keyFields");
  box.textContent = "";
  const seen = new Set();
  for (const s of SOURCES) {
    if (s.noKey) continue;
    const id = s.sharesKeyWith || s.id;
    if (seen.has(id)) continue;
    seen.add(id);
    const lab = el("label", "field");
    const name = el("span", "", s.keyLabel + " ");
    const a = el("a", "", t("getKey")); a.href = s.keyUrl; a.target = "_blank"; a.rel = "noopener noreferrer";
    name.append(a);
    const input = el("input"); input.type = "password"; input.autocomplete = "off"; input.dataset.id = id; input.value = keys[id] || "";
    lab.append(name, input);
    box.append(lab);
  }
  $("rememberKeys").checked = !!store("localStorage")?.getItem?.(KEYS);
  $("keysDialog").showModal();
}
$("keysDialog").addEventListener("close", () => {
  if ($("keysDialog").returnValue !== "save") return;
  const next = {};
  for (const i of $("keyFields").querySelectorAll("input")) if (i.value.trim()) next[i.dataset.id] = i.value.trim();
  keys = next;
  writeKeys(keys, $("rememberKeys").checked);
  render();
});

function applyLang(l) {
  lang = T[l] ? l : "en";
  document.documentElement.lang = lang;
  for (const e of document.querySelectorAll("[data-i18n]")) e.textContent = t(e.dataset.i18n);
  for (const b of document.querySelectorAll("[data-lang]")) b.setAttribute("aria-pressed", String(b.dataset.lang === lang));
  $("input").placeholder = lang === "tr" ? "Örnek: hxxps://login-microsoft[.]com/auth 185.220.101.4 CVE-2024-3400" : "Example: hxxps://login-microsoft[.]com/auth 185.220.101.4 CVE-2024-3400";
  render();
  renderSources();
}

for (const b of document.querySelectorAll("[data-lang]")) b.addEventListener("click", () => { try { localStorage.setItem(LANG, b.dataset.lang); } catch {} applyLang(b.dataset.lang); });
$("keysBtn").addEventListener("click", openKeys);
$("lookupBtn").addEventListener("click", lookupAll);
$("clearBtn").addEventListener("click", () => { $("input").value = ""; lookups = new Map(); asnInfo = new Map(); scan(); });
$("exportJson").addEventListener("click", () => download("iocs.json", JSON.stringify(rows(), null, 2), "application/json"));
$("exportCsv").addEventListener("click", () => download("iocs.csv", ["type,value,asn,feeds,lookups", ...rows().map((r) => [r.type, r.value, r.asn, r.feeds, r.lookups].map(csvCell).join(","))].join("\n") + "\n", "text/csv"));
for (const p of PLATFORMS) {
  const b = el("button", "", p.name); b.type = "button"; b.dataset.platform = p.id;
  b.addEventListener("click", () => { huntPlatform = p.id; renderHunt(); });
  $("huntTabs").append(b);
}
$("huntDays").addEventListener("change", () => { const d = parseInt($("huntDays").value, 10); huntDays = d > 0 && d <= 365 ? d : 30; $("huntDays").value = huntDays; renderHunt(); });
$("huntCopy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("huntText").value); } catch { $("huntText").select(); document.execCommand("copy"); }
  $("huntCopy").textContent = t("copied"); setTimeout(() => { $("huntCopy").textContent = t("copy"); }, 1500);
});
let timer = 0;
$("input").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(scan, 150); });

const saved = (() => { try { return localStorage.getItem(LANG); } catch { return null; } })();
applyLang(saved || ((navigator.language || "").toLowerCase().startsWith("tr") ? "tr" : "en"));
loadFeeds("/data/").then((d) => { db = d; scan(); renderSources(); }).catch(() => { $("feedList").textContent = t("loadError"); });
