import { extract, isNonRoutableIPv4 } from "./extract.js";
import { loadFeeds, feedsForType, matchLocal } from "./match.js";
import { SOURCES, sourcesFor, keyFor } from "./sources.js";

const STALE_HOURS = 48;
const KEYS = "ioclookup_keys";
const LANG = "ioclookup_lang";

const T = {
  en: {
    keys: "API keys", lead: "Paste an alert, an email, a report or a log. Indicators are extracted in your browser. Nothing you paste is sent anywhere unless you run a lookup.",
    inputLabel: "Text to scan", clear: "Clear", lookup: "Look up with my keys",
    counts: (n, by) => n ? `${n} indicators: ${by}` : "No indicators found yet.",
    noKeys: "Add API keys to look indicators up in services such as ThreatFox, URLhaus, AbuseIPDB, VirusTotal and OTX.",
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
    privacy: "No account, no tracking. Pasted text is processed in your browser.", source: "Source code", loadError: "Feed data could not be loaded. Extraction still works.",
  },
  tr: {
    keys: "API anahtarları", lead: "Bir alarm, e-posta, rapor ya da log yapıştırın. Göstergeler tarayıcınızda çıkarılır. Sorgu çalıştırmadığınız sürece yapıştırdığınız hiçbir şey bir yere gönderilmez.",
    inputLabel: "Taranacak metin", clear: "Temizle", lookup: "Anahtarlarımla sorgula",
    counts: (n, by) => n ? `${n} gösterge: ${by}` : "Henüz gösterge bulunmadı.",
    noKeys: "ThreatFox, URLhaus, AbuseIPDB, VirusTotal ve OTX gibi servislerde sorgulamak için API anahtarı ekleyin.",
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
    privacy: "Hesap yok, takip yok. Yapıştırılan metin tarayıcınızda işlenir.", source: "Kaynak kodu", loadError: "Feed verisi yüklenemedi. Gösterge çıkarma yine çalışır.",
  },
};
let lang = "en";
const t = (k, ...a) => { const v = T[lang][k]; return typeof v === "function" ? v(...a) : v; };
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

let db = null;
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
}

function render() {
  const by = {};
  for (const i of iocs) by[i.type] = (by[i.type] || 0) + 1;
  $("counts").textContent = t("counts", iocs.length, Object.entries(by).map(([k, v]) => `${v} ${k}`).join(", "));
  for (const id of ["exportCsv", "exportJson"]) $(id).disabled = !iocs.length;
  const usable = SOURCES.filter((s) => keyFor(s, keys));
  $("lookupBtn").disabled = !iocs.length || !usable.length;
  $("lookupNote").textContent = usable.length ? t("lookupNote", [...new Set(usable.map((s) => s.name))].join(", ")) : t("noKeys");

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
    const v = el("td", "value"); v.append(el("code", "", ioc.value)); tr.append(v);
    const loc = el("td");
    if (db) {
      const hits = matchLocal(db, ioc);
      const feeds = feedsForType(db, ioc.type);
      if (hits.length) for (const h of hits) { const b = el("div", "hit", `${t("inFeed")} ${h.name}`); if (h.detail) b.append(el("div", "meta", h.detail)); loc.append(b); }
      else loc.append(el("span", "meta", feeds.length ? t("noLocal", feeds.map((f) => f.name).join(", ")) : t("noFeed")));
    }
    tr.append(loc);
    const ext = el("td");
    for (const s of sourcesFor(ioc.type, keys)) {
      const r = lookups.get(`${s.id}|${ioc.type}|${ioc.value}`);
      if (!r) continue;
      const line = el("div", `ext ${r.status}`);
      line.append(el("strong", "", s.name + ": "));
      line.append(document.createTextNode(t(r.status === "not_listed" ? "notListed" : r.status) + (r.summary ? ` (${r.summary})` : "")));
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
$("clearBtn").addEventListener("click", () => { $("input").value = ""; lookups = new Map(); scan(); });
$("exportJson").addEventListener("click", () => download("iocs.json", JSON.stringify(rows(), null, 2), "application/json"));
$("exportCsv").addEventListener("click", () => download("iocs.csv", ["type,value,feeds,lookups", ...rows().map((r) => [r.type, r.value, r.feeds, r.lookups].map(csvCell).join(","))].join("\n") + "\n", "text/csv"));
let timer = 0;
$("input").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(scan, 150); });

const saved = (() => { try { return localStorage.getItem(LANG); } catch { return null; } })();
applyLang(saved || ((navigator.language || "").toLowerCase().startsWith("tr") ? "tr" : "en"));
loadFeeds("/data/").then((d) => { db = d; scan(); renderSources(); }).catch(() => { $("feedList").textContent = t("loadError"); });
