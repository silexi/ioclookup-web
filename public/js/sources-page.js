// /sources/: every source the tool uses, how it is reached, its terms and freshness.
// Published feeds and server-matched lists come from data/meta.json; the rest from the source modules.
import { SOURCES } from "./sources.js";
import { pivotsFor } from "./pivots.js";

const LANG = "ioclookup_lang";
const STALE_HOURS = 48;
const T = {
  en: {
    back: "Back to lookup", title: "Sources", source: "Source code",
    intro: "Each source is used in one of five ways. The way decides what leaves your browser and when.",
    published: "Published feeds", publishedIntro: "Downloaded once a day and published on this site because their license allows it. Your browser downloads only the indicator types that are on the page and matches them locally; nothing is sent.",
    server: "Matched on this site's server", serverIntro: "The terms allow use but say nothing about republishing, so the list is kept on the server and not published. When you press Look up, the indicators are sent to this site's server and only matching entries come back. Nothing is stored.",
    direct: "Queried from your browser", directIntro: "When you press Look up, your browser asks the service directly. Private and reserved addresses are never sent.",
    keyed: "With your own key", keyedIntro: "Used only if you add an API key. Services that do not accept browser requests are reached through this site's pass-through, which forwards the key and stores nothing.",
    context: "Context", contextIntro: "Added to every public IPv4 address, from a published snapshot.",
    links: "Search links", linksIntro: "Links next to each indicator. Nothing is sent unless you click one.",
    records: (n) => `${n} records`, byType: "types", license: "license", terms: "terms", updated: "updated",
    viaProxy: "via this site's pass-through", fromBrowser: "directly from your browser", noKey: "no key needed",
    stale: (name, h) => `${name} was last updated ${h} hours ago; the source failed since then and the previous copy is shown.`,
    nc: "Non-commercial terms; removed if the site ever charges.",
    ranges: (n) => `${n} IPv4 ranges`,
    types: { ipv4: "IPv4", ipv6: "IPv6", domain: "domain", url: "URL", md5: "MD5", sha1: "SHA1", sha256: "SHA256", cve: "CVE", email: "e-mail" },
  },
  tr: {
    back: "Sorgulamaya dön", title: "Kaynaklar", source: "Kaynak kodu",
    intro: "Her kaynak beş yoldan biriyle kullanılır. Tarayıcınızdan neyin, ne zaman çıktığını bu yol belirler.",
    published: "Yayımlanan feed'ler", publishedIntro: "Günde bir kez indirilir ve lisansı izin verdiği için bu sitede yayımlanır. Tarayıcınız yalnızca sayfadaki gösterge türlerinin dosyalarını indirir ve eşleştirmeyi kendisi yapar; hiçbir şey gönderilmez.",
    server: "Bu sitenin sunucusunda eşleştirilenler", serverIntro: "Kullanım şartları kullanıma izin veriyor ama yeniden yayım hakkında bir şey söylemiyor; bu yüzden liste sunucuda tutulur, yayımlanmaz. Sorgula'ya bastığınızda göstergeler bu sitenin sunucusuna gider, yalnızca eşleşen kayıtlar döner. Hiçbir şey saklanmaz.",
    direct: "Tarayıcınızdan sorgulananlar", directIntro: "Sorgula'ya bastığınızda tarayıcınız servise doğrudan sorar. Özel ve ayrılmış adresler hiçbir zaman gönderilmez.",
    keyed: "Kendi anahtarınızla", keyedIntro: "Yalnızca API anahtarı eklerseniz kullanılır. Tarayıcı isteğini kabul etmeyen servislere bu sitenin aktarıcısı üzerinden gidilir; aktarıcı anahtarı iletir, hiçbir şey saklamaz.",
    context: "Bağlam", contextIntro: "Her açık IPv4 adresine, yayımlanan bir snapshot'tan eklenir.",
    links: "Arama bağlantıları", linksIntro: "Her göstergenin yanındaki bağlantılar. Tıklamadıkça hiçbir şey gönderilmez.",
    records: (n) => `${n} kayıt`, byType: "türler", license: "lisans", terms: "şartlar", updated: "güncelleme",
    viaProxy: "bu sitenin aktarıcısı üzerinden", fromBrowser: "doğrudan tarayıcınızdan", noKey: "anahtar gerekmez",
    stale: (name, h) => `${name} en son ${h} saat önce güncellendi; kaynak o zamandan beri hata veriyor, önceki kopya gösteriliyor.`,
    nc: "Ticari olmayan kullanım şartı; site ücretli olursa çıkarılır.",
    ranges: (n) => `${n} IPv4 aralığı`,
    types: { ipv4: "IPv4", ipv6: "IPv6", domain: "alan adı", url: "URL", md5: "MD5", sha1: "SHA1", sha256: "SHA256", cve: "CVE", email: "e-posta" },
  },
};
const NON_COMMERCIAL = new Set(["c2intel", "internetdb"]);
let lang = "en";
let meta = null;
const t = (k, ...a) => { const v = T[lang][k]; return typeof v === "function" ? v(...a) : v; };
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const num = (n) => n.toLocaleString(lang === "tr" ? "tr-TR" : "en-US");
const when = (iso) => `${t("updated")} ${new Date(iso).toISOString().slice(0, 16).replace("T", " ")} UTC`;
const link = (text, href) => { const a = el("a", "", text); a.href = href; a.rel = "noopener"; return a; };

function section(title, intro, items) {
  const s = el("section", "srcsec");
  s.append(el("h2", "", title), el("p", "meta", intro));
  const ul = el("ul", "srclist");
  for (const it of items) ul.append(it);
  s.append(ul);
  return s;
}

function item(name, href, facts, note) {
  const li = el("li");
  li.append(href ? link(name, href) : el("strong", "", name));
  for (const f of facts.filter(Boolean)) li.append(el("span", "fact", f));
  if (note) li.append(el("div", "meta", note));
  return li;
}

function render() {
  const box = document.getElementById("sections");
  box.textContent = "";
  const stale = [];
  if (meta) {
    box.append(section(t("published"), t("publishedIntro"), meta.feeds.map((f) => {
      const h = Math.floor((Date.now() - new Date(f.fetched).getTime()) / 3600000);
      if (h >= STALE_HOURS) stale.push(t("stale", f.name, h));
      const types = Object.entries(f.files || {}).map(([k, n]) => `${t("types")[k] || k} ${num(n)}`).join(", ");
      const lic = el("span", "fact");
      lic.append(`${t("license")}: `, link(f.license, f.license_url));
      const li = item(f.name, f.home, [t("records", num(f.count)), types, when(f.fetched)], NON_COMMERCIAL.has(f.id) ? t("nc") : "");
      li.insertBefore(lic, li.children[3] || null);
      return li;
    })));
    if (meta.private?.length) box.append(section(t("server"), t("serverIntro"), meta.private.map((p) =>
      item(p.name, p.home, [t("records", num(p.count)), `${t("terms")}: ${p.terms}`, when(p.fetched)]))));
  }
  const types = (s) => s.types.map((k) => t("types")[k] || k).join(", ");
  box.append(section(t("direct"), t("directIntro"), SOURCES.filter((s) => s.noKey).map((s) =>
    item(s.name, null, [types(s), t("noKey")], NON_COMMERCIAL.has(s.id) ? t("nc") : ""))));
  box.append(section(t("keyed"), t("keyedIntro"), SOURCES.filter((s) => !s.noKey).map((s) =>
    item(s.name, s.keyUrl, [types(s), s.proxied ? t("viaProxy") : t("fromBrowser")]))));
  if (meta?.asn) {
    const a = meta.asn;
    const li = item(a.attribution, a.home, [t("ranges", num(a.ranges)), when(a.fetched)]);
    const lic = el("span", "fact"); lic.append(`${t("license")}: `, link(a.license, a.license_url)); li.append(lic);
    box.append(section(t("context"), t("contextIntro"), [li]));
  }
  const names = [...new Set(["ipv4", "domain", "url", "sha256", "cve"].flatMap((type) => pivotsFor({ type, value: "x" }).map((p) => p.name)))];
  box.append(section(t("links"), t("linksIntro"), [el("li", "", names.join(" · "))]));
  const w = document.getElementById("staleWarn");
  w.hidden = !stale.length;
  w.textContent = stale.join(" ");
}

function applyLang(l) {
  lang = T[l] ? l : "en";
  document.documentElement.lang = lang;
  for (const e of document.querySelectorAll("[data-i18n]")) e.textContent = t(e.dataset.i18n);
  for (const b of document.querySelectorAll("[data-lang]")) b.setAttribute("aria-pressed", String(b.dataset.lang === lang));
  document.title = `${t("title")} · IOC Lookup`;
  render();
}
for (const b of document.querySelectorAll("[data-lang]")) b.addEventListener("click", () => { try { localStorage.setItem(LANG, b.dataset.lang); } catch {} applyLang(b.dataset.lang); });
const saved = (() => { try { return localStorage.getItem(LANG); } catch { return null; } })();
applyLang(saved || ((navigator.language || "").toLowerCase().startsWith("tr") ? "tr" : "en"));
fetch("/data/meta.json", { cache: "no-cache" }).then((r) => r.json()).then((m) => { meta = m; render(); }).catch(() => {});
