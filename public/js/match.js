// Matching against the published snapshots in /data. Everything runs in the browser.
// Only feeds whose license allows redistribution are published (see scripts/build_feeds.py).
// Each feed is split into one file per indicator type (<id>.<type>.json); a file is downloaded
// only when an indicator of that type is on the page.

export async function loadFeeds(base = "data/", fetchFn = fetch) {
  const get = async (name, kind = "json") => {
    const r = await fetchFn(base + name, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${name}: ${r.status}`);
    return kind === "json" ? r.json() : r.text();
  };
  const meta = await get("meta.json");
  let tlds = null;
  try { tlds = new Set((await get("tlds.txt", "text")).split("\n").filter(Boolean)); } catch { /* fallback list in extract.js */ }
  return { meta, tlds, get, loaded: {}, pending: {} };
}

// Downloads the feed files needed for these indicator types. Safe to call repeatedly.
export async function ensureTypes(db, types) {
  const jobs = [];
  for (const f of db.meta.feeds) {
    for (const t of types) {
      const key = `${f.id}.${t}`;
      if (!f.files?.[t] || db.loaded[key]) continue;
      db.pending[key] ||= db.get(`${key}.json`).then((b) => { db.loaded[key] = b.v; }).catch(() => { delete db.pending[key]; });
      jobs.push(db.pending[key]);
    }
  }
  await Promise.all(jobs);
}

// Which published feeds can say anything about an indicator of this type.
export function feedsForType(db, type) {
  return db.meta.feeds.filter((f) => f.files?.[type]);
}

function describe(feedId, d) {
  if (d === null || d === undefined) return { detail: "", link: "" };
  if (feedId === "kev") return { detail: `${d.vendor} ${d.product}: ${d.name} (added ${d.added}${d.ransomware ? ", used in ransomware" : ""})`, link: "" };
  if (feedId === "tweetfeed") return { detail: `@${d[1]}, ${d[0]}`, link: d[2] };
  return { detail: typeof d === "string" ? d : "", link: "" };
}

const norm = (ioc) => (["domain", "md5", "sha1", "sha256"].includes(ioc.type) ? ioc.value.toLowerCase() : ioc.value);

export function matchLocal(db, ioc) {
  const hits = [];
  const key = norm(ioc);
  for (const f of feedsForType(db, ioc.type)) {
    const values = db.loaded[`${f.id}.${ioc.type}`];
    if (!values || !Object.prototype.hasOwnProperty.call(values, key)) continue;
    hits.push({ feed: f.id, name: f.name, ...describe(f.id, values[key]) });
  }
  return hits;
}
