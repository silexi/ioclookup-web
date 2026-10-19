// Matching against the published snapshots in /data. Everything runs in the browser.
// Only feeds whose license allows redistribution are published (see scripts/build_feeds.py).

export async function loadFeeds(base = "data/", fetchFn = fetch) {
  const get = async (name, kind = "json") => {
    const r = await fetchFn(base + name, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${name}: ${r.status}`);
    return kind === "json" ? r.json() : r.text();
  };
  const meta = await get("meta.json");
  const feeds = {};
  await Promise.all(meta.feeds.map(async (f) => {
    const body = await get(`${f.id}.json`);
    feeds[f.id] = body.ips ? { ...f, set: new Set(body.ips) } : { ...f, cves: body.cves };
  }));
  let tlds = null;
  try { tlds = new Set((await get("tlds.txt", "text")).split("\n").filter(Boolean)); } catch { /* fallback list in extract.js */ }
  return { meta, feeds, tlds };
}

// Which published feeds can say anything about an indicator of this type.
export function feedsForType(db, type) {
  return Object.values(db.feeds).filter((f) => f.types.includes(type));
}

export function matchLocal(db, ioc) {
  const hits = [];
  for (const f of feedsForType(db, ioc.type)) {
    if (f.set && f.set.has(ioc.value)) hits.push({ feed: f.id, name: f.name, detail: "" });
    if (f.cves && f.cves[ioc.value]) {
      const c = f.cves[ioc.value];
      hits.push({ feed: f.id, name: f.name, detail: `${c.vendor} ${c.product}: ${c.name} (added ${c.added}${c.ransomware ? ", used in ransomware" : ""})` });
    }
  }
  return hits;
}
