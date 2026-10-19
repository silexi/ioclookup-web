// IPv4 address -> AS number, AS name and country, from the IPtoASN snapshot in /data/asn/v4/.
// The snapshot is split by first octet; only the files that cover the pasted addresses are loaded.

const shards = new Map(); // octet -> Promise<shard | null>

export function ipv4ToU32(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function load(octet, base, fetchFn) {
  if (!shards.has(octet)) {
    shards.set(octet, fetchFn(`${base}${octet}.json`).then((r) => (r.ok ? r.json() : null)).catch(() => null));
  }
  return shards.get(octet);
}

export function findInShard(sh, n) {
  let lo = 0, hi = sh.s.length - 1, at = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sh.s[mid] <= n) { at = mid; lo = mid + 1; } else hi = mid - 1;
  }
  if (at < 0 || n > sh.e[at]) return null;
  const asn = sh.a[at];
  const [name, country] = sh.names[String(asn)] || ["", ""];
  return { asn, name, country };
}

// `octets` is meta.asn.octets: the shard files that exist. Addresses outside them have no route.
export async function asnFor(ip, { base = "/data/asn/v4/", fetchFn = fetch, octets = null } = {}) {
  const n = ipv4ToU32(ip);
  if (octets && !octets.includes(n >>> 24)) return null;
  const sh = await load(n >>> 24, base, fetchFn);
  return sh ? findInShard(sh, n) : null;
}
