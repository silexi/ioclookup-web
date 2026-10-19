#!/usr/bin/env python3
"""Builds the feed snapshots that ioclookup.com publishes.

Only sources whose license clearly allows public redistribution are included here.
Sources without that permission are queried from the user's browser with the user's own key
instead (see public/js/sources.js), never republished.

Output (default public/data/):
  <feed>.<type>.json for each feed and indicator type, tlds.txt, meta.json
  asn/v4/<first octet>.json: IPv4 ranges with AS number, country and AS name (IPtoASN, PDDL),
  split by first octet so the browser only downloads the parts that cover the pasted addresses.

Standard library only. Each feed has a minimum record count; a feed that comes back smaller
fails the build so a broken download never replaces a good snapshot.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import ipaddress
import json
import sys
import time
import urllib.request
from pathlib import Path

UA = "ioclookup.com feed builder (+https://ioclookup.com; https://github.com/silexi/ioclookup-web)"

FEEDS = [
    {
        "id": "tor-exit",
        "name": "Tor exit nodes",
        "urls": ["https://check.torproject.org/torbulkexitlist"],
        "parser": "ip_lines",
        "home": "https://metrics.torproject.org/collector.html",
        "license": "CC0 1.0",
        "license_url": "https://metrics.torproject.org/collector.html",
        "attribution": "The Tor Project",
        "min": 300,
    },
    {
        "id": "et-compromised",
        "name": "Emerging Threats compromised IPs",
        "urls": ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"],
        "parser": "ip_lines",
        "home": "https://rules.emergingthreats.net/",
        "license": "GPL-2.0",
        "license_url": "https://community.emergingthreats.net/t/licensing-is-the-compromised-ips-list-also-open/676",
        "attribution": "Proofpoint Emerging Threats",
        "min": 50,
    },
    {
        "id": "kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "urls": ["https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"],
        "parser": "kev",
        "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "license": "CC0 1.0",
        "license_url": "https://github.com/cisagov/kev-data",
        "attribution": "CISA",
        "min": 1000,
    },
    {
        # Indicators shared by researchers on X, last 365 days. The CSV feed is CC0; the abuse.ch
        # "external" block of the TweetFeed API is not part of it and is not used here.
        "id": "tweetfeed",
        "name": "TweetFeed",
        "urls": ["https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"],
        "parser": "tweetfeed",
        "home": "https://tweetfeed.live/",
        "license": "CC0 1.0",
        "license_url": "https://tweetfeed.live/tos/",
        "attribution": "TweetFeed",
        "min": 10000,
    },
    {
        # Non-commercial licence: to be removed if the site ever charges (portfolio MK-20).
        "id": "c2intel",
        "name": "C2IntelFeeds",
        "urls": ["https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
                 "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv"],
        "parser": "c2intel",
        "home": "https://github.com/drb-ra/C2IntelFeeds",
        "license": "CC BY-NC-SA 4.0",
        "license_url": "https://github.com/drb-ra/C2IntelFeeds/blob/master/License.md",
        "attribution": "C2IntelFeeds (drb-ra)",
        "min": 50,
    },
    {
        "id": "cert-pl",
        "name": "CERT Polska warning list",
        "urls": ["https://hole.cert.pl/domains/v2/domains.txt"],
        "parser": "domain_lines",
        "home": "https://cert.pl/en/warning-list/",
        "license": "Free for any purpose, including commercial (CERT Polska data usage policy)",
        "license_url": "https://cert.pl/en/warning-list/",
        "attribution": "CERT Polska",
        "min": 1000,
    },
]
# Sources whose terms allow use but say nothing about republishing. They are never published as
# files: the build writes them under public/_private/, the Worker refuses public requests for that
# path and answers only /api/match, which returns the matching entries (portfolio S-19, MK-21).
# Botvrij.eu was evaluated on 2026-10-19 and left out: its lists held about 28 indicators in total.
PRIVATE_FEEDS = [
    {
        "id": "cins",
        "name": "CINS Army",
        "urls": ["http://cinsscore.com/list/ci-badguys.txt"],
        "parser": "plain",
        "home": "https://cinsscore.com/",
        "terms": "\"parse and use in any way you see fit\"",
        "min": 1000,
    },
]
PRIVATE_SHARDS = 16

TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
ASN = {
    "url": "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz",
    "home": "https://iptoasn.com/",
    "license": "PDDL 1.0",
    "license_url": "https://opendatacommons.org/licenses/pddl/1.0/",
    "attribution": "IPtoASN",
    "min": 100000,
}
GPL2_URL = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt"


def fetch(url: str, attempts: int = 4) -> bytes:
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"{url}: {last}")


def parse_ip_lines(text: str) -> list[str]:
    """One IP per line; comments (#) and blanks ignored; invalid lines dropped."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            out.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return sorted(out, key=lambda s: (":" in s, ipaddress.ip_address(s)))


def parse_kev(raw: bytes) -> dict:
    doc = json.loads(raw)
    out = {}
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID", "").upper()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
        }
    return out


def parse_tlds(text: str) -> list[str]:
    return sorted({l.strip().lower() for l in text.splitlines() if l.strip() and not l.startswith("#")})


def parse_asn(raw: bytes) -> list[tuple[int, int, int, str, str]]:
    """ip2asn-v4-u32 rows: start end asn country description (tab separated, addresses as uint32).
    Unrouted ranges (AS 0) are dropped."""
    text = gzip.decompress(raw).decode("utf-8", "replace") if raw[:2] == b"\x1f\x8b" else raw.decode("utf-8", "replace")
    rows = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            start, end, asn = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            continue
        if asn == 0 or not (0 <= start <= end <= 0xFFFFFFFF):
            continue
        rows.append((start, end, asn, parts[3].strip(), parts[4].strip()))
    rows.sort()
    return rows


def write_asn_shards(rows, out: Path) -> list[int]:
    """One file per first octet. A range that crosses an octet boundary is split."""
    shards: dict[int, dict] = {}
    for start, end, asn, cc, name in rows:
        while start <= end:
            octet = start >> 24
            stop = min(end, (octet << 24) | 0xFFFFFF)
            sh = shards.setdefault(octet, {"s": [], "e": [], "a": [], "names": {}})
            sh["s"].append(start)
            sh["e"].append(stop)
            sh["a"].append(asn)
            sh["names"][str(asn)] = [name, cc]
            start = stop + 1
    d = out / "asn" / "v4"
    d.mkdir(parents=True, exist_ok=True)
    for octet, sh in shards.items():
        (d / f"{octet}.json").write_text(json.dumps(sh, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return sorted(shards)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ip_type(value: str) -> str:
    return "ipv6" if ":" in value else "ipv4"


def parse_tweetfeed(text: str) -> dict:
    """date,user,type,value,tags,tweet_url (no header). Detail kept: [date, user, tweet_url]."""
    import csv
    out: dict[str, dict] = {}
    kinds = {"domain": "domain", "url": "url", "md5": "md5", "sha256": "sha256", "sha1": "sha1"}
    for row in csv.reader(text.splitlines()):
        if len(row) < 6:
            continue
        date, user, kind, value, _tags, link = row[:6]
        value = value.strip()
        if kind == "ip":
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            t = ip_type(value)
        elif kind in kinds:
            t = kinds[kind]
            if t in ("domain", "md5", "sha1", "sha256"):
                value = value.lower()
        else:
            continue
        if not value:
            continue
        prev = out.setdefault(t, {}).get(value)
        if prev is None or date > prev[0]:  # keep the latest report
            out[t][value] = [date[:10], user, link]
    return out


def parse_c2intel(texts: list[str]) -> dict:
    """#ip,ioc and #domain,ioc CSV files. Detail kept: the ioc description."""
    out: dict[str, dict] = {}
    for text in texts:
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            value, _, desc = line.partition(",")
            value = value.strip().lower()
            try:
                value = str(ipaddress.ip_address(value))
                t = ip_type(value)
            except ValueError:
                t = "domain"
            out.setdefault(t, {})[value] = desc.strip()
    return out


def parse_domain_lines(text: str) -> dict:
    vals = {l.strip().lower() for l in text.splitlines() if l.strip() and not l.startswith("#") and "." in l}
    return {"domain": {v: None for v in sorted(vals)}}


HEX = set("0123456789abcdef")


def classify(value: str) -> tuple[str, str] | None:
    """Indicator type and normalised value, or None when the value is not a usable indicator."""
    v = value.strip().strip(",;")
    if not v:
        return None
    try:
        ip = ipaddress.ip_address(v)
        return ip_type(str(ip)), str(ip)
    except ValueError:
        pass
    low = v.lower()
    if low.startswith(("http://", "https://")):
        return "url", v
    if "@" in low and "." in low.split("@")[-1]:
        return "email", low
    if set(low) <= HEX and len(low) in (32, 40, 64):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(low)], low
    if "." in low and " " not in low and "/" not in low:
        return "domain", low.rstrip(".")
    return None


def parse_listing(texts: list[str]) -> dict:
    """Lines of `value` or `value # comment`; '#' lines and '---' separators are skipped."""
    out: dict[str, dict] = {}
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "---")):
                continue
            value, _, comment = line.partition("#")
            c = classify(value.split()[0] if value.split() else "")
            if c:
                out.setdefault(c[0], {})[c[1]] = comment.strip()[:120] or None
    return out


def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def write_private(feeds_data: dict, out: Path) -> None:
    """public/_private/<type>/<shard>.json = {value: [[feed id, detail], ...]}, shard = fnv1a(value) % 16.
    Small shards keep the Worker's per-request parsing well under its CPU limit."""
    merged: dict[str, dict] = {}
    for fid, data in feeds_data.items():
        for t, values in data.items():
            for v, d in values.items():
                merged.setdefault(t, {}).setdefault(v, []).append([fid, d])
    for t, values in merged.items():
        shards: dict[int, dict] = {}
        for v, hits in values.items():
            shards.setdefault(fnv1a(v) % PRIVATE_SHARDS, {})[v] = hits
        d = out / t
        d.mkdir(parents=True, exist_ok=True)
        for i in range(PRIVATE_SHARDS):
            (d / f"{i}.json").write_text(json.dumps(shards.get(i, {}), separators=(",", ":"), ensure_ascii=False), encoding="utf-8")


def build_private(out: Path, meta: dict, fetcher) -> None:
    feeds_data = {}
    meta["private"] = []
    for f in PRIVATE_FEEDS:
        try:
            data = parse_listing([r.decode("utf-8", "replace") for r in (fetcher(u) for u in f["urls"])])
            count = sum(len(v) for v in data.values())
            if count < f["min"]:
                raise RuntimeError(f"only {count} records, minimum is {f['min']}")
        except Exception as e:  # noqa: BLE001  the feed is left out until the next successful build
            meta["errors"].append({"feed": f["id"], "error": str(e)[:300], "at": now()})
            print(f"WARNING {f['id']}: {e}", file=sys.stderr)
            continue
        feeds_data[f["id"]] = data
        meta["private"].append({"id": f["id"], "name": f["name"], "home": f["home"], "terms": f["terms"],
                                "fetched": now(), "count": count, "types": sorted(data)})
        print(f"{f['id']} (private): {count} {dict((k, len(v)) for k, v in data.items())}", file=sys.stderr)
    write_private(feeds_data, out)


def by_type(f: dict, raws: list[bytes]) -> dict:
    texts = [r.decode("utf-8", "replace") for r in raws]
    p = f["parser"]
    if p == "ip_lines":
        out: dict[str, dict] = {}
        for ip in parse_ip_lines(texts[0]):
            out.setdefault(ip_type(ip), {})[ip] = None
        return out
    if p == "kev":
        return {"cve": parse_kev(raws[0])}
    if p == "tweetfeed":
        return parse_tweetfeed(texts[0])
    if p == "c2intel":
        return parse_c2intel(texts)
    if p == "domain_lines":
        return parse_domain_lines(texts[0])
    raise ValueError(p)


LIVE = "https://ioclookup.com/data/"


def reuse_live(f: dict, out: Path, live_meta: dict | None, fetcher) -> dict | None:
    """When a source fails, keep serving the copy that is live on the site, with its original
    fetch time so the page shows how old it is. A feed that was never published is skipped."""
    prev = next((x for x in (live_meta or {}).get("feeds", []) if x.get("id") == f["id"] and x.get("files")), None)
    if not prev:
        return None
    for t in prev["files"]:
        (out / f"{f['id']}.{t}.json").write_bytes(fetcher(f"{LIVE}{f['id']}.{t}.json"))
    return prev


def build(out: Path, fetcher=fetch, private_out: Path | None = None) -> dict:
    """Each feed is written as one file per indicator type, <id>.<type>.json = {"v": {value: detail}},
    so the browser only downloads the types that occur in the pasted text.
    A failing source does not stop the build: its live copy is reused (see reuse_live) and the
    failure is recorded in meta.json under "errors"."""
    out.mkdir(parents=True, exist_ok=True)
    meta = {"generated": now(), "feeds": [], "errors": []}
    live_meta = None
    try:
        live_meta = json.loads(fetcher(LIVE + "meta.json"))
    except Exception:  # noqa: BLE001  first deploy, or the site is down
        pass
    for f in FEEDS:
        try:
            data = by_type(f, [fetcher(u) for u in f["urls"]])
            count = sum(len(v) for v in data.values())
            if count < f["min"]:
                raise RuntimeError(f"only {count} records, minimum is {f['min']}")
        except Exception as e:  # noqa: BLE001
            meta["errors"].append({"feed": f["id"], "error": str(e)[:300], "at": now()})
            print(f"WARNING {f['id']}: {e}", file=sys.stderr)
            try:
                prev = reuse_live(f, out, live_meta, fetcher)
            except Exception as e2:  # noqa: BLE001
                prev = None
                meta["errors"][-1]["reuse"] = str(e2)[:200]
            if prev:
                meta["feeds"].append(prev)
            continue
        files = {}
        for t, values in sorted(data.items()):
            (out / f"{f['id']}.{t}.json").write_text(json.dumps({"v": values}, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            files[t] = len(values)
        entry = {k: f[k] for k in ("id", "name", "home", "license", "license_url", "attribution")}
        entry.update({"urls": f["urls"], "fetched": now(), "count": count, "files": files})
        meta["feeds"].append(entry)
        print(f"{f['id']}: {count} {files}", file=sys.stderr)
    if not meta["feeds"]:
        raise RuntimeError("no feed could be built or reused")
    tlds = parse_tlds(fetcher(TLD_URL).decode("ascii", "replace"))
    if len(tlds) < 1000:
        raise RuntimeError(f"tlds: only {len(tlds)}")
    (out / "tlds.txt").write_text("\n".join(tlds) + "\n", encoding="ascii")
    (out / "GPL-2.0.txt").write_bytes(fetcher(GPL2_URL))
    rows = parse_asn(fetcher(ASN["url"]))
    if len(rows) < ASN["min"]:
        raise RuntimeError(f"asn: only {len(rows)} ranges, minimum is {ASN['min']}")
    octets = write_asn_shards(rows, out)
    meta["asn"] = {k: ASN[k] for k in ("url", "home", "license", "license_url", "attribution")}
    # octets lists which shard files exist, so the browser never requests a missing one
    meta["asn"].update({"fetched": now(), "ranges": len(rows), "octets": octets})
    print(f"asn: {len(rows)} ranges in {len(octets)} files", file=sys.stderr)
    build_private(private_out or out / "_private", meta, fetcher)
    (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="public/data")
    ap.add_argument("--private-out", default="public/_private", help="served only to the Worker, never publicly")
    args = ap.parse_args()
    try:
        build(Path(args.out), private_out=Path(args.private_out))
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
