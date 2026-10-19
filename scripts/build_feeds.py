#!/usr/bin/env python3
"""Builds the feed snapshots that ioclookup.com publishes.

Only sources whose license clearly allows public redistribution are included here.
Sources without that permission are queried from the user's browser with the user's own key
instead (see public/js/sources.js), never republished.

Output (default public/data/):
  tor-exit.json, et-compromised.json, kev.json, tlds.txt, meta.json
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
        "url": "https://check.torproject.org/torbulkexitlist",
        "home": "https://metrics.torproject.org/collector.html",
        "license": "CC0 1.0",
        "license_url": "https://metrics.torproject.org/collector.html",
        "attribution": "The Tor Project",
        "types": ["ipv4", "ipv6"],
        "min": 300,
    },
    {
        "id": "et-compromised",
        "name": "Emerging Threats compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "home": "https://rules.emergingthreats.net/",
        "license": "GPL-2.0",
        "license_url": "https://community.emergingthreats.net/t/licensing-is-the-compromised-ips-list-also-open/676",
        "attribution": "Proofpoint Emerging Threats",
        "types": ["ipv4"],
        "min": 50,
    },
    {
        "id": "kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "license": "CC0 1.0",
        "license_url": "https://github.com/cisagov/kev-data",
        "attribution": "CISA",
        "types": ["cve"],
        "min": 1000,
    },
]
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


def build(out: Path, fetcher=fetch) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    meta = {"generated": now(), "feeds": []}
    for f in FEEDS:
        raw = fetcher(f["url"])
        if f["id"] == "kev":
            data = parse_kev(raw)
            count = len(data)
            body = {"cves": data}
        else:
            ips = parse_ip_lines(raw.decode("utf-8", "replace"))
            count = len(ips)
            body = {"ips": ips}
        if count < f["min"]:
            raise RuntimeError(f"{f['id']}: only {count} records, minimum is {f['min']}")
        (out / f"{f['id']}.json").write_text(json.dumps(body, separators=(",", ":")), encoding="utf-8")
        entry = {k: f[k] for k in ("id", "name", "url", "home", "license", "license_url", "attribution", "types")}
        entry.update({"fetched": now(), "count": count})
        meta["feeds"].append(entry)
        print(f"{f['id']}: {count}", file=sys.stderr)
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
    (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="public/data")
    args = ap.parse_args()
    try:
        build(Path(args.out))
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
