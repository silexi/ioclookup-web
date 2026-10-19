"""python3 -m unittest discover -s tests"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_feeds as B


def fake_fetcher(sizes):
    def f(url):
        if "torbulkexitlist" in url:
            return ("\n".join(f"185.220.{i // 250}.{i % 250 + 1}" for i in range(sizes["tor"])) + "\n2001:db8::1\nnot-an-ip\n").encode()
        if "compromised-ips" in url:
            return ("# header\n" + "\n".join(f"45.33.{i // 250}.{i % 250 + 1}" for i in range(sizes["et"]))).encode()
        if "TweetFeed" in url:
            rows = [f"2026-10-0{1 + i % 9} 10:00:00,user{i % 5},domain,bad{i}.example.com,#phishing,https://x.com/u/status/{i}" for i in range(sizes.get("tweet", 10050))]
            rows += ["2026-10-02 10:00:00,u,ip,45.9.1.1,#c2,https://x.com/u/status/1",
                     "2026-10-03 10:00:00,u,ip,45.9.1.1,#c2,https://x.com/u/status/2",
                     "2026-10-02 10:00:00,u,sha256,AB" + "c" * 62 + ",#malware,https://x.com/u/status/3",
                     "2026-10-02 10:00:00,u,url,https://bad.example.com/x,#phishing,https://x.com/u/status/4",
                     "2026-10-02 10:00:00,u,md5,0123456789abcdef0123456789abcdef,#malware,https://x.com/u/status/5",
                     "broken,row"]
            return "\n".join(rows).encode()
        if "IPC2s" in url:
            return ("#ip,ioc\n" + "\n".join(f"5.6.{i // 250}.{i % 250 + 1},Possible Cobaltstrike C2 IP" for i in range(60))).encode()
        if "domainC2s" in url:
            return b"#domain,ioc\nc2.example.net,Possible Cobalt Strike C2 Domain\n"
        if "hole.cert.pl" in url:
            return ("\n".join(f"phish{i}.example.pl" for i in range(sizes.get("certpl", 1200)))).encode()
        if "cinsscore" in url:
            return ("---\n" + "\n".join(f"77.88.{i // 250}.{i % 250 + 1}" for i in range(1100)) + "\n---\n").encode()
        if "kev" in url:
            return json.dumps({"vulnerabilities": [{"cveID": f"cve-2024-{i:05}", "vendorProject": "V", "product": "P",
                                                    "vulnerabilityName": "N", "dateAdded": "2024-01-01",
                                                    "knownRansomwareCampaignUse": "Known" if i == 0 else "Unknown"}
                                                   for i in range(sizes["kev"])]}).encode()
        if "tlds" in url:
            return ("# Version\n" + "\n".join(f"T{i}" for i in range(1500)) + "\nCOM\n").encode()
        if "gpl" in url:
            return b"GNU GENERAL PUBLIC LICENSE"
        if "ip2asn" in url:
            import gzip
            n = sizes.get("asn", 200001)
            rows = [f"{i * 256}\t{i * 256 + 255}\t{64500 + i % 3}\tTR\tEXAMPLE-AS-{i % 3}" for i in range(1, n)]
            rows += ["16777216\t33554431\t0\tNone\tNot routed", "garbage"]
            # one range that crosses from 1.x.x.x into 2.x.x.x
            rows.append(f"{(1 << 24) | 0xFFFF00}\t{(2 << 24) | 0xFF}\t65000\tDE\tCROSSING")
            return gzip.compress("\n".join(rows).encode())
        raise AssertionError(url)
    return f


class T(unittest.TestCase):
    def test_parse_ip_lines(self):
        self.assertEqual(B.parse_ip_lines("# c\n1.2.3.4\n\nbad\n1.2.3.4 # dup\n::1\n10.0.0.1\n"), ["1.2.3.4", "10.0.0.1", "::1"])

    def test_build(self):
        with tempfile.TemporaryDirectory() as d:
            meta = B.build(Path(d), fake_fetcher({"tor": 400, "et": 60, "kev": 1200}))
            self.assertEqual([f["id"] for f in meta["feeds"]], ["tor-exit", "et-compromised", "kev", "tweetfeed", "c2intel", "cert-pl"])
            tor4 = json.loads(Path(d, "tor-exit.ipv4.json").read_text())["v"]
            tor6 = json.loads(Path(d, "tor-exit.ipv6.json").read_text())["v"]
            self.assertEqual((len(tor4), list(tor6)), (400, ["2001:db8::1"]))
            tw = {t: json.loads(Path(d, f"tweetfeed.{t}.json").read_text())["v"] for t in ("ipv4", "sha256", "url", "domain")}
            self.assertEqual(tw["ipv4"]["45.9.1.1"], ["2026-10-03", "u", "https://x.com/u/status/2"])  # latest report kept
            self.assertIn("ab" + "c" * 62, tw["sha256"])  # hashes lower-cased
            self.assertIn("https://bad.example.com/x", tw["url"])
            c2 = json.loads(Path(d, "c2intel.domain.json").read_text())["v"]
            self.assertEqual(c2["c2.example.net"], "Possible Cobalt Strike C2 Domain")
            self.assertEqual(meta["feeds"][5]["files"], {"domain": 1200})
            kev = json.loads(Path(d, "kev.cve.json").read_text())["v"]
            self.assertTrue(kev["CVE-2024-00000"]["ransomware"])
            self.assertIn("com", Path(d, "tlds.txt").read_text().split())
            for f in meta["feeds"]:
                self.assertTrue(f["license"] and f["attribution"] and f["count"] > 0)

    def test_asn_shards(self):
        with tempfile.TemporaryDirectory() as d:
            meta = B.build(Path(d), fake_fetcher({"tor": 400, "et": 60, "kev": 1200}))
            self.assertEqual(meta["asn"]["license"], "PDDL 1.0")
            one = json.loads(Path(d, "asn", "v4", "1.json").read_text())
            two = json.loads(Path(d, "asn", "v4", "2.json").read_text())
            self.assertEqual(one["e"][-1], (1 << 24) | 0xFFFFFF)  # crossing range split at the octet boundary
            self.assertEqual(two["s"][0], 2 << 24)
            self.assertEqual(two["names"]["65000"], ["CROSSING", "DE"])
            self.assertNotIn("0", one["names"])

    def test_private_feeds_are_sharded_outside_data(self):
        with tempfile.TemporaryDirectory() as d:
            meta = B.build(Path(d, "data"), fake_fetcher({"tor": 400, "et": 60, "kev": 1200}), private_out=Path(d, "_private"))
            self.assertEqual([p["id"] for p in meta["private"]], ["cins"])
            self.assertFalse(any(Path(d, "data").glob("cins*")))
            v = "77.88.0.5"
            shard = json.loads(Path(d, "_private", "ipv4", f"{B.fnv1a(v) % 16}.json").read_text())
            self.assertEqual(shard[v], [["cins", None]])
            self.assertEqual(B.parse_listing(["# c\n---\n45.9.1.1 # Lazarus\nevil.example\nhttp://e.example/a\n" + "a" * 64]),
                             {"ipv4": {"45.9.1.1": "Lazarus"}, "domain": {"evil.example": None},
                              "url": {"http://e.example/a": None}, "sha256": {"a" * 64: None}})
            self.assertEqual(B.fnv1a("a"), 0xE40C292C)  # FNV-1a 32-bit reference value

    def test_short_feed_is_reported_and_live_copy_reused(self):
        live = {"feeds": [{"id": "tor-exit", "name": "Tor exit nodes", "fetched": "2026-10-18T00:00:00Z", "count": 1, "files": {"ipv4": 1}}]}
        base = fake_fetcher({"tor": 10, "et": 60, "kev": 1200})

        def f(url):
            if url == B.LIVE + "meta.json":
                return json.dumps(live).encode()
            if url == B.LIVE + "tor-exit.ipv4.json":
                return b'{"v":{"185.220.0.1":null}}'
            return base(url)
        with tempfile.TemporaryDirectory() as d:
            meta = B.build(Path(d), f)
            self.assertEqual(meta["errors"][0]["feed"], "tor-exit")
            tor = next(x for x in meta["feeds"] if x["id"] == "tor-exit")
            self.assertEqual(tor["fetched"], "2026-10-18T00:00:00Z")
            self.assertIn("185.220.0.1", Path(d, "tor-exit.ipv4.json").read_text())

    def test_failed_feed_without_live_copy_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            meta = B.build(Path(d), fake_fetcher({"tor": 10, "et": 60, "kev": 1200}))  # live meta unavailable
            self.assertNotIn("tor-exit", [x["id"] for x in meta["feeds"]])
            self.assertEqual(meta["errors"][0]["feed"], "tor-exit")


if __name__ == "__main__":
    unittest.main()
