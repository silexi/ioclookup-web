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
            self.assertEqual([f["id"] for f in meta["feeds"]], ["tor-exit", "et-compromised", "kev"])
            tor = json.loads(Path(d, "tor-exit.json").read_text())
            self.assertEqual(len(tor["ips"]), 401)
            kev = json.loads(Path(d, "kev.json").read_text())["cves"]
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

    def test_short_feed_fails(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                B.build(Path(d), fake_fetcher({"tor": 10, "et": 60, "kev": 1200}))


if __name__ == "__main__":
    unittest.main()
