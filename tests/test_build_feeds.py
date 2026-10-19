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

    def test_short_feed_fails(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                B.build(Path(d), fake_fetcher({"tor": 10, "et": 60, "kev": 1200}))


if __name__ == "__main__":
    unittest.main()
