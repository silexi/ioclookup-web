"""Writes small fake snapshots to public/data for local development (no network).
python3 tests/make_sample_data.py"""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_build_feeds import fake_fetcher  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_feeds as B  # noqa: E402

base = fake_fetcher({"tor": 400, "et": 60, "kev": 1200})


def fetcher(url):
    if "tlds" in url:
        return ("\n".join(["COM", "NET", "ORG", "RU", "IO", "UK", "CO", "TR"] + [f"T{i}" for i in range(1500)])).encode()
    if "kev" in url:
        doc = json.loads(base(url))
        doc["vulnerabilities"].append({"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS",
                                       "vulnerabilityName": "PAN-OS Command Injection", "dateAdded": "2024-04-12",
                                       "knownRansomwareCampaignUse": "Unknown"})
        return json.dumps(doc).encode()
    return base(url)


B.build(Path("public/data"), fetcher)
print("ok")
