# ioclookup.com

Paste text, get the indicators of compromise in it, and check them. Extraction and matching run in the browser.

## How data is handled

| Path | What happens | Who sees the indicator |
|---|---|---|
| Extraction (`public/js/extract.js`) | IPv4/IPv6, domains (checked against the IANA TLD list), URLs, emails, MD5/SHA1/SHA256, CVE IDs. Defanged input (`hxxp`, `[.]`, `[at]`) is accepted. | Nobody. It runs in the browser. |
| Published feeds (`public/js/match.js`) | Daily snapshots downloaded by `scripts/build_feeds.py` and matched in the browser. | Nobody. The browser downloads the whole snapshot. |
| AS context (`public/js/asn.js`) | Each public IPv4 address is matched to its AS number, AS name and country from the IPtoASN snapshot. | Nobody. Only the snapshot file for the address's first octet is downloaded. |
| Search links (`public/js/pivots.js`) | Links that open the indicator on VirusTotal, AbuseIPDB, Shodan, GreyNoise, urlscan, OTX, ViriBack, NVD. | The service, only if you click. |
| Hunting queries (`public/js/queries.js`) | Queries for Microsoft Sentinel (KQL), Splunk (SPL with CIM data models), QRadar (AQL), Elastic (KQL with ECS) and Sigma, built from the indicators. Private and reserved IPv4 addresses are left out. | Nobody. Built in the browser. |
| USOM (`public/js/sources.js`) | IPv4 addresses, domains and URLs are checked against the list of Türkiye's national CERT (Siber Güvenlik Başkanlığı) through its public API, when you press Look up. Nothing from the list is copied to this site. | Siber Güvenlik Başkanlığı. |
| Server matching (`src/worker.js`, `/api/match`) | CINS Army allows use ("parse and use in any way you see fit") but says nothing about republishing, so it is not published. The daily build writes them under `/_private/`, which the Worker refuses to serve; when you press Look up, the indicators are sent to `/api/match` and only the matching entries come back. Nothing is stored or logged. | This site's Worker. |
| Shodan InternetDB (`public/js/sources.js`) | Open ports, known CVEs, tags and hostnames for public IPv4 addresses, without a key, when you press Look up. Free for non-commercial use; it is removed if the site ever charges. | Shodan. |
| Lookups with your keys (`public/js/sources.js`) | Only when you press the button, only for sources you added a key for. Private and reserved IPs are never sent. | The lookup service you chose. |
| Pass-through (`src/worker.js`) | For services that do not accept browser requests (no CORS): ThreatFox, URLhaus, AbuseIPDB, VirusTotal. Fixed endpoints only, same-origin requests only, nothing stored or logged. | The lookup service, through this site's Worker. |

Keys are kept in the browser: in `sessionStorage` by default, in `localStorage` only if you tick "remember".

## Published feeds

Only feeds whose license allows public redistribution are published. Each feed is split into one file per indicator type (`data/<feed>.<type>.json`), and the browser downloads only the types that appear in the pasted text. `data/meta.json` records each feed's source, license and fetch time.

| Feed | License |
|---|---|
| Tor exit nodes (The Tor Project) | CC0 1.0 |
| Emerging Threats compromised IPs (Proofpoint) | GPL-2.0, license text shipped as `data/GPL-2.0.txt` |
| CISA Known Exploited Vulnerabilities | CC0 1.0 |
| IPtoASN IPv4 to AS mapping | PDDL 1.0 |
| TweetFeed (indicators shared by researchers on X, last 365 days) | CC0 1.0 |
| C2IntelFeeds (C2 IPs and domains, last 30 days) | CC BY-NC-SA 4.0 (non-commercial; removed if the site ever charges) |
| CERT Polska warning list (phishing domains) | Free for any purpose under the CERT Polska data usage policy |

abuse.ch (URLhaus, ThreatFox, MalwareBazaar) and Spamhaus DROP data are not republished: their terms do not grant redistribution. They are available as lookups with your own key. Permission to publish has been requested.

"Not listed" never means "clean". It means the sources that were checked have no record.

## Development

```sh
npm ci
npm test                          # extractor, Worker and feed builder tests
python3 tests/make_sample_data.py # fake snapshots, no network
npx wrangler dev                  # local server
BASE=http://127.0.0.1:8787 node tests/e2e.mjs   # needs playwright
python3 scripts/build_feeds.py    # real snapshots
```

Deploy needs the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets.

## License

Copyright (c) 2026 Bartu Kılıç. All rights reserved.

The source is public so that what the page and the pass-through do can be checked. No license to copy, modify or redistribute the code is granted. Feed snapshots under `data/` keep the license of their source, listed above and in `data/meta.json`.
