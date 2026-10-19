# ioclookup.com

Paste text, get the indicators of compromise in it, and check them. Extraction and matching run in the browser.

## How data is handled

| Path | What happens | Who sees the indicator |
|---|---|---|
| Extraction (`public/js/extract.js`) | IPv4/IPv6, domains (checked against the IANA TLD list), URLs, emails, MD5/SHA1/SHA256, CVE IDs. Defanged input (`hxxp`, `[.]`, `[at]`) is accepted. | Nobody. It runs in the browser. |
| Published feeds (`public/js/match.js`) | Daily snapshots downloaded by `scripts/build_feeds.py` and matched in the browser. | Nobody. The browser downloads the whole snapshot. |
| Lookups with your keys (`public/js/sources.js`) | Only when you press the button, only for sources you added a key for. Private and reserved IPs are never sent. | The lookup service you chose. |
| Pass-through (`src/worker.js`) | For services that do not accept browser requests (no CORS): ThreatFox, URLhaus, AbuseIPDB, VirusTotal. Fixed endpoints only, same-origin requests only, nothing stored or logged. | The lookup service, through this site's Worker. |

Keys are kept in the browser: in `sessionStorage` by default, in `localStorage` only if you tick "remember".

## Published feeds

Only feeds whose license allows public redistribution are published. Each snapshot records its source, license and fetch time in `data/meta.json`.

| Feed | License |
|---|---|
| Tor exit nodes (The Tor Project) | CC0 1.0 |
| Emerging Threats compromised IPs (Proofpoint) | GPL-2.0, license text shipped as `data/GPL-2.0.txt` |
| CISA Known Exploited Vulnerabilities | CC0 1.0 |

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
