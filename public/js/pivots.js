// Links that open an indicator on another service. Nothing is sent until the user clicks.

const e = encodeURIComponent;

const BY_TYPE = {
  ipv4: [
    ["VirusTotal", (v) => `https://www.virustotal.com/gui/ip-address/${e(v)}`],
    ["AbuseIPDB", (v) => `https://www.abuseipdb.com/check/${e(v)}`],
    ["Shodan", (v) => `https://www.shodan.io/host/${e(v)}`],
    ["GreyNoise", (v) => `https://viz.greynoise.io/ip/${e(v)}`],
    ["urlscan", (v) => `https://urlscan.io/ip/${e(v)}`],
    ["OTX", (v) => `https://otx.alienvault.com/indicator/ip/${e(v)}`],
    ["ViriBack", (v) => `https://tracker.viriback.com/index.php?q=${e(v)}`],
  ],
  ipv6: [
    ["VirusTotal", (v) => `https://www.virustotal.com/gui/ip-address/${e(v)}`],
    ["AbuseIPDB", (v) => `https://www.abuseipdb.com/check/${e(v)}`],
    ["OTX", (v) => `https://otx.alienvault.com/indicator/ip/${e(v)}`],
  ],
  domain: [
    ["VirusTotal", (v) => `https://www.virustotal.com/gui/domain/${e(v)}`],
    ["urlscan", (v) => `https://urlscan.io/domain/${e(v)}`],
    ["OTX", (v) => `https://otx.alienvault.com/indicator/domain/${e(v)}`],
    ["ViriBack", (v) => `https://tracker.viriback.com/index.php?q=${e(v)}`],
  ],
  url: [
    ["VirusTotal", (v) => `https://www.virustotal.com/gui/search/${e(e(v))}`],
    ["OTX", (v) => `https://otx.alienvault.com/indicator/url/${e(v)}`],
  ],
  md5: [["VirusTotal", (v) => `https://www.virustotal.com/gui/file/${v}`], ["OTX", (v) => `https://otx.alienvault.com/indicator/file/${v}`]],
  sha1: [["VirusTotal", (v) => `https://www.virustotal.com/gui/file/${v}`], ["OTX", (v) => `https://otx.alienvault.com/indicator/file/${v}`]],
  sha256: [
    ["VirusTotal", (v) => `https://www.virustotal.com/gui/file/${v}`],
    ["MalwareBazaar", (v) => `https://bazaar.abuse.ch/sample/${v}/`],
    ["OTX", (v) => `https://otx.alienvault.com/indicator/file/${v}`],
  ],
  cve: [
    ["NVD", (v) => `https://nvd.nist.gov/vuln/detail/${v}`],
    ["CVE.org", (v) => `https://www.cve.org/CVERecord?id=${v}`],
  ],
  email: [],
};

export function pivotsFor(ioc) {
  return (BY_TYPE[ioc.type] || []).map(([name, url]) => ({ name, url: url(ioc.value) }));
}
