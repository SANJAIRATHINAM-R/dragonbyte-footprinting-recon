# 🐉 DRAGONBYTE – Footprinting & Reconnaissance Toolkit

A single-command footprinting tool for the **reconnaissance phase of ethical hacking**.
Pure Python 3, **no external packages** – works on Kali Linux, Windows, macOS.

> ⚠️ **Authorized use only.** Run it only against domains you own or have written permission to test.

## What it does

| Module | What it collects |
|--------|------------------|
| **WHOIS** | Registrar, creation/expiry dates, name servers, status |
| **DNS** | A, AAAA, NS, MX, TXT, SOA records + SPF / DMARC check |
| **Web fingerprint** | Server banner, CMS/framework detection, page title, `robots.txt`, `sitemap.xml`, `security.txt` |
| **WAF / CDN detection** | Cloudflare, Akamai, Sucuri, Imperva, CloudFront, Fastly, F5, ModSecurity… |
| **Security-header audit** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer/Permissions-Policy |
| **Subdomain discovery** | Threaded DNS brute-force with a built-in or custom wordlist |
| **Report** | `report.html` (dark themed) + `report.json` with a severity-ranked findings list |

## Quick start

```bash
git clone https://github.com/SANJAIRATHINAM-R/dragonbyte-footprinting-recon.git
cd dragonbyte-footprinting-recon

python3 dragonbyte_recon.py yourdomain.com --yes
```

Open `reports/<domain>_<timestamp>/report.html` in a browser.

### Options

```text
python3 dragonbyte_recon.py DOMAIN [--yes] [--skip whois dns web subdomains]
                                   [--wordlist FILE] [--timeout SECONDS] [-o OUTDIR]
```

Examples:

```bash
python3 dragonbyte_recon.py yourdomain.com --yes --skip subdomains
python3 dragonbyte_recon.py yourdomain.com --yes --wordlist wordlists/subdomains.txt
python3 dragonbyte_recon.py yourdomain.com          # asks for authorization confirmation
```

## Project structure

```
dragonbyte-footprinting-recon/
├── dragonbyte_recon.py        # entry point
├── dragonbyte/
│   ├── cli.py                 # argument parsing, orchestration
│   ├── whois_mod.py           # WHOIS over TCP/43
│   ├── dns_mod.py             # DNS client, records, subdomains
│   ├── web_mod.py             # HTTP fingerprint, WAF, header audit
│   └── report.py              # JSON + HTML reports, findings
├── tests/test_dragonbyte.py   # unit tests (python3 -m unittest discover -s tests)
├── wordlists/subdomains.txt   # extended subdomain wordlist
├── REPORT_TEMPLATE.md         # write-up template for your assignment
└── screenshots/               # put your own screenshots here
```

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

## Equivalent Kali commands (for your screenshots)

```bash
whois example.com
dnsrecon -d example.com
whatweb example.com
wafw00f https://example.com
theHarvester -d example.com -b duckduckgo
```

## Notes & limitations

- Needs normal internet access (port 43 for WHOIS, port 53 UDP for DNS, 80/443 for web).
  If a module is blocked it is reported as "no data" – the tool never guesses.
- WAF and technology detection are signature based (headers/body), so treat them as hints, not proof.
- Passive and low-impact: normal DNS queries and a handful of HTTP GET requests. No exploitation, no port scanning.

## License
MIT – © DRAGONBYTE
