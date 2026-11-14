"""Command-line interface."""
import argparse
import os
import re
import sys
from datetime import datetime

from . import __version__, dns_mod, report, web_mod, whois_mod

BANNER = r"""
 ____  ____      _    ____  ___  _   _ ______   _______ _____
|  _ \|  _ \    / \  / ___|/ _ \| \ | | __ ) \ / /_   _| ____|
| | | | |_) |  / _ \| |  _| | | |  \| |  _ \\ V /  | | |  _|
| |_| |  _ <  / ___ \ |_| | |_| | |\  | |_) || |   | | | |___
|____/|_| \_\/_/   \_\____|\___/|_| \_|____/ |_|   |_| |_____|
      Footprinting & Recon Toolkit v{v}  |  by DRAGONBYTE
"""

DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def build_parser():
    p = argparse.ArgumentParser(
        prog="dragonbyte",
        description="DRAGONBYTE footprinting & reconnaissance toolkit (authorized use only).",
    )
    p.add_argument("domain", help="target domain, e.g. example.com")
    p.add_argument("--yes", action="store_true", help="confirm you are authorized to test this target")
    p.add_argument("--skip", nargs="*", default=[], choices=["whois", "dns", "web", "subdomains"],
                   help="modules to skip")
    p.add_argument("--wordlist", help="file with one subdomain prefix per line")
    p.add_argument("--timeout", type=int, default=10, help="network timeout in seconds (default 10)")
    p.add_argument("-o", "--output", default="reports", help="output directory (default: reports)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(BANNER.format(v=__version__))
    domain = args.domain.lower().strip()
    if not DOMAIN_RE.match(domain):
        print(f"[!] Invalid domain: {domain}")
        return 2
    if not args.yes:
        ans = input(f"[?] Do you own or have written permission to test {domain}? (yes/no): ")
        if ans.strip().lower() != "yes":
            print("[!] Aborted. Authorization is required.")
            return 1

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    data = {"target": domain, "version": __version__, "generated": report.utcnow()}
    steps = [
        ("whois", "WHOIS lookup", lambda: whois_mod.run(domain, args.timeout)),
        ("dns", "DNS enumeration", lambda: dns_mod.enumerate_records(domain)),
        ("web", "Web fingerprint + WAF detection", lambda: web_mod.run(domain, args.timeout)),
        ("subdomains", "Subdomain discovery", lambda: dns_mod.find_subdomains(domain, wordlist)),
    ]
    for key, label, fn in steps:
        if key in args.skip:
            print(f"[-] {label}: skipped")
            continue
        print(f"[*] {label} ...")
        try:
            data[key] = fn()
        except Exception as exc:  # noqa: BLE001 - one failing module must not kill the scan
            data[key] = {"ok": False, "error": str(exc)}
        print(f"    {'done' if data[key].get('ok') else 'no data'}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(args.output, f"{domain}_{stamp}")
    jpath, hpath = report.save(data, outdir)

    print("\n=== Findings ===")
    for sev, txt in data["findings"] or [("Info", "none")]:
        print(f"  [{sev}] {txt}")
    print(f"\n[+] JSON report: {jpath}\n[+] HTML report: {hpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
