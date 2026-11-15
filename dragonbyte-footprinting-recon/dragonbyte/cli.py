"""Command-line interface."""
import argparse
import os
import re
import sys
import time
from datetime import datetime

from . import __version__, dns_mod, report, ui, web_mod, whois_mod

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
    p.add_argument("--no-color", action="store_true", help="disable colours")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color:
        ui.ENABLED = False
    ui.banner(__version__)

    domain = args.domain.lower().strip()
    if not DOMAIN_RE.match(domain):
        ui.bad(f"Invalid domain: {domain}")
        return 2
    if not args.yes:
        prompt = ui.c("  [?] ", f"1;{ui.YELLOW}") + f"Do you own or have written permission to test {ui.c(domain, '1;97')}? (yes/no): "
        if input(prompt).strip().lower() != "yes":
            ui.bad("Aborted. Authorization is required.")
            return 1

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    print("  " + ui.c("TARGET ", f"1;{ui.CYAN}") + ui.c(domain, "1;97") + ui.c("   " + datetime.now().strftime("%d %b %Y %H:%M"), ui.GREY))

    data = {"target": domain, "version": __version__, "generated": report.utcnow()}
    steps = [
        ("whois", "🔎", "WHOIS LOOKUP", lambda: whois_mod.run(domain, args.timeout), ui.show_whois),
        ("dns", "🌐", "DNS ENUMERATION", lambda: dns_mod.enumerate_records(domain), ui.show_dns),
        ("web", "🕸 ", "WEB FINGERPRINT · WAF · HEADERS", lambda: web_mod.run(domain, args.timeout), ui.show_web),
        ("subdomains", "🧭", "SUBDOMAIN DISCOVERY", lambda: dns_mod.find_subdomains(domain, wordlist), ui.show_subs),
    ]
    t0 = time.time()
    for key, icon, title, fn, view in steps:
        ui.section(icon, title)
        if key in args.skip:
            ui.note("skipped")
            continue
        start = time.time()
        with ui.Spinner(title.title()):
            try:
                data[key] = fn()
            except Exception as exc:  # noqa: BLE001 - one failing module must not kill the scan
                data[key] = {"ok": False, "error": str(exc)}
        view(data[key])
        print("    " + ui.took(start))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jpath, hpath = report.save(data, os.path.join(args.output, f"{domain}_{stamp}"))
    ui.show_findings(data["findings"])
    ui.summary_box(domain, data["findings"], jpath, hpath, time.time() - t0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
