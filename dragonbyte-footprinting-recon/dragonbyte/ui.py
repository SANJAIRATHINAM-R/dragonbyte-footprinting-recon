"""Colourful terminal UI (ANSI, standard library only).

Colours switch off automatically when output is piped to a file, or when the
NO_COLOR environment variable is set.
"""
import itertools
import os
import shutil
import sys
import threading
import time

# ---------------------------------------------------------------- colour core
if os.name == "nt":
    os.system("")  # enables ANSI escape processing on Windows 10+ terminals

ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if os.environ.get("FORCE_COLOR"):
    ENABLED = True


def c(text, code):
    """Wrap text in an ANSI SGR code (e.g. '1;38;5;208')."""
    return f"\033[{code}m{text}\033[0m" if ENABLED else str(text)


def fg(n):
    return f"38;5;{n}"


RED, ORANGE, YELLOW, GREEN = fg(196), fg(208), fg(220), fg(82)
CYAN, BLUE, PURPLE, GREY, WHITE = fg(51), fg(75), fg(141), fg(245), fg(255)

SEV_STYLE = {
    "High": ("1;97;48;5;196", "HIGH  "),
    "Medium": ("1;30;48;5;208", "MEDIUM"),
    "Low": ("1;30;48;5;220", "LOW   "),
    "Info": ("1;30;48;5;75", "INFO  "),
}


def width():
    return max(60, min(shutil.get_terminal_size((90, 24)).columns, 100))


# --------------------------------------------------------------------- banner
# 5x5 pixel font; every pixel is drawn as two solid block characters, so the
# banner looks the same in every terminal (no thin box-drawing characters).
FONT = {
    "D": ["XXXX.", "X...X", "X...X", "X...X", "XXXX."],
    "R": ["XXXX.", "X...X", "XXXX.", "X..X.", "X...X"],
    "A": [".XXX.", "X...X", "XXXXX", "X...X", "X...X"],
    "G": [".XXXX", "X....", "X.XXX", "X...X", ".XXX."],
    "O": [".XXX.", "X...X", "X...X", "X...X", ".XXX."],
    "N": ["X...X", "XX..X", "X.X.X", "X..XX", "X...X"],
    "B": ["XXXX.", "X...X", "XXXX.", "X...X", "XXXX."],
    "Y": ["X...X", ".X.X.", "..X..", "..X..", "..X.."],
    "T": ["XXXXX", "..X..", "..X..", "..X..", "..X.."],
    "E": ["XXXXX", "X....", "XXXX.", "X....", "XXXXX"],
}
FIRE = [196, 208, 214, 220, 226]  # red -> orange -> yellow, one colour per row


def big_text(word):
    rows = []
    for r in range(5):
        row = "  ".join(FONT[ch][r].replace("X", "██").replace(".", "  ") for ch in word)
        rows.append(row)
    return rows


def banner(version):
    w = width()
    print()
    for word in ("DRAGON", "BYTE"):
        for i, line in enumerate(big_text(word)):
            print("  " + c(line, f"1;{fg(FIRE[i])}"))
    print()
    line = "━" * (w - 4)
    print("  " + c(line, fg(202)))
    tag = "🐉  FOOTPRINTING & RECON TOOLKIT"
    print("  " + c(tag, f"1;{WHITE}") + c(f"   v{version}", GREY) + c("   by ", GREY) + c("DRAGONBYTE", f"1;{ORANGE}"))
    print("  " + c("⚠  Authorized targets only - own it or have written permission", YELLOW))
    print("  " + c(line, fg(202)))
    print()


# ------------------------------------------------------------ small elements
def section(icon, title):
    print()
    print("  " + c(f" {icon} {title} ", f"1;38;5;16;48;5;208") + c(" " + "─" * (width() - len(title) - 10), fg(238)))


def kv(key, value, indent=4, keycol=16, color=WHITE):
    print(" " * indent + c(f"{key:<{keycol}}", f"1;{CYAN}") + c("│ ", GREY) + c(value, color))


def good(msg):
    print("    " + c("✔", f"1;{GREEN}") + " " + msg)


def bad(msg):
    print("    " + c("✘", f"1;{RED}") + " " + c(msg, RED))


def note(msg):
    print("    " + c("•", GREY) + " " + c(msg, GREY))


def badge(sev):
    style, label = SEV_STYLE.get(sev, SEV_STYLE["Info"])
    return c(f" {label} ", style)


class Spinner:
    """Animated spinner shown while a module runs (no-op when not a TTY)."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label):
        self.label, self._stop = label, threading.Event()
        self._t = threading.Thread(target=self._spin, daemon=True)
        self.start_time = time.time()

    def _spin(self):
        for i, f in enumerate(itertools.cycle(self.FRAMES)):
            if self._stop.is_set():
                break
            col = FIRE[i // 2 % len(FIRE)]
            sys.stdout.write(f"\r    {c(f, f'1;{fg(col)}')} {c(self.label, WHITE)} {c('...', GREY)}  ")
            sys.stdout.flush()
            time.sleep(0.08)

    def __enter__(self):
        if ENABLED:
            self._t.start()
        else:
            print(f"    {self.label} ...")
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if ENABLED:
            self._t.join()
            sys.stdout.write("\r" + " " * (width()) + "\r")
            sys.stdout.flush()


def took(start):
    return c(f"({time.time() - start:.1f}s)", GREY)


# ---------------------------------------------------------------- result views
def show_whois(d):
    if not d.get("ok"):
        return bad(f"WHOIS unavailable: {d.get('error', 'no data')}")
    good("WHOIS record retrieved")
    for k, v in d.get("parsed", {}).items():
        kv(k.replace("_", " ").title(), ", ".join(v) if isinstance(v, list) else v)


def show_dns(d):
    if not d.get("ok"):
        return bad("No DNS records returned (blocked, NXDOMAIN or resolver unreachable)")
    good("DNS records retrieved")
    for rtype, vals in d["records"].items():
        if vals:
            for i, v in enumerate(vals[:6]):
                kv(rtype if i == 0 else "", v[:70])
    es = d.get("email_security", {})
    for name in ("spf", "dmarc"):
        state = es.get(name)
        label = name.upper()
        if state is True:
            print("    " + c("✔", f"1;{GREEN}") + f" {label} present")
        elif state is False:
            print("    " + c("✘", f"1;{RED}") + " " + c(f"{label} missing", RED))


def show_web(d):
    if not d.get("ok"):
        return bad("Web server unreachable: " + "; ".join(d.get("errors", ["no data"]))[:90])
    good(f"HTTP {d.get('status')} from {d.get('final_url')}")
    kv("Title", d.get("title") or "-")
    kv("Server", d.get("server") or "hidden", color=GREEN if not d.get("server") else YELLOW)
    kv("Technologies", ", ".join(d.get("technologies", [])) or "none detected")
    waf = ", ".join(d.get("waf", []))
    kv("WAF / CDN", waf or "none detected", color=GREEN if waf else YELLOW)
    miss = d.get("missing_security_headers", [])
    kv("Header audit", f"{6 - min(6, len(miss))}/6 security headers present",
       color=GREEN if not miss else (YELLOW if len(miss) < 4 else RED))
    for m in miss:
        note(m)


def show_subs(d):
    found = d.get("found", [])
    if not found:
        return note(f"No subdomains found ({d.get('tested', 0)} tested)")
    good(f"{len(found)} subdomain(s) found ({d.get('tested')} tested)")
    for s in found:
        kv(s["host"], ", ".join(s["ips"]), keycol=34, color=GREEN)


def show_findings(items):
    section("🛡", "FINDINGS")
    if not items:
        return note("Nothing to report")
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    for sev, txt in sorted(items, key=lambda x: order.get(x[0], 9)):
        print("    " + badge(sev) + " " + txt)


def summary_box(target, items, jpath, hpath, secs):
    counts = {s: sum(1 for x in items if x[0] == s) for s in ("High", "Medium", "Low", "Info")}
    w = width() - 4
    top, bot = "╭" + "─" * (w - 2) + "╮", "╰" + "─" * (w - 2) + "╯"

    def row(text, plain_len):
        pad = " " * max(0, w - 4 - plain_len)
        print("  " + c("│", fg(208)) + " " + text + pad + " " + c("│", fg(208)))

    print()
    print("  " + c(top, fg(208)))
    t = f"SCAN COMPLETE  ·  {target}  ·  {secs:.1f}s"
    row(c(t, f"1;{WHITE}"), len(t))
    line = f"High {counts['High']}   Medium {counts['Medium']}   Low {counts['Low']}   Info {counts['Info']}"
    row(c("High ", f"1;{RED}") + c(counts["High"], WHITE) + "   " + c("Medium ", f"1;{ORANGE}") + c(counts["Medium"], WHITE)
        + "   " + c("Low ", f"1;{YELLOW}") + c(counts["Low"], WHITE) + "   " + c("Info ", f"1;{BLUE}") + c(counts["Info"], WHITE),
        len(line))
    for label, path in (("HTML report", hpath), ("JSON report", jpath)):
        txt = f"{label}: {path}"
        row(c(f"{label}: ", f"1;{CYAN}") + c(path, WHITE), len(txt))
    print("  " + c(bot, fg(208)))
    print("  " + c("🐉 DRAGONBYTE  ·  recon first, always authorized.", GREY))
    print()
