"""Minimal DNS client (UDP) + record enumeration + subdomain discovery."""
import os
import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in QTYPES.items()}


def get_resolvers():
    servers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers + ["8.8.8.8", "1.1.1.1"]


def build_query(name, qtype):
    header = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")
    ) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def read_name(buf, off):
    labels, jumped, end = [], False, off
    for _ in range(128):  # loop guard
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        labels.append(buf[off + 1: off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    if not jumped:
        end = off
    return ".".join(labels), end


def parse_response(buf):
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0xF
    off = 12
    for _ in range(qd):
        _, off = read_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = read_name(buf, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off: off + 10])
        off += 10
        rd = buf[off: off + rdlen]
        value = None
        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntop(socket.AF_INET, rd)
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rd)
        elif rtype in (2, 5, 12):
            value, _ = read_name(buf, off)
        elif rtype == 15:
            pref = struct.unpack(">H", rd[:2])[0]
            host, _ = read_name(buf, off + 2)
            value = f"{pref} {host}"
        elif rtype == 16:
            parts, i = [], 0
            while i < len(rd):
                ln = rd[i]
                parts.append(rd[i + 1: i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            value = "".join(parts)
        elif rtype == 6:
            mname, p = read_name(buf, off)
            rname, p = read_name(buf, p)
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", buf[p: p + 20])
            value = f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        if value is not None:
            answers.append((TYPE_NAMES.get(rtype, str(rtype)), value))
        off += rdlen
    return rcode, answers


def query(name, rtype="A", timeout=3):
    pkt = build_query(name, QTYPES[rtype])
    last = None
    for server in get_resolvers():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (server, 53))
                data, _ = s.recvfrom(4096)
            rcode, answers = parse_response(data)
            if rcode not in (0, 3):  # 0=ok, 3=NXDOMAIN (a genuine "does not exist")
                last = OSError(f"{server} returned DNS rcode {rcode}")
                continue
            return [v for t, v in answers if t == rtype]
        except (OSError, struct.error, IndexError) as exc:
            last = exc
    raise OSError(f"all resolvers failed: {last}")


def enumerate_records(domain):
    result = {"module": "dns", "domain": domain, "records": {}, "ok": False, "notes": []}
    for rtype in ("A", "AAAA", "NS", "MX", "TXT", "SOA"):
        try:
            result["records"][rtype] = query(domain, rtype)
        except OSError as exc:
            result["records"][rtype] = []
            result["notes"].append(f"{rtype}: {exc}")
    # Successful only if real records came back; an empty/NXDOMAIN result
    # (domain missing, or a filtered resolver) must not produce conclusions.
    result["ok"] = any(result["records"].values())
    if not result["ok"]:
        result["notes"].append("No DNS records returned (NXDOMAIN, blocked or unreachable resolver)")
        return result
    txt = result["records"].get("TXT", [])
    result["email_security"] = {
        "spf": any(t.lower().startswith("v=spf1") for t in txt),
        "dmarc": False,
    }
    try:
        dmarc = query("_dmarc." + domain, "TXT")
        result["email_security"]["dmarc"] = any("v=DMARC1" in t for t in dmarc)
    except OSError as exc:
        result["email_security"]["dmarc"] = None
        result["notes"].append(f"DMARC lookup failed: {exc}")
    return result


COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "api", "dev", "test", "staging",
    "beta", "admin", "portal", "vpn", "remote", "blog", "shop", "store", "cdn", "static",
    "assets", "img", "images", "ns1", "ns2", "m", "mobile", "app", "docs", "support", "help",
    "status", "git", "gitlab", "jenkins", "intranet", "secure", "login", "sso", "auth",
]


def find_subdomains(domain, wordlist=None, workers=20):
    words = wordlist or COMMON_SUBS

    def probe(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ips = query(fqdn, "A", timeout=2)
            return (fqdn, ips) if ips else None
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [r for r in pool.map(probe, words) if r]
    return {
        "module": "subdomains",
        "domain": domain,
        "ok": True,
        "tested": len(words),
        "found": [{"host": h, "ips": ips} for h, ips in sorted(found)],
    }
