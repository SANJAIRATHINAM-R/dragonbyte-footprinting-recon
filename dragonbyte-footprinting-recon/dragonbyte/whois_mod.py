"""WHOIS lookup over raw TCP/43 (no external packages)."""
import re
import socket

IANA = "whois.iana.org"
FIELDS = {
    "registrar": r"^\s*Registrar:\s*(.+)$",
    "created": r"^\s*(?:Creation Date|Created On|created):\s*(.+)$",
    "updated": r"^\s*(?:Updated Date|Last Updated On|changed):\s*(.+)$",
    "expires": r"^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|paid-till):\s*(.+)$",
    "registrant_org": r"^\s*Registrant Organi[sz]ation:\s*(.+)$",
    "registrant_country": r"^\s*Registrant Country:\s*(.+)$",
}


def _query(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def parse(raw):
    info = {}
    for key, pattern in FIELDS.items():
        m = re.search(pattern, raw, re.I | re.M)
        if m:
            info[key] = m.group(1).strip()
    ns = re.findall(r"^\s*Name Server:\s*(\S+)", raw, re.I | re.M)
    if ns:
        info["name_servers"] = sorted({n.lower().rstrip(".") for n in ns})
    status = re.findall(r"^\s*(?:Domain )?Status:\s*(\S+)", raw, re.I | re.M)
    if status:
        info["status"] = sorted(set(status))
    return info


def run(domain, timeout=10):
    result = {"module": "whois", "domain": domain, "ok": False}
    try:
        iana = _query(IANA, domain, timeout)
        m = re.search(r"^\s*(?:refer|whois):\s*(\S+)", iana, re.I | re.M)
        server = m.group(1) if m else IANA
        raw = _query(server, domain, timeout)
        # Thin registries (e.g. .com) refer to the registrar's server
        m2 = re.search(r"Registrar WHOIS Server:\s*(\S+)", raw, re.I)
        if m2 and m2.group(1).lower() != server.lower():
            try:
                raw = _query(m2.group(1), domain, timeout) or raw
            except OSError:
                pass
        result.update(ok=True, server=server, parsed=parse(raw), raw=raw[:6000])
    except OSError as exc:
        result["error"] = str(exc)
    return result
