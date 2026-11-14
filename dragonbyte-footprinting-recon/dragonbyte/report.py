"""JSON + HTML report generation."""
import html
import json
import os
from datetime import datetime, timezone


def _e(x):
    return html.escape(str(x))


def findings(data):
    """Turn raw module output into a short list of (severity, text)."""
    out = []
    web, dns = data.get("web", {}), data.get("dns", {})
    for msg in web.get("missing_security_headers", []):
        out.append(("Medium" if "HSTS" in msg or "plain HTTP" in msg else "Low", msg))
    if web.get("ok") and not web.get("waf"):
        out.append(("Info", "No WAF/CDN signature detected from response headers"))
    if web.get("server"):
        out.append(("Low", f"Server banner exposed: {web['server']}"))
    for t in web.get("technologies", []):
        if t in ("PHP", "ASP.NET", "Express"):
            out.append(("Low", f"X-Powered-By technology disclosed: {t}"))
    es = dns.get("email_security", {})
    if dns.get("ok") and es.get("spf") is False:
        out.append(("Medium", "No SPF record found (email spoofing risk)"))
    if dns.get("ok") and es.get("dmarc") is False:
        out.append(("Medium", "No DMARC record found (email spoofing risk)"))
    subs = data.get("subdomains", {}).get("found", [])
    if subs:
        out.append(("Info", f"{len(subs)} subdomain(s) discovered - review for forgotten/dev hosts"))
    return out


def save(data, outdir):
    os.makedirs(outdir, exist_ok=True)
    data["findings"] = findings(data)
    jpath = os.path.join(outdir, "report.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    hpath = os.path.join(outdir, "report.html")
    with open(hpath, "w", encoding="utf-8") as fh:
        fh.write(render_html(data))
    return jpath, hpath


def render_html(d):
    w, dns, who = d.get("web", {}), d.get("dns", {}), d.get("whois", {})
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>DRAGONBYTE Recon - {_e(d['target'])}</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
 .wrap{{max-width:980px;margin:auto}} h1{{color:#ff6b35;margin-bottom:0}}
 h2{{border-bottom:1px solid #30363d;padding-bottom:6px;color:#58a6ff;margin-top:32px}}
 table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:top;word-break:break-word}}
 th{{background:#161b22}} code{{background:#161b22;padding:1px 5px;border-radius:4px}}
 .Medium{{color:#f0883e}} .Low{{color:#d29922}} .Info{{color:#58a6ff}} .High{{color:#f85149}}
 .muted{{color:#8b949e}}
</style></head><body><div class="wrap">
<h1>&#128009; DRAGONBYTE Recon Report</h1>
<p class="muted">Target: <b>{_e(d['target'])}</b> &middot; Generated: {_e(d['generated'])} &middot; Tool v{_e(d['version'])}</p>
<h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th></tr>"""]
    for sev, txt in d.get("findings", []):
        parts.append(f"<tr><td class='{sev}'>{sev}</td><td>{_e(txt)}</td></tr>")
    if not d.get("findings"):
        parts.append("<tr><td colspan=2>No findings.</td></tr>")
    parts.append("</table>")

    parts.append("<h2>WHOIS</h2>")
    if who.get("ok"):
        parts.append("<table>")
        for k, v in who.get("parsed", {}).items():
            parts.append(f"<tr><th>{_e(k)}</th><td>{_e(', '.join(v) if isinstance(v, list) else v)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append(f"<p class='muted'>Unavailable: {_e(who.get('error', 'skipped'))}</p>")

    parts.append("<h2>DNS Records</h2>")
    if dns.get("ok"):
        parts.append("<table>")
        for rtype, vals in dns.get("records", {}).items():
            parts.append(f"<tr><th>{rtype}</th><td>{'<br>'.join(_e(v) for v in vals) or '-'}</td></tr>")
        es = dns.get("email_security", {})
        parts.append(f"<tr><th>SPF / DMARC</th><td>SPF: {es.get('spf')} &middot; DMARC: {es.get('dmarc')}</td></tr></table>")
    else:
        parts.append(f"<p class='muted'>Unavailable: {_e('; '.join(dns.get('notes', [])) or 'skipped')}</p>")

    parts.append("<h2>Web Fingerprint</h2>")
    if w.get("ok"):
        parts.append("<table>")
        for label, val in (
            ("URL", w.get("final_url")), ("Status", w.get("status")), ("Title", w.get("title")),
            ("Server", w.get("server")), ("Technologies", ", ".join(w.get("technologies", [])) or "none detected"),
            ("WAF / CDN", ", ".join(w.get("waf", [])) or "none detected"),
            ("Common files", ", ".join(f"{k}={v}" for k, v in w.get("files", {}).items())),
        ):
            parts.append(f"<tr><th>{label}</th><td>{_e(val)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append(f"<p class='muted'>Unavailable: {_e('; '.join(w.get('errors', [])) or 'skipped')}</p>")

    subs = d.get("subdomains")
    if subs:
        parts.append(f"<h2>Subdomains ({len(subs.get('found', []))} found / {subs.get('tested')} tested)</h2><table>")
        for s in subs.get("found", []):
            parts.append(f"<tr><td>{_e(s['host'])}</td><td>{_e(', '.join(s['ips']))}</td></tr>")
        parts.append("</table>")

    parts.append("<p class='muted' style='margin-top:40px'>Authorized security assessment only. &copy; DRAGONBYTE</p></div></body></html>")
    return "".join(parts)


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
