"""HTTP fingerprinting, security-header audit and WAF detection."""
import re
import ssl
import urllib.error
import urllib.request

UA = "DRAGONBYTE-Recon/1.0 (authorized security assessment)"

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing: browsers may use plain HTTP",
    "content-security-policy": "CSP missing: weaker XSS protection",
    "x-frame-options": "X-Frame-Options missing: clickjacking risk",
    "x-content-type-options": "X-Content-Type-Options missing: MIME sniffing",
    "referrer-policy": "Referrer-Policy missing",
    "permissions-policy": "Permissions-Policy missing",
}

# (technology, where, regex)
TECH_SIGNATURES = [
    ("WordPress", "body", r"wp-content|wp-includes|/wp-json/"),
    ("Drupal", "body", r"Drupal\.settings|sites/default/files"),
    ("Joomla", "body", r"/media/jui/|Joomla!"),
    ("Shopify", "body", r"cdn\.shopify\.com"),
    ("Wix", "body", r"static\.wixstatic\.com"),
    ("React", "body", r"data-reactroot|__NEXT_DATA__"),
    ("jQuery", "body", r"jquery[.-][\d.]*(?:min\.)?js"),
    ("Bootstrap", "body", r"bootstrap[.-][\d.]*(?:min\.)?(?:css|js)"),
    ("Google Analytics", "body", r"google-analytics\.com|googletagmanager\.com"),
    ("Nginx", "server", r"nginx"),
    ("Apache", "server", r"apache"),
    ("Microsoft IIS", "server", r"iis"),
    ("LiteSpeed", "server", r"litespeed"),
    ("PHP", "x-powered-by", r"php"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("Express", "x-powered-by", r"express"),
]

# (WAF/CDN, header-or-cookie signature regex applied to "name: value" lines)
WAF_SIGNATURES = [
    ("Cloudflare", r"^cf-ray:|^server:\s*cloudflare|__cfduid|cf_clearance"),
    ("Akamai", r"^server:\s*akamaighost|x-akamai"),
    ("Sucuri", r"^x-sucuri|^server:\s*sucuri"),
    ("Imperva Incapsula", r"x-iinfo|incap_ses|visid_incap"),
    ("AWS CloudFront / WAF", r"^x-amz-cf-id|^via:.*cloudfront|awselb|awsalb"),
    ("Fastly", r"^x-served-by:.*cache|^fastly-"),
    ("F5 BIG-IP ASM", r"bigipserver|ts[0-9a-f]{8}=|x-wa-info"),
    ("Barracuda", r"barra_counter_session"),
    ("ModSecurity", r"mod_security|modsecurity"),
    ("Wordfence", r"wordfence"),
]


def fetch(url, timeout=10, max_bytes=300_000):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(max_bytes).decode("utf-8", "replace")
            return resp.status, dict(resp.headers.items()), body, resp.geturl()
    except urllib.error.HTTPError as err:  # 4xx/5xx still carry useful headers
        body = err.read(max_bytes).decode("utf-8", "replace")
        return err.code, dict(err.headers.items()), body, url


def detect_tech(headers, body):
    low = {k.lower(): v for k, v in headers.items()}
    found = set()
    for tech, where, pattern in TECH_SIGNATURES:
        hay = body if where == "body" else low.get(where, "")
        if hay and re.search(pattern, hay, re.I):
            found.add(tech)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        found.add("Generator: " + gen.group(1).strip())
    return sorted(found)


def detect_waf(headers):
    blob = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items())
    return sorted({name for name, pat in WAF_SIGNATURES if re.search(pat, blob, re.I | re.M)})


def audit_headers(headers):
    low = {k.lower() for k in headers}
    return [msg for h, msg in SECURITY_HEADERS.items() if h not in low]


def run(domain, timeout=10):
    result = {"module": "web", "domain": domain, "ok": False}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            status, headers, body, final = fetch(url, timeout)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the scan
            result.setdefault("errors", []).append(f"{url}: {exc}")
            continue
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        result.update(
            ok=True,
            url=url,
            final_url=final,
            status=status,
            title=title.group(1).strip()[:150] if title else None,
            server=headers.get("Server"),
            headers=headers,
            technologies=detect_tech(headers, body),
            waf=detect_waf(headers),
            missing_security_headers=audit_headers(headers) if scheme == "https" else
            ["Site served over plain HTTP only"] + audit_headers(headers),
        )
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
            try:
                code, _, _, _ = fetch(f"{scheme}://{domain}/{path}", timeout)
                result.setdefault("files", {})[path] = code
            except Exception:  # noqa: BLE001
                result.setdefault("files", {})[path] = None
        break
    return result
