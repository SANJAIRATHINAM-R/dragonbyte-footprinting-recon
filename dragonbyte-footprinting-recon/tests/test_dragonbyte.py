import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dragonbyte import dns_mod, report, web_mod, whois_mod  # noqa: E402


def fake_dns_response(qname="example.com"):
    """Build a response with an A, MX and TXT answer using name compression."""
    qn = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    header = struct.pack(">HHHHHH", 1, 0x8180, 1, 3, 0, 0)
    question = qn + struct.pack(">HH", 1, 1)
    ptr = b"\xc0\x0c"  # points at the question name (offset 12)
    a = ptr + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    mx_name = b"\x04mail" + ptr
    mx = ptr + struct.pack(">HHIH", 15, 1, 60, 2 + len(mx_name)) + struct.pack(">H", 10) + mx_name
    txt_val = b"v=spf1 -all"
    txt = ptr + struct.pack(">HHIH", 16, 1, 60, 1 + len(txt_val)) + bytes([len(txt_val)]) + txt_val
    return header + question + a + mx + txt


class TestDNS(unittest.TestCase):
    def test_parse_response(self):
        rcode, answers = dns_mod.parse_response(fake_dns_response())
        self.assertEqual(rcode, 0)
        self.assertIn(("A", "93.184.216.34"), answers)
        self.assertIn(("MX", "10 mail.example.com"), answers)
        self.assertIn(("TXT", "v=spf1 -all"), answers)

    def test_build_query_roundtrip(self):
        pkt = dns_mod.build_query("a.b.com", 1)
        name, off = dns_mod.read_name(pkt, 12)
        self.assertEqual(name, "a.b.com")


class TestWeb(unittest.TestCase):
    def test_tech_and_waf(self):
        headers = {"Server": "nginx", "CF-RAY": "abc", "X-Powered-By": "PHP/8.2"}
        body = '<meta name="generator" content="WordPress 6.5"><link href="/wp-content/x.css">'
        tech = web_mod.detect_tech(headers, body)
        self.assertIn("WordPress", tech)
        self.assertIn("Nginx", tech)
        self.assertIn("PHP", tech)
        self.assertIn("Cloudflare", web_mod.detect_waf(headers))

    def test_header_audit(self):
        missing = web_mod.audit_headers({"X-Frame-Options": "DENY"})
        self.assertTrue(any("HSTS" in m for m in missing))
        self.assertFalse(any("X-Frame" in m for m in missing))


class TestWhoisAndReport(unittest.TestCase):
    def test_whois_parse(self):
        raw = ("Registrar: Example Registrar\nCreation Date: 2001-01-01T00:00:00Z\n"
               "Name Server: NS1.EXAMPLE.COM\nName Server: ns2.example.com\n")
        p = whois_mod.parse(raw)
        self.assertEqual(p["registrar"], "Example Registrar")
        self.assertEqual(p["name_servers"], ["ns1.example.com", "ns2.example.com"])

    def test_report_files(self):
        data = {
            "target": "example.com", "version": "1.0.0", "generated": report.utcnow(),
            "web": {"ok": True, "final_url": "https://example.com", "status": 200, "server": "nginx",
                    "technologies": ["Nginx"], "waf": [], "missing_security_headers": ["HSTS missing"],
                    "files": {"robots.txt": 200}},
            "dns": {"ok": True, "records": {"A": ["1.2.3.4"]}, "email_security": {"spf": False, "dmarc": False}},
            "whois": {"ok": False, "error": "offline"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            j, h = report.save(data, tmp)
            self.assertTrue(os.path.getsize(j) > 0)
            with open(h, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("DRAGONBYTE Recon Report", content)
            self.assertIn("No SPF record", content)


if __name__ == "__main__":
    unittest.main()
