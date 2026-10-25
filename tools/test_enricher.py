"""Offline tests for enricher.py. No API keys or network needed.

Run from the repo root:  python -m unittest discover -s tools -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enricher as e  # noqa: E402


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    """Returns canned responses keyed by a substring of the requested URL or IP."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        key = params["ipAddress"] if params else url
        self.calls.append(key)
        for needle, resp in self.routes.items():
            if needle in key:
                return resp
        return FakeResponse(404)


def vt(mal, sus=0, harmless=60, undetected=10):
    return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": undetected}}}})


def abuse(score, reports=0, tor=False):
    return FakeResponse(200, {"data": {"abuseConfidenceScore": score, "totalReports": reports,
                                       "isp": "Test ISP", "countryCode": "DE", "isTor": tor}})


class TestParsing(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(e.classify("8.8.8.8"), "ip")
        self.assertEqual(e.classify("192.168.10.45"), "private_ip")
        self.assertEqual(e.classify("127.0.0.1"), "private_ip")
        self.assertEqual(e.classify("devret.xyz"), "domain")
        self.assertEqual(e.classify("a" * 64), "hash")
        self.assertEqual(e.classify("not an ioc"), "unknown")

    def test_domain_regex_rejects_symbols(self):
        # The old pattern [a-zA-Z0-9-_] accidentally allowed characters like ':' and '@'.
        self.assertEqual(e.classify("bad:host.com"), "unknown")
        self.assertEqual(e.classify("user@host.com"), "unknown")

    def test_defang_and_refang_round_trip(self):
        self.assertEqual(e.defang("devret.xyz"), "devret[.]xyz")
        self.assertEqual(e.refang("hxxps://devret[.]xyz/pixel.png"), "devret.xyz")


class TestVerdicts(unittest.TestCase):
    def run_one(self, ioc, routes, vt_key="k", abuse_key="k"):
        rows = e.enrich([(ioc, "")], vt_key, abuse_key, vt_delay=0,
                        session=FakeSession(routes), log=lambda *_: None)
        return rows[0]

    def test_no_keys_is_no_data_not_clean(self):
        """The old version reported BENIGN when no keys were set. That is fail-open."""
        row = self.run_one("8.8.8.8", {}, vt_key="", abuse_key="")
        self.assertEqual(row["verdict"], "NO DATA")

    def test_private_ip_never_sent_to_apis(self):
        session = FakeSession({})
        rows = e.enrich([("192.168.10.45", "")], "k", "k", vt_delay=0, session=session, log=lambda *_: None)
        self.assertEqual(rows[0]["verdict"], "INTERNAL")
        self.assertEqual(session.calls, [])

    def test_malicious_by_virustotal(self):
        row = self.run_one("devret.xyz", {"devret.xyz": vt(9)})
        self.assertEqual(row["verdict"], "MALICIOUS")

    def test_malicious_by_abuseipdb(self):
        row = self.run_one("185.220.101.5", {"185.220.101.5": abuse(100, 1420, tor=True)})
        self.assertEqual(row["verdict"], "MALICIOUS")
        self.assertIn("Tor exit", row["abuse"])

    def test_suspicious_low_detections(self):
        row = self.run_one("sultanbogor.com", {"sultanbogor.com": vt(2)})
        self.assertEqual(row["verdict"], "SUSPICIOUS")

    def test_clean_requires_real_answer(self):
        row = self.run_one("8.8.8.8", {"8.8.8.8": vt(0)})
        self.assertEqual(row["verdict"], "CLEAN")

    def test_not_found_hash(self):
        row = self.run_one("b" * 64, {})
        self.assertEqual(row["verdict"], "NOT FOUND")

    def test_rate_limit_is_no_data(self):
        row = self.run_one("devret.xyz", {"devret.xyz": FakeResponse(429)}, abuse_key="")
        self.assertEqual(row["verdict"], "NO DATA")
        self.assertIn("rate limited", row["vt"])


class TestRateLimit(unittest.TestCase):
    def test_waits_between_virustotal_calls(self):
        waits = []
        e.enrich([("a.com", ""), ("b.com", ""), ("c.com", "")], "k", "", vt_delay=15,
                 session=FakeSession({}), sleep=waits.append, log=lambda *_: None)
        self.assertEqual(waits, [15, 15])


if __name__ == "__main__":
    unittest.main()
