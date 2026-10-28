"""
Tests for ZAP Integration Engine
Validates ZAP client health diagnostics and alert normalization parsing.
"""
import unittest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zap_engine import ZAPEngine


class TestZAPEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ZAPEngine(zap_url="http://127.0.0.1:8080", api_key="test_api_key")

    def test_health_check_offline_diagnostics(self):
        """Verifies that health check accurately reports offline status when daemon is not listening."""
        health = self.engine.check_health()
        self.assertIn("online", health)
        if not health["online"]:
            self.assertIn("error", health)
            self.assertIn("diagnostics", health)
            self.assertIn("ZAP", health["diagnostics"])

    def test_normalize_zap_alert(self):
        """Verifies that raw ZAP alert payloads are accurately mapped to SentinelX schema."""
        raw_zap_alert = {
            "sourceid": "1",
            "other": "Attackers can steal session identifiers.",
            "method": "GET",
            "evidence": "Set-Cookie: sessionid=secret_session_token_xyz999; path=/",
            "pluginId": "10010",
            "cweid": "614",
            "confidence": "2",
            "wascid": "13",
            "description": "A cookie has been set without the Secure attribute.",
            "messageId": "4",
            "url": "https://example.com/login",
            "risk": "Medium",
            "reference": "https://owasp.org/www-project-web-security-testing-guide/",
            "solution": "Set the Secure flag on all sensitive cookies.",
            "alert": "Cookie No HttpOnly Flag",
            "param": "sessionid"
        }

        normalized = self.engine._normalize_zap_alert(raw_zap_alert)

        self.assertEqual(normalized["name"], "Cookie No HttpOnly Flag")
        self.assertEqual(normalized["severity"], "Medium")
        self.assertEqual(normalized["confidence"], "High")
        self.assertEqual(normalized["cwe_id"], "CWE-614")
        self.assertEqual(normalized["affected_url"], "https://example.com/login")
        self.assertEqual(normalized["status"], "Confirmed Evidence")
        self.assertEqual(normalized["remediation"], "Set the Secure flag on all sensitive cookies.")
        self.assertIn("scanner", normalized)


if __name__ == "__main__":
    unittest.main()
