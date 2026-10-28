"""
Tests for SentinelX REST API Endpoints
Validates API authorization controls, input validations, scan triggers,
findings queries, and report download routes.
"""
import unittest
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from models import create_scan, save_findings, finalize_scan


class TestAppEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.scan_id = create_scan("https://example.com", "quick", "SentinelX Native Auditor")
        self.findings = [{
            "name": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "severity": "Medium",
            "confidence": "Certain",
            "affected_url": "https://example.com",
            "evidence": "X-Frame-Options header absent.",
            "cwe_id": "CWE-1021",
            "description": "Page can be rendered in an iframe.",
            "impact": "Clickjacking vulnerability.",
            "remediation": "Send X-Frame-Options: DENY.",
            "status": "Confirmed Evidence",
            "category": "Security Headers"
        }]
        save_findings(self.scan_id, self.findings)
        finalize_scan(self.scan_id, "completed", 5.2, self.findings)

    def test_get_index(self):
        """Verifies dashboard HTML renders successfully."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SentinelX", resp.data)

    def test_get_system_status(self):
        """Verifies system status endpoint returns engine details."""
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("zap_engine", data)
        self.assertIn("native_engine", data)
        self.assertIn("profiles", data)

    def test_scan_trigger_rejects_unauthorized(self):
        """Verifies scans without explicit authorization are rejected with 403."""
        payload = {
            "url": "https://example.com",
            "profile": "quick",
            "authorized": False
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertIn("authorization", data["error"].lower())

    def test_scan_trigger_rejects_ssrf(self):
        """Verifies SSRF target is rejected with 400."""
        payload = {
            "url": "http://169.254.169.254/latest/meta-data/",
            "profile": "quick",
            "authorized": True
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("SSRF", data["message"])

    def test_scan_trigger_accepts_valid_request(self):
        """Verifies authorized valid scan request returns 202 Accepted with scan_id."""
        payload = {
            "url": "https://example.com",
            "profile": "quick",
            "authorized": True
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 202)
        data = resp.get_json()
        self.assertEqual(data["status"], "started")
        self.assertIn("scan_id", data)

    def test_get_scan_details(self):
        """Verifies scan details endpoint."""
        resp = self.client.get(f"/api/scans/{self.scan_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["scan"]["id"], self.scan_id)

    def test_get_findings_with_filter(self):
        """Verifies findings query and severity filtering."""
        resp = self.client.get(f"/api/scans/{self.scan_id}/findings?severity=Medium")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 1)

        # Non-matching filter
        resp_none = self.client.get(f"/api/scans/{self.scan_id}/findings?severity=High")
        self.assertEqual(resp_none.get_json()["count"], 0)

    def test_get_finding_advisory(self):
        """Verifies AI/deterministic remediation advisory endpoint."""
        findings_resp = self.client.get(f"/api/scans/{self.scan_id}/findings")
        finding_id = findings_resp.get_json()["findings"][0]["id"]

        resp = self.client.get(f"/api/findings/{finding_id}/advisory")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("advisory", data)
        self.assertIn("remediation_steps", data["advisory"])


if __name__ == "__main__":
    unittest.main()
