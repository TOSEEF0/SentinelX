"""
Tests for Report Generation Module
Validates structured JSON export and publication-grade PDF report production.
"""
import unittest
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import create_scan, save_findings, finalize_scan
from report_generator import generate_json_report, generate_pdf_report


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.target_url = "https://test-example.com"
        self.scan_id = create_scan(self.target_url, "standard", "SentinelX Native Auditor")
        self.sample_findings = [
            {
                "name": "Missing Strict-Transport-Security (HSTS) Header",
                "severity": "Medium",
                "confidence": "Certain",
                "affected_url": self.target_url,
                "evidence": "Header absent in response.",
                "cwe_id": "CWE-319",
                "wasc_id": "WASC-15",
                "description": "HSTS header is absent from HTTPS response.",
                "impact": "Susceptible to SSL stripping downgrade attacks.",
                "remediation": "Add Strict-Transport-Security header.",
                "status": "Confirmed Evidence",
                "category": "Security Headers"
            },
            {
                "name": "Exposed Sensitive Credential: AWS Access Key ID",
                "severity": "High",
                "confidence": "Certain",
                "affected_url": f"{self.target_url}/app.js",
                "evidence": "Matched: AKIA************MPLE",
                "cwe_id": "CWE-798",
                "wasc_id": "WASC-14",
                "description": "High-entropy key pattern found in public JS bundle.",
                "impact": "Account takeover and cloud unauthorized access.",
                "remediation": "Revoke key and migrate to environment variables.",
                "status": "Confirmed Evidence",
                "category": "Credential Exposure"
            }
        ]
        save_findings(self.scan_id, self.sample_findings)
        finalize_scan(self.scan_id, "completed", 12.5, self.sample_findings)

    def test_json_report_generation(self):
        """Verifies JSON export structure and schema conformance."""
        json_path = generate_json_report(self.scan_id)
        self.assertTrue(json_path.exists())

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["target"]["url"], self.target_url)
        self.assertEqual(data["executive_summary"]["total_findings"], 2)
        self.assertEqual(data["executive_summary"]["high_severity"], 1)
        self.assertEqual(data["executive_summary"]["medium_severity"], 1)
        self.assertEqual(len(data["findings"]), 2)

    def test_pdf_report_generation(self):
        """Verifies executive PDF report generation via ReportLab."""
        pdf_path = generate_pdf_report(self.scan_id)
        self.assertTrue(pdf_path.exists())
        self.assertGreater(pdf_path.stat().st_size, 2000, "PDF report should contain formatted content.")


if __name__ == "__main__":
    unittest.main()
