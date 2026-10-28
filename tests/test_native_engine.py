"""
Tests for Native Security Auditor Engine
Tests real dynamic auditing against the authorized local test fixture application.
"""
import unittest
import threading
import time
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from native_engine import NativeAuditorEngine
from test_target_app import test_app
from models import create_scan, get_scan


class TestNativeEngine(unittest.TestCase):
    server_thread = None
    server_started = False

    @classmethod
    def setUpClass(cls):
        """Starts the vulnerable test target on 127.0.0.1:5050 in a background thread."""
        cls.server_thread = threading.Thread(
            target=lambda: test_app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False),
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1.0)  # Wait for Flask to bind

    def test_audit_execution_against_test_target(self):
        """Runs the native engine against the live test target and verifies evidence extraction."""
        engine = NativeAuditorEngine(allow_local_for_test=True)
        target_url = "http://127.0.0.1:5050/"
        scan_id = create_scan(target_url, "standard", "SentinelX Native Auditor")

        findings = engine.execute_scan(scan_id, target_url, profile_code="standard")
        self.assertGreater(len(findings), 0, "Native auditor should generate findings from vulnerable test target.")

        finding_names = [f["name"] for f in findings]
        cwes = [f.get("cwe_id") for f in findings]

        # Verify key vulnerability checks were triggered with real evidence:
        # 1. Missing CSP
        self.assertTrue(any("Content-Security-Policy" in n for n in finding_names))
        # 2. Missing Clickjacking Protection
        self.assertTrue(any("Clickjacking" in n or "X-Frame-Options" in n for n in finding_names))
        # 3. Missing X-Content-Type-Options
        self.assertTrue(any("X-Content-Type-Options" in n for n in finding_names))
        # 4. Server information disclosure
        self.assertTrue(any("Server" in n or "Banner" in n for n in finding_names))
        # 5. Insecure Cookie attributes
        self.assertTrue(any("Cookie" in n for n in finding_names))
        # 6. Exposed credential detection
        self.assertTrue(any("Exposed" in n or "Credential" in n for n in finding_names))
        # 7. Sensitive file disclosure (/.env)
        self.assertTrue(any("Environment Variables" in n or ".env" in n for n in finding_names))

        # Verify evidence is present and sanitized
        for f in findings:
            self.assertIn("affected_url", f)
            self.assertIn("severity", f)
            self.assertIn("confidence", f)
            self.assertIn("description", f)
            self.assertIn("remediation", f)
            self.assertIn("status", f)
            # Ensure no unredacted AWS test secret appears in evidence
            if "AKIAIOSFODNN7EXAMPLE" in f.get("evidence", ""):
                self.fail(f"Finding {f['name']} leaked raw unredacted secret in evidence!")


if __name__ == "__main__":
    unittest.main()
