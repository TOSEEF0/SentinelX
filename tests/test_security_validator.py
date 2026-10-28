"""
Tests for Security Validator Module
Validates URL syntax, SSRF protection, DNS resolution, and sensitive data redaction.
"""
import unittest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_validator import (
    validate_target_url, is_ip_blocked, redact_sensitive_headers,
    redact_secrets, find_exposed_credentials
)


class TestSecurityValidator(unittest.TestCase):

    def test_invalid_schemes(self):
        """Ensures non-HTTP/HTTPS schemes are blocked."""
        for invalid_url in [
            "ftp://example.com/file",
            "gopher://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,test",
            "ws://example.com",
        ]:
            valid, err, _ = validate_target_url(invalid_url, allow_local_for_test=False)
            self.assertFalse(valid, f"Should reject scheme for {invalid_url}")
            self.assertIn("Invalid scheme", err)

    def test_rejection_of_userinfo_credentials(self):
        """Ensures embedded username/password in URL is rejected to prevent credential leaks."""
        url = "http://admin:supersecret@example.com/login"
        valid, err, _ = validate_target_url(url, allow_local_for_test=False)
        self.assertFalse(valid)
        self.assertIn("Credentials in URL", err)

    def test_ssrf_blocking_private_ips(self):
        """Ensures RFC 1918 and loopback IPs are blocked by default."""
        test_cases = [
            "http://10.0.0.1/",
            "http://192.168.1.100:8080/",
            "http://172.16.5.20/",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://0.0.0.0/",
            "http://127.0.0.1/",
            "http://localhost:8000/",
        ]
        for url in test_cases:
            valid, err, _ = validate_target_url(url, allow_local_for_test=False)
            self.assertFalse(valid, f"Failed to block SSRF target {url}")
            self.assertTrue("SSRF" in err or "restricted" in err or "prohibited" in err)

    def test_local_test_exemption(self):
        """Verifies that allow_local_for_test=True permits approved test ports."""
        valid_local = "http://127.0.0.1:5050/"
        valid, err, details = validate_target_url(valid_local, allow_local_for_test=True, allowed_ports=[5050])
        self.assertTrue(valid)
        self.assertEqual(details["port"], 5050)
        self.assertTrue(details["is_test_target"])

        # Unapproved port should still fail
        invalid_local = "http://127.0.0.1:22/"
        valid2, err2, _ = validate_target_url(invalid_local, allow_local_for_test=True, allowed_ports=[5050])
        self.assertFalse(valid2)

    def test_redact_sensitive_headers(self):
        """Verifies that Authorization, Cookie, and API keys are redacted."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI...",
            "Cookie": "session=secret_session_token_12345",
            "X-Api-Key": "live_api_key_abcdef12345",
            "Server": "nginx/1.24"
        }
        redacted = redact_sensitive_headers(headers)
        self.assertEqual(redacted["Content-Type"], "application/json")
        self.assertEqual(redacted["Server"], "nginx/1.24")
        self.assertEqual(redacted["Authorization"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(redacted["Cookie"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(redacted["X-Api-Key"], "[REDACTED_SENSITIVE_HEADER]")

    def test_redact_secrets_in_text(self):
        """Verifies pattern matching and masking of known credentials."""
        text = "Found AWS Key: AKIAIOSFODNN7EXAMPLE in config and github token ghp_1234567890abcdef1234567890abcdef1234"
        masked = redact_secrets(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", masked)
        self.assertNotIn("ghp_1234567890abcdef1234567890abcdef1234", masked)
        self.assertIn("AKIA", masked)  # Preserves prefix for diagnosis
        self.assertIn("****", masked)

    def test_find_exposed_credentials(self):
        """Verifies detection of exposed tokens in HTML/JS."""
        sample_code = """
        const awsKey = "AKIAIOSFODNN7EXAMPLE";
        const googleKey = "AIzaSyD-TEST_KEY_FOR_QA_AUDITOR_12345";
        """
        findings = find_exposed_credentials(sample_code, "http://example.com/app.js")
        self.assertEqual(len(findings), 2)
        types = [f["type"] for f in findings]
        self.assertIn("AWS Access Key ID", types)
        self.assertIn("Google Cloud API Key", types)
        # Verify evidence context is redacted
        for f in findings:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f["evidence_context"])


if __name__ == "__main__":
    unittest.main()
