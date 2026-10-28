"""
SentinelX OWASP ZAP Integration Engine
Directly interfaces with the OWASP ZAP REST API using official zapv2 client.
Handles spidering, active/passive scans, and alert normalization with evidence parsing.
"""
import time
import uuid
import logging
from typing import Dict, Any, List, Optional
import requests
from zapv2 import ZAPv2

from config import ZAP_URL, ZAP_API_KEY, ZAP_TIMEOUT, ZAP_POLL_INTERVAL
from security_validator import redact_sensitive_headers, redact_secrets
from models import update_scan_progress, add_audit_log

logger = logging.getLogger("sentinelx.zap")


class ZAPEngine:
    """Production wrapper for OWASP ZAP REST API."""

    def __init__(self, zap_url: str = ZAP_URL, api_key: str = ZAP_API_KEY):
        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key
        # Configure ZAP client
        self.zap = ZAPv2(
            proxies={"http": self.zap_url, "https": self.zap_url},
            apikey=self.api_key
        )

    def check_health(self) -> Dict[str, Any]:
        """
        Pings ZAP daemon and checks connectivity.
        Returns health dict with online status, version, and diagnostics.
        """
        try:
            # Test direct HTTP ping first to provide accurate connection error messages
            test_resp = requests.get(f"{self.zap_url}/JSON/core/view/version/?apikey={self.api_key}", timeout=2.5)
            if test_resp.status_code == 200:
                data = test_resp.json()
                version = data.get("version", "Unknown")
                return {
                    "online": True,
                    "version": version,
                    "zap_url": self.zap_url,
                    "message": f"OWASP ZAP Core v{version} is online and accepting API commands."
                }
            elif test_resp.status_code == 403:
                return {
                    "online": False,
                    "version": None,
                    "zap_url": self.zap_url,
                    "error": "ZAP API key authentication failed (HTTP 403 Forbidden).",
                    "diagnostics": "Verify that ZAP_API_KEY in .env matches the api.key configured in the ZAP daemon."
                }
            else:
                return {
                    "online": False,
                    "version": None,
                    "zap_url": self.zap_url,
                    "error": f"ZAP responded with unexpected status HTTP {test_resp.status_code}.",
                    "diagnostics": test_resp.text[:200]
                }
        except requests.exceptions.ConnectionError as ce:
            return {
                "online": False,
                "version": None,
                "zap_url": self.zap_url,
                "error": f"Connection refused on {self.zap_url}.",
                "diagnostics": (
                    "ZAP daemon is not currently listening. In this environment, Docker service or local "
                    "ZAP daemon can be started using: 'docker run -d -p 8080:8080 zaproxy/zap-stable zap.sh -daemon "
                    f"-port 8080 -host 0.0.0.0 -config api.key={self.api_key}'. "
                    "SentinelX will utilize its Native Security Auditor engine when ZAP daemon is offline."
                )
            }
        except Exception as e:
            return {
                "online": False,
                "version": None,
                "zap_url": self.zap_url,
                "error": str(e),
                "diagnostics": "Unhandled exception connecting to ZAP API endpoint."
            }

    def execute_scan(self, scan_id: str, target_url: str, profile_code: str) -> List[Dict[str, Any]]:
        """
        Runs an end-to-end scan using the live OWASP ZAP engine.
        Updates progress via models callback and returns normalized findings.
        """
        add_audit_log(scan_id, "INFO", f"Connecting to OWASP ZAP API at {self.zap_url}...")
        
        # 1. Access the target URL through ZAP to seed the session
        try:
            self.zap.core.access_url(url=target_url)
            time.sleep(1)
        except Exception as e:
            add_audit_log(scan_id, "WARN", f"ZAP core accessUrl notice: {e}")

        # 2. Spider / Crawl Target
        add_audit_log(scan_id, "INFO", f"Starting OWASP ZAP Spider for target {target_url}...")
        update_scan_progress(scan_id, 15, "ZAP Spider: Discovering Endpoints")
        
        try:
            spider_scan_id = self.zap.spider.scan(url=target_url)
            start_time = time.time()
            while int(self.zap.spider.status(spider_scan_id)) < 100:
                progress = int(self.zap.spider.status(spider_scan_id))
                mapped_progress = 15 + int(progress * 0.35)  # 15% to 50%
                update_scan_progress(scan_id, mapped_progress, f"ZAP Spider: Crawling ({progress}%)")
                time.sleep(ZAP_POLL_INTERVAL)
                if time.time() - start_time > ZAP_TIMEOUT:
                    add_audit_log(scan_id, "WARN", "ZAP Spider reached configured timeout limit.")
                    break
        except Exception as e:
            add_audit_log(scan_id, "WARN", f"ZAP Spider execution notice: {e}")

        # 3. Passive Scanning: Drain records queue
        add_audit_log(scan_id, "INFO", "Waiting for ZAP passive scan queue to complete analysis...")
        update_scan_progress(scan_id, 55, "ZAP Passive Scanner: Analyzing Traffic")
        try:
            pscan_start = time.time()
            records_to_scan = int(self.zap.pscan.records_to_scan)
            while records_to_scan > 0 and (time.time() - pscan_start < 45):
                time.sleep(1.0)
                records_to_scan = int(self.zap.pscan.records_to_scan)
        except Exception as e:
            add_audit_log(scan_id, "WARN", f"ZAP pscan status check: {e}")

        # 4. Active Scan (Only for Advanced Profile)
        if profile_code == "advanced":
            add_audit_log(scan_id, "INFO", "Profile 'Advanced Audit' requested. Starting OWASP ZAP Active Scanner...")
            update_scan_progress(scan_id, 65, "ZAP Active Scanner: Executing Authorized Checks")
            try:
                ascan_id = self.zap.ascan.scan(url=target_url)
                ascan_start = time.time()
                while int(self.zap.ascan.status(ascan_id)) < 100:
                    status = int(self.zap.ascan.status(ascan_id))
                    mapped_progress = 65 + int(status * 0.25)  # 65% to 90%
                    update_scan_progress(scan_id, mapped_progress, f"ZAP Active Scanner ({status}%)")
                    time.sleep(ZAP_POLL_INTERVAL)
                    if time.time() - ascan_start > ZAP_TIMEOUT:
                        add_audit_log(scan_id, "WARN", "ZAP Active Scan reached timeout limit.")
                        break
            except Exception as e:
                add_audit_log(scan_id, "ERROR", f"ZAP Active Scan error: {e}")
        else:
            add_audit_log(scan_id, "INFO", f"Skipping active scanner (profile '{profile_code}' is non-aggressive).")

        # 5. Retrieve and Normalize ZAP Alerts
        update_scan_progress(scan_id, 92, "Retrieving and Parsing ZAP Alerts")
        add_audit_log(scan_id, "INFO", "Retrieving real alerts from ZAP session...")
        
        normalized_findings = []
        try:
            raw_alerts = self.zap.alert.alerts(baseurl=target_url)
            add_audit_log(scan_id, "INFO", f"ZAP reported {len(raw_alerts)} raw alerts.")
            
            for alert in raw_alerts:
                finding = self._normalize_zap_alert(alert)
                normalized_findings.append(finding)
        except Exception as e:
            add_audit_log(scan_id, "ERROR", f"Failed to retrieve alerts from ZAP: {e}")

        return normalized_findings

    def _normalize_zap_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Maps ZAP raw alert to unified SentinelX Finding schema."""
        raw_risk = alert.get("risk", "Informational").capitalize()
        # Ensure severity is one of standard: High, Medium, Low, Informational
        severity_map = {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Informational",
            "Info": "Informational"
        }
        severity = severity_map.get(raw_risk, "Informational")

        confidence_map = {
            "3": "Certain",
            "2": "High",
            "1": "Medium",
            "0": "Low",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Certain": "Certain",
            "False Positive": "Low"
        }
        raw_conf = str(alert.get("confidence", "Medium"))
        confidence = confidence_map.get(raw_conf, "Medium")

        evidence = alert.get("evidence", "").strip()
        has_evidence = bool(evidence)
        verification_status = "Confirmed Evidence" if has_evidence else "Potential Finding"

        # Request / Response details
        message_id = alert.get("messageId")
        req_snippet = ""
        resp_snippet = ""
        if message_id:
            try:
                msg = self.zap.core.message(id=message_id)
                if msg:
                    raw_req = msg.get("requestHeader", "") + "\n" + msg.get("requestBody", "")
                    raw_resp = msg.get("responseHeader", "") + "\n" + msg.get("responseBody", "")
                    req_snippet = redact_secrets(raw_req[:1000])
                    resp_snippet = redact_secrets(raw_resp[:1000])
            except Exception:
                pass

        cwe_id = alert.get("cweid", "")
        if cwe_id and not str(cwe_id).startswith("CWE-") and cwe_id != "0":
            cwe_id = f"CWE-{cwe_id}"
        elif cwe_id == "0":
            cwe_id = ""

        return {
            "id": str(uuid.uuid4()),
            "name": alert.get("alert", "ZAP Finding"),
            "severity": severity,
            "confidence": confidence,
            "affected_url": alert.get("url", ""),
            "evidence": redact_secrets(evidence),
            "cwe_id": cwe_id,
            "wasc_id": alert.get("wascid", ""),
            "description": alert.get("description", "").strip(),
            "impact": alert.get("other", "Potential risk identified through automated dynamic analysis.").strip(),
            "remediation": alert.get("solution", "Review server configuration and apply recommended defense-in-depth controls.").strip(),
            "request_snippet": req_snippet,
            "response_snippet": resp_snippet,
            "status": verification_status,
            "category": alert.get("pluginId", "OWASP ZAP Engine"),
            "scanner": "OWASP ZAP Engine"
        }
