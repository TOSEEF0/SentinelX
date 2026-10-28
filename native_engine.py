"""
SentinelX Native Security Auditor Engine
Performs real, evidence-backed security assessments when OWASP ZAP is offline or
as a complementary security intelligence engine.
Crawls targets, audits HTTP headers, tests TLS enforcement, detects exposed credentials,
checks cookie flags, probes CORS, and discovers sensitive disclosures.
"""
import time
import uuid
import re
import urllib.parse
from typing import Dict, Any, List, Set
import requests
from bs4 import BeautifulSoup

from config import MAX_SPIDER_PAGES, MAX_REDIRECTS, REQUEST_TIMEOUT
from security_validator import SafeRedirectSession, find_exposed_credentials, redact_secrets, redact_sensitive_headers
from models import update_scan_progress, add_audit_log


class NativeAuditorEngine:
    """Production-grade native web security auditor."""

    def __init__(self, allow_local_for_test: bool = True):
        self.allow_local_for_test = allow_local_for_test
        self.session = SafeRedirectSession(
            allow_local_for_test=allow_local_for_test,
            max_redirects=MAX_REDIRECTS,
            request_timeout=REQUEST_TIMEOUT
        )

    def execute_scan(self, scan_id: str, target_url: str, profile_code: str) -> List[Dict[str, Any]]:
        """
        Executes an end-to-end audit with actual HTTP transactions and evidence gathering.
        """
        add_audit_log(scan_id, "INFO", f"Initiating SentinelX Native Security Audit on {target_url}...")
        findings: List[Dict[str, Any]] = []

        # 1. Initial Connection & Baseline Response
        update_scan_progress(scan_id, 10, "Fetching Baseline Target Response")
        add_audit_log(scan_id, "INFO", "Connecting to target endpoint and analyzing response structure...")
        
        try:
            resp = self.session.get(target_url, headers={"User-Agent": "SentinelX-Security-Auditor/2.0"})
        except Exception as e:
            add_audit_log(scan_id, "ERROR", f"Failed to connect to target URL: {str(e)}")
            raise e

        base_headers = dict(resp.headers)
        base_status = resp.status_code
        base_body = resp.text
        add_audit_log(scan_id, "INFO", f"Baseline HTTP response received (Status: {base_status}, Content-Length: {len(base_body)} bytes).")

        # 2. Security Headers Audit
        update_scan_progress(scan_id, 25, "Auditing Security Headers & HTTP Configuration")
        add_audit_log(scan_id, "INFO", "Auditing response headers against OWASP Secure Headers Project specifications...")
        header_findings = self._audit_security_headers(target_url, resp)
        findings.extend(header_findings)
        add_audit_log(scan_id, "INFO", f"Security headers check completed: {len(header_findings)} observations recorded.")

        # 3. Transport Layer & HTTPS Audit
        update_scan_progress(scan_id, 40, "Inspecting Transport Security & TLS Enforcement")
        tls_findings = self._audit_transport_security(target_url)
        findings.extend(tls_findings)

        # 4. Cookie Security Audit
        update_scan_progress(scan_id, 50, "Auditing Set-Cookie Flags and Attributes")
        cookie_findings = self._audit_cookies(target_url, resp)
        findings.extend(cookie_findings)

        # 5. Spidering & Crawling Endpoints
        update_scan_progress(scan_id, 60, "Crawling Internal Links and Assets")
        crawled_urls = self._crawl_endpoints(target_url, base_body, max_urls=MAX_SPIDER_PAGES)
        add_audit_log(scan_id, "INFO", f"Spider discovered {len(crawled_urls)} accessible internal endpoints.")

        # 6. Exposed Secrets & Credential Leakage Scan
        update_scan_progress(scan_id, 75, "Scanning HTML & JavaScript for Exposed Credentials")
        secret_findings = self._audit_exposed_credentials(target_url, base_body, crawled_urls)
        findings.extend(secret_findings)
        if secret_findings:
            add_audit_log(scan_id, "WARN", f"Identified {len(secret_findings)} potentially exposed sensitive tokens/credentials!")

        # 7. Additional Profile-Specific Checks (CORS, Dangerous Methods, Sensitive Files)
        if profile_code in ("standard", "advanced"):
            update_scan_progress(scan_id, 85, "Testing CORS Policies & Sensitive File Disclosures")
            cors_findings = self._audit_cors(target_url)
            findings.extend(cors_findings)

            method_findings = self._audit_http_methods(target_url)
            findings.extend(method_findings)

            disclosure_findings = self._probe_sensitive_disclosures(target_url)
            findings.extend(disclosure_findings)

        update_scan_progress(scan_id, 95, "Synthesizing Observations and Compiling Report")
        add_audit_log(scan_id, "INFO", f"Native audit finalized. Total evidence-backed findings: {len(findings)}.")
        return findings

    def _audit_security_headers(self, url: str, resp: requests.Response) -> List[Dict[str, Any]]:
        """Audits HTTP response headers against OWASP Secure Headers recommendations."""
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        req_headers_snippet = f"GET {url} HTTP/1.1\nHost: {urllib.parse.urlsplit(url).netloc}\n"
        resp_headers_snippet = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])

        # 1. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        is_https = url.lower().startswith("https://")
        if is_https and not hsts:
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Missing Strict-Transport-Security (HSTS) Header",
                "severity": "Medium",
                "confidence": "Certain",
                "affected_url": url,
                "evidence": "Header 'Strict-Transport-Security' is absent from response.",
                "cwe_id": "CWE-319",
                "wasc_id": "WASC-15",
                "description": "The HTTP Strict-Transport-Security (HSTS) response header instructs browsers that the site must only be accessed using HTTPS, guarding against SSL stripping attacks and man-in-the-middle downgrade attempts.",
                "impact": "Unencrypted communication can be intercepted, or users could be downgraded to plaintext HTTP via active network attackers.",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })
        elif hsts:
            # Check max-age duration
            match = re.search(r"max-age=(\d+)", hsts)
            if match and int(match.group(1)) < 15552000:  # Less than 180 days
                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": "Weak Strict-Transport-Security Max-Age Policy",
                    "severity": "Low",
                    "confidence": "High",
                    "affected_url": url,
                    "evidence": f"Strict-Transport-Security: {hsts}",
                    "cwe_id": "CWE-319",
                    "wasc_id": "WASC-15",
                    "description": "The HSTS header specifies a max-age value below the recommended minimum of 180 days (15552000 seconds).",
                    "impact": "Short HSTS policy durations reduce browser-level enforcement resilience over extended periods.",
                    "remediation": "Increase max-age to at least 31536000 seconds (1 year) and includeSubDomains.",
                    "request_snippet": req_headers_snippet,
                    "response_snippet": resp_headers_snippet,
                    "status": "Confirmed Evidence",
                    "category": "Security Headers",
                    "scanner": "SentinelX Native Auditor"
                })

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Missing Content-Security-Policy (CSP) Header",
                "severity": "Medium",
                "confidence": "Certain",
                "affected_url": url,
                "evidence": "Header 'Content-Security-Policy' is absent from response.",
                "cwe_id": "CWE-693",
                "wasc_id": "WASC-15",
                "description": "Content Security Policy (CSP) is a declarative mechanism that enables developers to restrict the sources from which scripts, styles, objects, and other resources can be loaded.",
                "impact": "Significantly heightens susceptibility to Cross-Site Scripting (XSS), clickjacking, and code injection attacks.",
                "remediation": "Define a robust Content-Security-Policy restricting script sources (e.g., default-src 'self'; script-src 'self').",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })
        elif "unsafe-inline" in csp or "*" in csp:
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Permissive Content-Security-Policy Configuration",
                "severity": "Low",
                "confidence": "High",
                "affected_url": url,
                "evidence": f"Content-Security-Policy: {csp[:120]}...",
                "cwe_id": "CWE-693",
                "wasc_id": "WASC-15",
                "description": "Content-Security-Policy includes directives containing 'unsafe-inline' or wildcard '*' sources.",
                "impact": "Weakens CSP protections against inline script execution and dynamic payload injection.",
                "remediation": "Refactor inline scripts to external scripts with cryptographic nonces or SHA-256 hashes.",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })

        # 3. X-Frame-Options (Clickjacking Protection)
        xfo = headers.get("x-frame-options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                "severity": "Medium",
                "confidence": "Certain",
                "affected_url": url,
                "evidence": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' is specified.",
                "cwe_id": "CWE-1021",
                "wasc_id": "WASC-15",
                "description": "The page does not specify framing restrictions, permitting external sites to render it inside an <iframe>.",
                "impact": "Enables UI redressing / clickjacking attacks where victims are deceived into triggering unwanted actions.",
                "remediation": "Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'none''.",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Missing X-Content-Type-Options: nosniff Header",
                "severity": "Low",
                "confidence": "Certain",
                "affected_url": url,
                "evidence": f"X-Content-Type-Options: {xcto if xcto else '[ABSENT]'}",
                "cwe_id": "CWE-16",
                "wasc_id": "WASC-15",
                "description": "Without 'X-Content-Type-Options: nosniff', older browsers may attempt MIME-type sniffing on user uploads or script files.",
                "impact": "Can allow non-executable files (like images) to be executed as HTML or JavaScript if MIME types are misconfigured.",
                "remediation": "Configure web server to emit 'X-Content-Type-Options: nosniff' on all responses.",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        if not ref_pol or ref_pol.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Missing or Insecure Referrer-Policy Header",
                "severity": "Low",
                "confidence": "High",
                "affected_url": url,
                "evidence": f"Referrer-Policy: {ref_pol if ref_pol else '[ABSENT]'}",
                "cwe_id": "CWE-200",
                "wasc_id": "WASC-13",
                "description": "Specifies how much referrer information (URL paths, query parameters) is included with requests made to third-party domains.",
                "impact": "May inadvertently leak sensitive URL parameters (tokens, identifiers, user emails) to external websites.",
                "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Security Headers",
                "scanner": "SentinelX Native Auditor"
            })

        # 6. Information Disclosure (Server / Technology Banners)
        server_hdr = headers.get("server")
        x_powered_by = headers.get("x-powered-by")
        leaked_info = []
        if server_hdr and any(c.isdigit() for c in server_hdr):
            leaked_info.append(f"Server: {server_hdr}")
        if x_powered_by:
            leaked_info.append(f"X-Powered-By: {x_powered_by}")

        if leaked_info:
            findings.append({
                "id": str(uuid.uuid4()),
                "name": "Server & Technology Banner Information Disclosure",
                "severity": "Informational",
                "confidence": "Certain",
                "affected_url": url,
                "evidence": " | ".join(leaked_info),
                "cwe_id": "CWE-200",
                "wasc_id": "WASC-13",
                "description": "The web server explicitly discloses software names and version numbers in HTTP response headers.",
                "impact": "Assists attackers in profiling target infrastructure and identifying known unpatched CVEs.",
                "remediation": "Disable server identification tokens in web server configurations (e.g. 'server_tokens off;' in Nginx).",
                "request_snippet": req_headers_snippet,
                "response_snippet": resp_headers_snippet,
                "status": "Confirmed Evidence",
                "category": "Information Disclosure",
                "scanner": "SentinelX Native Auditor"
            })

        return findings

    def _audit_transport_security(self, url: str) -> List[Dict[str, Any]]:
        """Verifies HTTPS availability and HTTP-to-HTTPS redirect enforcement."""
        findings = []
        parsed = urllib.parse.urlsplit(url)

        if parsed.scheme.lower() == "http":
            # Test if HTTPS counterpart exists and whether HTTP redirects
            https_url = f"https://{parsed.netloc}{parsed.path}"
            try:
                test_resp = self.session.get(url, allow_redirects=False, timeout=5)
                is_redirect = test_resp.status_code in (301, 302, 307, 308)
                location = test_resp.headers.get("Location", "")
                if not (is_redirect and location.lower().startswith("https://")):
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "name": "Unencrypted Plaintext HTTP Communication Permitted",
                        "severity": "High",
                        "confidence": "Certain",
                        "affected_url": url,
                        "evidence": f"Endpoint responded over plaintext HTTP with status {test_resp.status_code} without immediate 301/308 redirect to HTTPS.",
                        "cwe_id": "CWE-319",
                        "wasc_id": "WASC-04",
                        "description": "The web application allows communication over unencrypted HTTP channels without mandating TLS.",
                        "impact": "Traffic containing credentials, cookies, and sensitive data can be passively captured or modified in transit.",
                        "remediation": "Implement automatic 301 Permanent Redirect from HTTP to HTTPS across all domains.",
                        "request_snippet": f"GET {url} HTTP/1.1",
                        "response_snippet": f"HTTP/1.1 {test_resp.status_code}\nLocation: {location}",
                        "status": "Confirmed Evidence",
                        "category": "Transport Security",
                        "scanner": "SentinelX Native Auditor"
                    })
            except Exception:
                pass
        return findings

    def _audit_cookies(self, url: str, resp: requests.Response) -> List[Dict[str, Any]]:
        """Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."""
        findings = []
        set_cookie_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        if not set_cookie_headers and "set-cookie" in resp.headers:
            set_cookie_headers = [resp.headers["set-cookie"]]

        for cookie_str in set_cookie_headers:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            name_val = cookie_parts[0] if cookie_parts else "cookie"
            cookie_name = name_val.split("=")[0] if "=" in name_val else name_val
            
            flags_lower = [p.lower() for p in cookie_parts[1:]]
            has_secure = "secure" in flags_lower
            has_httponly = "httponly" in flags_lower
            has_samesite = any("samesite" in p for p in flags_lower)

            # Redact actual cookie value in evidence
            redacted_cookie_str = f"{cookie_name}=[REDACTED_COOKIE_VALUE]; " + "; ".join(cookie_parts[1:])

            # Missing Secure
            if not has_secure and url.lower().startswith("https://"):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    "severity": "Medium",
                    "confidence": "Certain",
                    "affected_url": url,
                    "evidence": redacted_cookie_str,
                    "cwe_id": "CWE-614",
                    "wasc_id": "WASC-13",
                    "description": "Cookies set over HTTPS without the 'Secure' attribute can be transmitted over unencrypted HTTP connections if the user makes a plain HTTP request.",
                    "impact": "Session fixation or session hijacking if authentication cookies leak over plaintext.",
                    "remediation": "Add '; Secure' attribute to all sensitive session and state cookies.",
                    "request_snippet": f"GET {url} HTTP/1.1",
                    "response_snippet": f"Set-Cookie: {redacted_cookie_str}",
                    "status": "Confirmed Evidence",
                    "category": "Cookie Security",
                    "scanner": "SentinelX Native Auditor"
                })

            # Missing HttpOnly
            if not has_httponly:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    "severity": "Low",
                    "confidence": "Certain",
                    "affected_url": url,
                    "evidence": redacted_cookie_str,
                    "cwe_id": "CWE-1004",
                    "wasc_id": "WASC-13",
                    "description": "Cookies without the 'HttpOnly' attribute are accessible to client-side scripts via document.cookie.",
                    "impact": "If an XSS vulnerability exists on the application, attackers can directly read and exfiltrate this cookie.",
                    "remediation": "Set '; HttpOnly' attribute on all sensitive cookies not explicitly required by frontend scripts.",
                    "request_snippet": f"GET {url} HTTP/1.1",
                    "response_snippet": f"Set-Cookie: {redacted_cookie_str}",
                    "status": "Confirmed Evidence",
                    "category": "Cookie Security",
                    "scanner": "SentinelX Native Auditor"
                })

            # Missing SameSite
            if not has_samesite:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    "severity": "Low",
                    "confidence": "High",
                    "affected_url": url,
                    "evidence": redacted_cookie_str,
                    "cwe_id": "CWE-1275",
                    "wasc_id": "WASC-09",
                    "description": "The 'SameSite' attribute governs whether cookies are sent with cross-site requests.",
                    "impact": "Without SameSite=Lax or SameSite=Strict, the application relies entirely on CSRF tokens to prevent Cross-Site Request Forgery.",
                    "remediation": "Configure '; SameSite=Lax' (or SameSite=Strict) on session cookies.",
                    "request_snippet": f"GET {url} HTTP/1.1",
                    "response_snippet": f"Set-Cookie: {redacted_cookie_str}",
                    "status": "Confirmed Evidence",
                    "category": "Cookie Security",
                    "scanner": "SentinelX Native Auditor"
                })

        return findings

    def _crawl_endpoints(self, base_url: str, html_body: str, max_urls: int = 15) -> List[str]:
        """Extracts accessible internal URLs within the same origin."""
        discovered: Set[str] = set()
        parsed_base = urllib.parse.urlsplit(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        try:
            soup = BeautifulSoup(html_body, "html.parser")
            # Extract links and script src tags
            tags = soup.find_all(["a", "script", "link"], href=True) + soup.find_all("script", src=True)
            for tag in tags:
                attr = "href" if tag.has_attr("href") else "src"
                raw_link = tag[attr]
                if not raw_link or raw_link.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full_url = urllib.parse.urljoin(base_url, raw_link)
                parsed_target = urllib.parse.urlsplit(full_url)
                
                # Check origin match
                if parsed_target.netloc == parsed_base.netloc:
                    cleaned_url = urllib.parse.urlunsplit((parsed_target.scheme, parsed_target.netloc, parsed_target.path, "", ""))
                    if cleaned_url != base_url:
                        discovered.add(cleaned_url)
                if len(discovered) >= max_urls:
                    break
        except Exception:
            pass

        return list(discovered)

    def _audit_exposed_credentials(self, base_url: str, base_body: str, crawled_urls: List[str]) -> List[Dict[str, Any]]:
        """Scans page content and crawled assets for exposed API keys and credentials."""
        findings = []
        pages_to_check = [(base_url, base_body)]

        # Fetch up to 5 additional internal script/HTML assets
        for url in crawled_urls[:5]:
            try:
                res = self.session.get(url, timeout=4)
                if res.status_code == 200:
                    pages_to_check.append((url, res.text))
            except Exception:
                continue

        seen_signatures = set()
        for url, content in pages_to_check:
            detected = find_exposed_credentials(content, url)
            for d in detected:
                sig = f"{d['type']}:{d['redacted_token']}"
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": f"Exposed Sensitive Credential: {d['type']}",
                    "severity": "High",
                    "confidence": "Certain",
                    "affected_url": url,
                    "evidence": f"Context: \"...{d['evidence_context']}...\"",
                    "cwe_id": "CWE-798",
                    "wasc_id": "WASC-14",
                    "description": f"Potential high-entropy secret token ({d['type']}) was discovered publicly exposed in client-accessible HTML or JavaScript.",
                    "impact": "Exposed keys can allow unauthorized attackers to access cloud infrastructure, external APIs, or sensitive services directly.",
                    "remediation": "Revoke the exposed key immediately in the respective vendor console. Move secrets to backend environment variables.",
                    "request_snippet": f"GET {url} HTTP/1.1",
                    "response_snippet": f"Matched pattern in response body:\n{d['evidence_context']}",
                    "status": "Confirmed Evidence",
                    "category": "Credential Exposure",
                    "scanner": "SentinelX Native Auditor"
                })

        return findings

    def _audit_cors(self, url: str) -> List[Dict[str, Any]]:
        """Tests Cross-Origin Resource Sharing (CORS) policy for dangerous reflections."""
        findings = []
        test_origin = "https://sentinelx-evil-test.com"
        try:
            cors_resp = self.session.get(url, headers={"Origin": test_origin}, timeout=4)
            acao = cors_resp.headers.get("access-control-allow-origin")
            acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == "*":
                if acac == "true":
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "name": "Critical CORS Misconfiguration: Wildcard with Credentials",
                        "severity": "High",
                        "confidence": "Certain",
                        "affected_url": url,
                        "evidence": "Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                        "cwe_id": "CWE-942",
                        "wasc_id": "WASC-14",
                        "description": "The server returns a wildcard Access-Control-Allow-Origin while also permitting credentials.",
                        "impact": "Allows malicious websites to issue authenticated cross-origin requests and read private user data.",
                        "remediation": "Do not combine wildcard origin with Allow-Credentials. Whitelist explicit trusted origins.",
                        "request_snippet": f"GET {url} HTTP/1.1\nOrigin: {test_origin}",
                        "response_snippet": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        "status": "Confirmed Evidence",
                        "category": "Access Control",
                        "scanner": "SentinelX Native Auditor"
                    })
            elif acao == test_origin:
                severity = "Medium" if acac == "true" else "Low"
                findings.append({
                    "id": str(uuid.uuid4()),
                    "name": "Permissive CORS Origin Reflection",
                    "severity": severity,
                    "confidence": "High",
                    "affected_url": url,
                    "evidence": f"Request Origin '{test_origin}' was dynamically reflected in Access-Control-Allow-Origin.",
                    "cwe_id": "CWE-942",
                    "wasc_id": "WASC-14",
                    "description": "The backend dynamically reflects arbitrary Origin headers in the CORS response instead of enforcing an explicit whitelist.",
                    "impact": "Cross-origin websites can interact with restricted endpoints if credentials or session cookies are respected.",
                    "remediation": "Validate the incoming Origin header against a strict, static server-side whitelist.",
                    "request_snippet": f"GET {url} HTTP/1.1\nOrigin: {test_origin}",
                    "response_snippet": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    "status": "Confirmed Evidence",
                    "category": "Access Control",
                    "scanner": "SentinelX Native Auditor"
                })
        except Exception:
            pass
        return findings

    def _audit_http_methods(self, url: str) -> List[Dict[str, Any]]:
        """Probes endpoint for dangerous or unnecessary HTTP methods."""
        findings = []
        try:
            opt_resp = self.session.options(url, timeout=4)
            allow_header = opt_resp.headers.get("allow", "")
            if allow_header:
                dangerous = [m for m in ["TRACE", "DELETE", "PUT"] if m in allow_header.upper()]
                if "TRACE" in dangerous:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "name": "HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                        "severity": "Medium",
                        "confidence": "Certain",
                        "affected_url": url,
                        "evidence": f"Allow: {allow_header}",
                        "cwe_id": "CWE-16",
                        "wasc_id": "WASC-15",
                        "description": "The HTTP TRACE method echoes back the received request in the response body.",
                        "impact": "Enables Cross-Site Tracing (XST) attacks where an attacker can steal HttpOnly cookies via script-generated TRACE requests.",
                        "remediation": "Disable the TRACE method in the web server configuration (e.g. 'TraceEnable off' in Apache).",
                        "request_snippet": f"OPTIONS {url} HTTP/1.1",
                        "response_snippet": f"HTTP/1.1 {opt_resp.status_code}\nAllow: {allow_header}",
                        "status": "Confirmed Evidence",
                        "category": "Configuration Security",
                        "scanner": "SentinelX Native Auditor"
                    })
        except Exception:
            pass
        return findings

    def _probe_sensitive_disclosures(self, base_url: str) -> List[Dict[str, Any]]:
        """Safely probes for publicly accessible configuration and repository files."""
        findings = []
        parsed = urllib.parse.urlsplit(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"

        test_paths = [
            ("/.env", "Environment Variables File", ["DB_PASSWORD", "SECRET_KEY", "AWS_", "API_KEY", "="], "High", "CWE-552"),
            ("/.git/HEAD", "Exposed Git Repository Metadata", ["ref: refs/heads", "ref: refs/tags"], "High", "CWE-538"),
            ("/robots.txt", "Robots.txt Information Disclosure", ["Disallow:", "User-agent:"], "Informational", "CWE-200"),
            ("/.well-known/security.txt", "Security.txt Contact Notice", ["Contact:", "Expires:"], "Informational", "CWE-200"),
        ]

        for path, name, signatures, severity, cwe in test_paths:
            probe_url = f"{root_url}{path}"
            try:
                probe_resp = self.session.get(probe_url, timeout=3, allow_redirects=False)
                if probe_resp.status_code == 200:
                    text_sample = probe_resp.text[:500]
                    # Verify signature matches to prevent false positives from custom 404 pages
                    if any(sig in text_sample for sig in signatures):
                        redacted_evidence = redact_secrets(text_sample[:180])
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "name": f"Publicly Accessible {name}",
                            "severity": severity,
                            "confidence": "Certain",
                            "affected_url": probe_url,
                            "evidence": f"HTTP 200 OK. Body snippet:\n{redacted_evidence}",
                            "cwe_id": cwe,
                            "wasc_id": "WASC-13",
                            "description": f"The file '{path}' is publicly served and readable without authentication.",
                            "impact": "Exposes internal paths, system architecture, or confidential environment credentials.",
                            "remediation": f"Block public access to '{path}' in server routing rules immediately.",
                            "request_snippet": f"GET {probe_url} HTTP/1.1",
                            "response_snippet": f"HTTP/1.1 200 OK\n\n{redacted_evidence}",
                            "status": "Confirmed Evidence",
                            "category": "Information Disclosure",
                            "scanner": "SentinelX Native Auditor"
                        })
            except Exception:
                continue

        return findings
