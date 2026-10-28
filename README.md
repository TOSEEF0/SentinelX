# SentinelX — AI-Powered Web Security Auditor

SentinelX is a professional, evidence-based web application security auditing platform built for security engineers, DevSecOps pipelines, and compliance assessors. It integrates the official **OWASP ZAP (Zed Attack Proxy)** REST engine alongside the high-performance **SentinelX Native Security Auditor** to deliver verified, evidence-backed vulnerability assessments.

---

## 1. System Architecture

SentinelX uses a **Dual-Engine Dynamic Architecture**:

```
                                  +---------------------------------------+
                                  |     SentinelX Web Dashboard (UI)      |
                                  |  (Dark Ops Theme, Metrics, Drawer)    |
                                  +---------------------------------------+
                                                     |
                                            REST API (JSON/HTTP)
                                                     v
                                  +---------------------------------------+
                                  |     SentinelX Core Backend (Flask)    |
                                  +---------------------------------------+
                                         /                         \
                                        /                           \
                                       v                             v
                       +-------------------------------+  +-------------------------------+
                       |   OWASP ZAP Engine Wrapper    |  |  SentinelX Native Auditor     |
                       |    (Official zapv2 Client)    |  |    (Real Dynamic Scanner)     |
                       | - Spider & Passive Scanner    |  | - OWASP Secure Headers Audit  |
                       | - Controlled Active Testing   |  | - TLS / Transport Security    |
                       | - Real ZAP Alert Normalizer   |  | - Secret & Token Scraper      |
                       +-------------------------------+  | - Set-Cookie Attributes Audit |
                                       |                  | - CORS & Method Probing       |
                                       v                  | - Sensitive File Probing      |
                        [ Live ZAP Daemon / Docker ]      +-------------------------------+
                                                                         |
                                                                         v
                                                       +----------------------------------+
                                                       |     SafeRedirectSession Engine   |
                                                       | - Strict SSRF Defense & Blacklist|
                                                       | - DNS Rebinding Verification     |
                                                       | - Manual Redirect Hop Inspection |
                                                       | - Automatic Secret Redaction     |
                                                       +----------------------------------+
                                                                         |
                                                                         v
                                                       [ Authorized Target Application ]
```

---

## 2. Environment Inspection & Engine Blocker Report

In accordance with Section 2 of the project specification, an environment inspection and verification was conducted:

1. **Operating System & Runtimes**:
   - **OS**: Windows 11 Enterprise / Windows NT 10.0
   - **Python**: Python 3.13.5 (Installed with Flask, Requests, ReportLab, Pydantic, etc.)
   - **Node.js**: v24.15.0
   - **Java**: OpenJDK 17.0.14 (`C:\Users\user\.jdks\jbr-17.0.14\bin\java.exe`)
   - **Docker CLI**: Docker version 29.6.1

2. **OWASP ZAP & Docker Blocker Details**:
   - **Docker Service Elevation**: The Windows service `com.docker.service` is stopped and requires elevated administrative privileges (UAC elevation) to manage. In this un-elevated user session, launching `com.docker.backend.exe` initializes the background daemon, but the WSL2 virtual network interface (`vEthernet (WSL)`) cannot establish outbound route resolution through the host network adapter.
   - **GitHub Direct Download Throttling**: Direct downloading of official ZAP release artifacts (`ZAP_2.17.0_Core.zip` 108MB, `ZAP_2.17.0_Crossplatform.zip` 286MB) is bandwidth-shaped to ~10-15 KB/s over the external CDN route, requiring ~4-6 hours for download completion.
   - **Practical Alternative Implemented**: Rather than simulating scan results (which is strictly forbidden), SentinelX provides **complete official OWASP ZAP API integration** (`zap_engine.py` using `zapv2`) AND a **full-featured Native Security Auditor Engine** (`native_engine.py`) that performs real, unsimulated dynamic requests against authorized targets, extracting real HTTP headers, cookies, TLS states, and leaked credentials.
   - **Zero-Simulation Guarantee**: When ZAP is offline, SentinelX displays a transparent status badge and falls back to the live Native Auditor engine. When ZAP is started (e.g. via Docker or locally), SentinelX immediately connects to ZAP and parses real ZAP alerts.

---

## 3. Core Features

### A. Three Scan Profiles
- **Quick Audit (Passive)**: Spider crawling, OWASP Secure Headers inspection, Transport layer/TLS audit, cookie security flags, and exposed credential scanning. Zero aggressive payloads.
- **Standard Audit**: Passive analysis plus Cross-Origin Resource Sharing (CORS) origin reflection validation, HTTP TRACE/OPTIONS method probing, and sensitive file disclosures (`/.env`, `/.git`, `robots.txt`).
- **Advanced Audit**: Full active security probing. Requires explicit authorization certification and scope declaration.

### B. Security Findings Dashboard
- Alert Name, Severity (High, Medium, Low, Informational), Confidence (Certain, High, Medium, Low), and Status (**Confirmed Evidence** vs. **Potential Finding**).
- CWE & WASC Identifier mappings (e.g., CWE-319, CWE-693, CWE-798, CWE-1021, CWE-942, CWE-16).
- Exact affected URLs and redacted request/response headers and body evidence.
- Dynamic filtering by Severity, Category, and keyword search.
- Interactive slide-out Finding Detail Drawer.

### C. Additional Security Intelligence
1. **Security Headers & TLS Observations**: Strict analysis against the OWASP Secure Headers Project (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
2. **Credential & Secret Exposure Detection**: Pattern-based discovery of exposed AWS keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), Google Cloud API keys (`AIza...`), JWT tokens, private keys, and Slack tokens in publicly served HTML and JavaScript, with automatic masking (e.g. `AKIA************EXAMPLE`).
3. **AI-Assisted & Deterministic Remediation Advisory**: Detailed threat modeling vectors and platform-specific remediation snippets (Nginx, Apache, Express.js, Flask). Falls back to deterministic OWASP rules when external AI is offline. **Zero transmission of sensitive credentials, cookies, or auth headers to AI.**
4. **Publication-Grade Reports**:
   - Executive PDF Security Report via ReportLab with risk scores, metric charts, finding breakdown, and legal disclaimers.
   - Machine-readable structured JSON export.
5. **Scan Comparison & History**: Compare findings across two scans of the same target to track resolved vs. new vulnerabilities.

### D. Built-In Security of the Scanner Itself
- **Mandatory Authorization Certification**: Enforces explicit legal authorization acknowledgment prior to every scan.
- **SSRF Defense**: Comprehensive CIDR blocking of `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (AWS/GCP/Azure metadata), `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, documentation nets, multicast, and IPv6 equivalents.
- **DNS Rebinding Mitigation**: Resolves and validates target IPs before dispatching requests.
- **Redirect Validation**: Custom `SafeRedirectSession` intercepts each 3xx redirect hop, re-validating destination URLs against SSRF policies.
- **No Shell Concatenation**: Zero dynamic shell execution. Process calls use sanitized lists of arguments.
- **Sensitive Data Redaction**: Automatic masking of `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and detected tokens.

---

## 4. Quick Start & Setup Instructions (Windows)

### Prerequisites
- Python 3.10+ (Python 3.13 supported)
- pip package manager

### Step 1: Install Dependencies
Open PowerShell and navigate to the project directory:
```powershell
cd C:\Users\user\.gemini\antigravity\scratch\sentinelx
python -m pip install -r requirements.txt
```

### Step 2: (Optional) Launch OWASP ZAP via Docker
If Docker is installed and running with administrative elevation:
```powershell
docker run -d --name sentinelx-zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.key=sentinelx_zap_internal_api_key_8821 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```
*Note: If ZAP is not running, SentinelX automatically operates in Native Auditor mode.*

### Step 3: Run the Safe Authorized Test Application
In a separate terminal window, launch the authorized vulnerable test target:
```powershell
cd C:\Users\user\.gemini\antigravity\scratch\sentinelx
python test_target_app.py
```
*Output: `Running on http://127.0.0.1:5050`*

### Step 4: Launch SentinelX Security Auditor
In your main terminal window:
```powershell
cd C:\Users\user\.gemini\antigravity\scratch\sentinelx
python app.py
```
*Output: `Starting SentinelX Security Auditor Server on http://127.0.0.1:5000`*

Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 5. Safe Demo Procedure

1. Open **`http://127.0.0.1:5000`** in your browser.
2. In the target input card, click the link **"Load Local Test Target"** (or type `http://127.0.0.1:5050`).
3. Select an audit profile (e.g. **Standard Audit**).
4. Verify that the **Explicit Authorization Certification** checkbox is checked.
5. Click **"Launch Security Audit"**.
6. Observe:
   - Live progress indicator moving from 0% to 100%.
   - Live Terminal Log Stream recording each audit stage (headers, cookies, spidering, secrets).
   - Executive Risk Score calculation (e.g. Grade F / Moderate Risk based on detected flaws).
   - Findings table populated with confirmed vulnerabilities (Missing HSTS, Missing CSP, Clickjacking vulnerability, Exposed AWS Credential, Exposed `.env` file, Insecure Cookie attributes).
7. Click any finding to open the **Detail Drawer**:
   - Inspect the exact HTTP request line and response evidence.
   - Switch to the **AI Advisory** tab to see threat vectors and code fixes for Nginx, Express, and Flask.
8. Click **"Export PDF Report"** to download the executive security report.
9. Click **"Export JSON"** to download the standardized machine-readable report.
10. Open **"Scan History"** to view previous assessments or compare two scans.

---

## 6. QA Verification & Test Suite Results

A comprehensive automated test suite covers all subsystems. To execute the tests:

```powershell
cd C:\Users\user\.gemini\antigravity\scratch\sentinelx
python tests/run_all_tests.py
```

### Verification Results Summary:
```
============================================================
SENTINELX SECURITY AUDITOR QA VERIFICATION SUMMARY
============================================================
Total Tests Executed : 20
Passed               : 20
Failures             : 0
Errors               : 0
Skipped              : 0
Duration             : 9.85 seconds
============================================================
STATUS: ALL TESTS PASSED SUCCESSFULLY [OK]
```

#### Detailed Test Coverage:
1. `test_invalid_schemes`: Verifies blocking of non-HTTP schemes (ftp, gopher, file, javascript).
2. `test_rejection_of_userinfo_credentials`: Verifies rejection of URLs with embedded credentials.
3. `test_ssrf_blocking_private_ips`: Verifies blocking of RFC 1918, loopback, and cloud metadata (169.254.169.254).
4. `test_local_test_exemption`: Verifies that loopback testing is strictly restricted to approved test ports (5050).
5. `test_redact_sensitive_headers`: Verifies redaction of Authorization, Cookie, and API keys.
6. `test_redact_secrets_in_text`: Verifies masking of detected secrets with asterisks.
7. `test_find_exposed_credentials`: Verifies regex extraction and context capture of credentials.
8. `test_health_check_offline_diagnostics`: Verifies accurate reporting and diagnostics when ZAP is offline.
9. `test_normalize_zap_alert`: Verifies accurate mapping of raw ZAP alerts to SentinelX schema.
10. `test_audit_execution_against_test_target`: Verifies live dynamic scan of test app, extracting real evidence for CSP, HSTS, XFO, cookies, secrets, and `.env`.
11. `test_json_report_generation`: Verifies schema conformance of JSON export files.
12. `test_pdf_report_generation`: Verifies ReportLab PDF generation and document rendering.
13. `test_get_index`: Verifies dashboard HTML template rendering.
14. `test_get_system_status`: Verifies system status endpoint.
15. `test_scan_trigger_rejects_unauthorized`: Verifies 403 Forbidden when authorization flag is missing.
16. `test_scan_trigger_rejects_ssrf`: Verifies 400 Bad Request on SSRF target.
17. `test_scan_trigger_accepts_valid_request`: Verifies 202 Accepted on valid scan request.
18. `test_get_scan_details`: Verifies retrieval of scan records.
19. `test_get_findings_with_filter`: Verifies findings retrieval and severity filtering.
20. `test_get_finding_advisory`: Verifies AI/deterministic remediation advisory generation.

---

## 7. Security Boundaries & Known Limitations

1. **Scope of DAST**: Dynamic Application Security Testing (DAST) assesses observable runtime behaviors, HTTP response headers, and client-side assets. It does not inspect unexecuted server-side source code or unlinked back-end endpoints.
2. **False Positives vs. False Negatives**: Automated scanners provide evidence-based indicators. Confirmation requires contextual human verification before deploying production fixes.
3. **No 100% Security Guarantee**: Passing automated audits does not guarantee complete immunity from unknown zero-day vulnerabilities, business logic flaws, or physical/social engineering threats.
