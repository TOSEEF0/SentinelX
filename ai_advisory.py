"""
SentinelX AI-Assisted Security Advisory & Expert Remediation Engine
Provides in-depth risk analysis, threat modeling explanations, and actionable
code-level remediation snippets (Nginx, Apache, Express, Flask).
Enforces zero transmission of credentials, cookies, or authorization tokens to external providers.
Seamlessly falls back to deterministic expert knowledge base when AI is offline.
"""
import os
import re
import json
from typing import Dict, Any, Optional

from config import AI_PROVIDER, AI_API_KEY, AI_MODEL
from security_validator import redact_secrets

# High-quality deterministic remediation knowledge base
DETERMINISTIC_KNOWLEDGE_BASE = {
    "CWE-319": {
        "title": "Cleartext Transmission of Sensitive Information",
        "threat_vector": "Network eavesdropping, SSL stripping, and MitM packet interception.",
        "explanation": "When communications occur over unencrypted HTTP, or when HSTS is absent, attackers positioned on local networks (such as public Wi-Fi or compromised routers) can inspect and alter packet payloads in flight.",
        "remediation_steps": [
            "1. Procure and install a valid TLS/SSL certificate.",
            "2. Mandate HTTP-to-HTTPS permanent redirects (HTTP 301/308).",
            "3. Enforce HTTP Strict Transport Security (HSTS) with a minimum duration of 1 year.",
        ],
        "code_snippets": {
            "Nginx": (
                "# In /etc/nginx/sites-available/default\n"
                "server {\n"
                "    listen 80;\n"
                "    server_name example.com www.example.com;\n"
                "    return 301 https://$host$request_uri;\n"
                "}\n"
                "server {\n"
                "    listen 443 ssl http2;\n"
                "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                "}"
            ),
            "Apache": (
                "# In .htaccess or virtual host\n"
                "RewriteEngine On\n"
                "RewriteCond %{HTTPS} off\n"
                "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
            ),
            "Express.js": (
                "const helmet = require('helmet');\n"
                "app.use(helmet.hsts({\n"
                "  maxAge: 31536000,\n"
                "  includeSubDomains: true,\n"
                "  preload: true\n"
                "}));"
            )
        }
    },
    "CWE-693": {
        "title": "Protection Mechanism Failure / Missing CSP",
        "threat_vector": "Cross-Site Scripting (XSS), malicious script injection, and dynamic asset hijacking.",
        "explanation": "Content Security Policy (CSP) acts as an essential defense-in-depth barrier. Without CSP, any injected script executes with the full privileges of the user's session.",
        "remediation_steps": [
            "1. Restrict script loading exclusively to trusted, first-party origins ('self').",
            "2. Prohibit inline script execution ('unsafe-inline') and eval() calls ('unsafe-eval').",
            "3. Use cryptographic nonces (nonce-...) or SHA-256 hashes for authorized inline elements.",
            "4. Configure frame-ancestors to prevent unauthorized iframe embedding.",
        ],
        "code_snippets": {
            "Nginx": (
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; object-src 'none';\" always;"
            ),
            "Express.js": (
                "const helmet = require('helmet');\n"
                "app.use(helmet.contentSecurityPolicy({\n"
                "  directives: {\n"
                "    defaultSrc: [\"'self'\"],\n"
                "    scriptSrc: [\"'self'\"],\n"
                "    objectSrc: [\"'none'\"],\n"
                "    upgradeInsecureRequests: [],\n"
                "  },\n"
                "}));"
            ),
            "Flask": (
                "@app.after_request\n"
                "def add_security_headers(response):\n"
                "    response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'; object-src 'none';\"\n"
                "    return response"
            )
        }
    },
    "CWE-1021": {
        "title": "Improper Restriction of Rendered UI Layers (Clickjacking)",
        "threat_vector": "UI redressing, invisible iframe overlays, and unauthorized state manipulation.",
        "explanation": "An adversary embeds your application inside an invisible <iframe> on an attacker-controlled page, tricking an authenticated user into clicking sensitive action buttons (e.g., 'Delete Account', 'Transfer Funds').",
        "remediation_steps": [
            "1. Deliver 'X-Frame-Options: DENY' for pages that should never be embedded.",
            "2. Deliver 'X-Frame-Options: SAMEORIGIN' if framing within the same domain is required.",
            "3. Supplement with CSP 'frame-ancestors 'none'' (or 'self') for modern browser enforcement.",
        ],
        "code_snippets": {
            "Nginx": "add_header X-Frame-Options \"DENY\" always;",
            "Apache": "Header always set X-Frame-Options \"DENY\"",
            "Express.js": "const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
            "Flask": (
                "@app.after_request\n"
                "def set_clickjacking_protection(response):\n"
                "    response.headers['X-Frame-Options'] = 'DENY'\n"
                "    return response"
            )
        }
    },
    "CWE-16": {
        "title": "Configuration / MIME-Type Sniffing Deficiencies",
        "threat_vector": "MIME confusion attacks, arbitrary script execution via masqueraded media files.",
        "explanation": "Browsers may attempt to detect the MIME type of a response by sniffing its content rather than respecting the Content-Type header. If a user-uploaded image contains HTML/JS, it could execute as script in older user agents.",
        "remediation_steps": [
            "1. Emit 'X-Content-Type-Options: nosniff' header across all HTTP responses.",
            "2. Ensure all file serving endpoints output precise, accurate Content-Type headers.",
        ],
        "code_snippets": {
            "Nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "Apache": "Header always set X-Content-Type-Options \"nosniff\"",
            "Express.js": "const helmet = require('helmet');\napp.use(helmet.noSniff());"
        }
    },
    "CWE-798": {
        "title": "Use of Hard-coded Credentials / Exposed Secrets",
        "threat_vector": "Cloud account takeover, database infiltration, and API impersonation.",
        "explanation": "High-entropy secrets (AWS keys, GitHub tokens, JWTs, private keys) embedded in source code, HTML, or JavaScript bundles can be scraped by automated bots and unauthorized visitors.",
        "remediation_steps": [
            "1. Rotate and invalidate the exposed secret immediately in the cloud provider console.",
            "2. Audit access logs for unauthorized activity during the exposure window.",
            "3. Shift secret storage to secure environment variables, AWS Secrets Manager, or HashiCorp Vault.",
            "4. Employ pre-commit git hooks (e.g., git-secrets, trufflehog) to block hardcoded credentials.",
        ],
        "code_snippets": {
            "Node.js": (
                "# In .env (added to .gitignore)\n"
                "API_KEY=your_secure_value_here\n\n"
                "# In code\n"
                "require('dotenv').config();\n"
                "const apiKey = process.env.API_KEY;"
            ),
            "Python": (
                "# In .env\n"
                "API_KEY=your_secure_value_here\n\n"
                "# In code\n"
                "import os\n"
                "from dotenv import load_dotenv\n"
                "load_dotenv()\n"
                "api_key = os.getenv('API_KEY')"
            )
        }
    },
    "CWE-942": {
        "title": "Permissive Cross-Origin Resource Sharing (CORS) Policy",
        "threat_vector": "Unauthorized cross-origin data extraction and authenticated API exploitation.",
        "explanation": "A wildcard Access-Control-Allow-Origin or dynamic reflection of the Origin header allows untrusted external websites to read private responses on behalf of an authenticated victim.",
        "remediation_steps": [
            "1. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
            "2. Maintain an explicit whitelist of authorized partner domains.",
            "3. Reject any Origin header not present on the whitelist.",
        ],
        "code_snippets": {
            "Express.js": (
                "const cors = require('cors');\n"
                "const allowedOrigins = ['https://trusted.example.com'];\n"
                "app.use(cors({\n"
                "  origin: (origin, callback) => {\n"
                "    if (!origin || allowedOrigins.includes(origin)) callback(null, true);\n"
                "    else callback(new Error('Blocked by CORS policy'));\n"
                "  },\n"
                "  credentials: true\n"
                "}));"
            ),
            "Python Flask": (
                "from flask_cors import CORS\n"
                "CORS(app, origins=['https://trusted.example.com'], supports_credentials=True)"
            )
        }
    }
}


def sanitize_finding_for_advisory(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes finding before passing to advisory module or external AI.
    Strictly removes credentials, session tokens, and sensitive headers.
    """
    return {
        "name": finding.get("name", "Security Observation"),
        "severity": finding.get("severity", "Informational"),
        "cwe_id": finding.get("cwe_id", ""),
        "evidence": redact_secrets(finding.get("evidence", "")[:300]),
        "description": finding.get("description", ""),
        "category": finding.get("category", "General")
    }


def get_ai_advisory(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates intelligent remediation guidance for a specific security finding.
    Uses configured external AI provider if enabled and credentials exist;
    otherwise delivers deterministic expert remediation rules.
    """
    cwe_id = finding.get("cwe_id", "")
    sanitized = sanitize_finding_for_advisory(finding)

    # 1. Google Gemma / Gemini API Provider
    if AI_PROVIDER.lower() in ("gemma", "gemini", "google") and AI_API_KEY:
        try:
            import requests
            model_name = AI_MODEL or "gemma-4-26b-a4b-it"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={AI_API_KEY}"
            prompt = (
                f"You are a cybersecurity engineer reviewing a SentinelX finding.\n"
                f"Finding: {sanitized['name']}\n"
                f"Severity: {sanitized['severity']}\n"
                f"CWE: {sanitized['cwe_id']}\n"
                f"Description: {sanitized['description']}\n\n"
                f"Provide concise remediation in this exact JSON format:\n"
                f"{{\n"
                f'  "threat_vector": "1 sentence describing attack vector",\n'
                f'  "technical_impact": "1 sentence describing impact",\n'
                f'  "remediation_steps": ["Action 1", "Action 2", "Action 3"],\n'
                f'  "configuration_fixes": {{"Nginx": "1-2 line config fix", "Apache": "1-2 line config fix"}}\n'
                f"}}\n"
                f"Respond with valid JSON only."
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048}
            }
            resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=45)
            if resp.status_code == 200:
                data = resp.json()
                candidate = data["candidates"][0]
                parts = candidate["content"]["parts"]
                text_parts = [p["text"] for p in parts if not p.get("thought")]
                raw_text = "\n".join(text_parts) if text_parts else parts[-1]["text"]
                clean_json = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text.strip(), flags=re.MULTILINE).strip()
                match = re.search(r"(\{.*\})", clean_json, re.DOTALL)
                if match:
                    clean_json = match.group(1)
                content = json.loads(clean_json)
                return {
                    "source": f"Gemma 4 AI Advisory ({model_name})",
                    "is_ai_connected": True,
                    "threat_vector": content.get("threat_vector", "Potential unauthorized access or misconfiguration."),
                    "technical_impact": content.get("technical_impact", sanitized["description"]),
                    "remediation_steps": content.get("remediation_steps", ["Review server configuration and apply recommended defense-in-depth controls."]),
                    "code_snippets": content.get("configuration_fixes", {})
                }
        except Exception:
            # Fall back to deterministic rules if connection or parse fails
            pass

    # 2. OpenAI Provider
    elif AI_PROVIDER.lower() == "openai" and AI_API_KEY:
        try:
            import openai
            client = openai.OpenAI(api_key=AI_API_KEY)
            prompt = (
                f"You are a principal cybersecurity engineer reviewing a vulnerability finding from SentinelX.\n"
                f"Finding: {sanitized['name']}\n"
                f"Severity: {sanitized['severity']}\n"
                f"CWE: {sanitized['cwe_id']}\n"
                f"Evidence: {sanitized['evidence']}\n"
                f"Description: {sanitized['description']}\n\n"
                f"Provide a structured JSON response with:\n"
                f"- threat_vector: concise summary of attacker vectors\n"
                f"- technical_impact: impact of successful exploitation\n"
                f"- remediation_steps: array of actionable steps\n"
                f"- configuration_fixes: dictionary of snippets for Nginx/Apache/Express\n"
            )
            response = client.chat.completions.create(
                model=AI_MODEL or "gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=650,
                temperature=0.2
            )
            content = json.loads(response.choices[0].message.content)
            return {
                "source": "AI-Assisted Security Engine (OpenAI)",
                "is_ai_connected": True,
                "threat_vector": content.get("threat_vector", "Potential unauthorized access or misconfiguration."),
                "technical_impact": content.get("technical_impact", sanitized["description"]),
                "remediation_steps": content.get("remediation_steps", ["Review server configuration and apply recommended defense-in-depth controls."]),
                "code_snippets": content.get("configuration_fixes", {})
            }
        except Exception as e:
            # Graceful fallback to deterministic engine
            pass

    # 2. Deterministic Expert Knowledge Base (Default)
    base_info = DETERMINISTIC_KNOWLEDGE_BASE.get(cwe_id)
    if not base_info:
        # Generic deterministic guidance
        return {
            "source": "Deterministic Security Rule Base",
            "is_ai_connected": False,
            "threat_vector": "Security configuration discrepancy or information disclosure.",
            "technical_impact": finding.get("impact") or "Increases attack surface or facilitates reconnaissance.",
            "remediation_steps": [
                "1. Audit the endpoint against OWASP Security Verification Standards (ASVS).",
                "2. Remove unnecessary HTTP response headers disclosing server versions.",
                "3. Ensure all sensitive operations enforce strict authentication and input validation."
            ],
            "code_snippets": {
                "General Recommendation": (
                    "# Enforce least-privilege principles and verify all response headers\n"
                    "# against the OWASP Secure Headers Project guidelines."
                )
            }
        }

    return {
        "source": "Deterministic Security Rule Base",
        "is_ai_connected": False,
        "threat_vector": base_info["threat_vector"],
        "technical_impact": base_info["explanation"],
        "remediation_steps": base_info["remediation_steps"],
        "code_snippets": base_info["code_snippets"]
    }
