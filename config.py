"""
SentinelX Configuration Module
Defines runtime configurations, security boundaries, and scanner parameters.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = BASE_DIR / "sentinelx.db"

# Load environment variables from .env file
load_dotenv(BASE_DIR / ".env")

# Server Configuration
SECRET_KEY = os.getenv("SENTINELX_SECRET_KEY", "sentinelx_audit_secret_key_change_in_prod_9918")
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# ZAP Engine Configuration
# Official OWASP ZAP default daemon port is 8080 or 8090
ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "sentinelx_zap_internal_api_key_8821")
ZAP_TIMEOUT = int(os.getenv("ZAP_TIMEOUT", "300"))  # 5 minutes scan max
ZAP_POLL_INTERVAL = float(os.getenv("ZAP_POLL_INTERVAL", "1.5"))

# Scanner Safety & Resource Limits
MAX_SPIDER_PAGES = int(os.getenv("MAX_SPIDER_PAGES", "20"))
MAX_SPIDER_DEPTH = int(os.getenv("MAX_SPIDER_DEPTH", "2"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "8"))  # seconds
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))

# SSRF Protection & Network Whitelist/Blacklist
# Set to True only during automated testing of local intentionally vulnerable applications
ALLOW_LOCAL_TESTING = os.getenv("ALLOW_LOCAL_TESTING", "True").lower() in ("true", "1", "yes")
ALLOWED_TEST_PORTS = [5000, 5050, 8000, 8080, 8888]

# AI Advisory Configuration
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemma").lower()  # 'gemma', 'gemini', 'openai', 'deterministic'
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gemma-4-26b-a4b-it")

# Scan Profiles
SCAN_PROFILES = {
    "quick": {
        "name": "Quick Audit",
        "code": "quick",
        "description": "Passive crawling, security headers, TLS audit, cookie flags, and credential leakage checks. Zero aggressive payload injection.",
        "aggressive": False,
        "max_pages": 15,
        "enable_active_scan": False,
    },
    "standard": {
        "name": "Standard Audit",
        "code": "standard",
        "description": "Crawling, passive analysis, CORS evaluation, HTTP verb probing, and sensitive file disclosure checks.",
        "aggressive": False,
        "max_pages": 25,
        "enable_active_scan": False,
    },
    "advanced": {
        "name": "Advanced Audit",
        "code": "advanced",
        "description": "Full active vulnerability testing including parameterized injection, path traversal, and security policy verification. Requires explicit authorization.",
        "aggressive": True,
        "max_pages": 35,
        "enable_active_scan": True,
    }
}
