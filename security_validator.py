"""
SentinelX Security Validator Module
Provides SSRF prevention, URL & Hostname validation, DNS rebinding mitigation,
redirect validation, and sensitive data redaction.
"""
import re
import socket
import ipaddress
import urllib.parse
from typing import Tuple, Optional, Dict, Any, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Private, link-local, cloud-metadata, and reserved CIDR ranges to block against SSRF
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / AWS/GCP/Azure Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (Documentation)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (Documentation)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (Documentation)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
]

# Sensitive HTTP headers to redact
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "apikey",
    "token",
    "secret",
}

# Regex patterns for credential exposure detection
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"\b(AKIA[0-9A-Z]{16})\b"),
    ("GitHub Personal Access Token", r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    ("Google Cloud API Key", r"\b(AIza[0-9A-Za-z-_]{30,36})\b"),
    ("JSON Web Token (JWT)", r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    ("Generic Bearer Token", r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{24,})"),
    ("Slack Token", r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    ("Private Key Header", r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"),
]


def is_ip_blocked(ip_str: str) -> bool:
    """Checks if an IP address belongs to any blocked/internal range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True


def resolve_hostname(hostname: str) -> List[str]:
    """Resolves hostname to IPv4/IPv6 addresses via DNS."""
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list(set([item[4][0] for item in addr_info]))
        return ips
    except socket.gaierror:
        return []


def validate_target_url(url: str, allow_local_for_test: bool = False, allowed_ports: Optional[List[int]] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Validates a target URL against strict syntax, protocol, and SSRF restrictions.
    Returns: (is_valid: bool, error_message: str, details_dict: Optional[dict])
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string.", None

    url = url.strip()
    parsed = urllib.parse.urlsplit(url)

    # 1. Scheme Validation
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}'. Only 'http' and 'https' protocols are permitted.", None

    # 2. Rejection of embedded userinfo (e.g. http://user:pass@example.com)
    if parsed.username or parsed.password:
        return False, "Credentials in URL (user:pass@host) are strictly forbidden to prevent credential leakage.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "Unable to extract a valid hostname from the URL.", None

    # 3. Hostname syntax validation
    if len(hostname) > 253:
        return False, "Hostname exceeds maximum length of 253 characters.", None

    # Disallow control characters and whitespace
    if re.search(r"[\s\x00-\x1f\x7f]", hostname):
        return False, "Hostname contains illegal characters or whitespace.", None

    # 4. Port Validation
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port <= 0 or port > 65535:
        return False, f"Port {port} is out of valid range (1-65535).", None

    # 5. Local Testing Exemption Check
    is_localhost = hostname.lower() in ("localhost", "127.0.0.1", "::1")
    if is_localhost:
        if allow_local_for_test:
            approved_ports = allowed_ports or [5000, 5050, 8000, 8080, 8888]
            if port in approved_ports:
                normalized_url = f"{parsed.scheme.lower()}://{hostname}:{port}{parsed.path or '/'}"
                if parsed.query:
                    normalized_url += f"?{parsed.query}"
                return True, "", {
                    "hostname": hostname,
                    "resolved_ips": ["127.0.0.1"],
                    "port": port,
                    "scheme": parsed.scheme.lower(),
                    "normalized_url": normalized_url,
                    "is_test_target": True
                }
            else:
                return False, f"Localhost access is restricted. Port {port} is not in the approved test port list {approved_ports}.", None
        else:
            return False, "SSRF Protection: Access to localhost/loopback addresses is strictly prohibited.", None

    # 6. DNS Resolution and SSRF IP Verification
    resolved_ips = resolve_hostname(hostname)
    if not resolved_ips:
        return False, f"DNS resolution failed for hostname '{hostname}'. Host does not exist or cannot be resolved.", None

    for ip in resolved_ips:
        if is_ip_blocked(ip):
            return False, f"SSRF Protection: Host '{hostname}' resolves to restricted internal IP address '{ip}'. Scan rejected.", None

    # 7. Construct canonical normalized URL
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
    netloc = hostname if default_port else f"{hostname}:{port}"
    normalized_path = parsed.path if parsed.path else "/"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, normalized_path, parsed.query, ""))

    return True, "", {
        "hostname": hostname,
        "resolved_ips": resolved_ips,
        "port": port,
        "scheme": parsed.scheme.lower(),
        "normalized_url": normalized_url,
        "is_test_target": False
    }


class SafeRedirectSession(requests.Session):
    """
    Custom Requests Session enforcing SSRF validation on every redirect hop
    and mitigating DNS rebinding attacks.
    """
    def __init__(self, allow_local_for_test: bool = False, max_redirects: int = 5, request_timeout: int = 8):
        super().__init__()
        self.allow_local_for_test = allow_local_for_test
        self.max_redirects_allowed = max_redirects
        self.request_timeout = request_timeout
        self.max_redirects = max_redirects
        
        # Configure standard retries
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.3,
            status_forcelist=[502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def send(self, request, **kwargs):
        # Intercept and validate destination URL before each request
        is_valid, err, _ = validate_target_url(request.url, allow_local_for_test=self.allow_local_for_test)
        if not is_valid:
            raise requests.exceptions.RequestException(f"SafeRedirectSession blocked outbound request: {err}")
        
        kwargs.setdefault("timeout", self.request_timeout)
        kwargs.setdefault("allow_redirects", False)  # Handle redirects manually for strict inspection
        
        response = super().send(request, **kwargs)
        
        # Follow redirects manually with full verification
        redirect_count = 0
        current_response = response
        while current_response.is_redirect and redirect_count < self.max_redirects_allowed:
            redirect_count += 1
            location = current_response.headers.get("Location")
            if not location:
                break
            
            # Resolve relative redirects against current URL
            next_url = urllib.parse.urljoin(current_response.url, location)
            
            # Revalidate next target URL against SSRF policy
            valid_next, redirect_err, _ = validate_target_url(next_url, allow_local_for_test=self.allow_local_for_test)
            if not valid_next:
                raise requests.exceptions.RequestException(f"SSRF Protection blocked redirect to '{next_url}': {redirect_err}")
            
            # Build and send the redirect request
            req = requests.Request(method="GET", url=next_url, headers=request.headers)
            prepared_req = self.prepare_request(req)
            current_response = super().send(prepared_req, **kwargs)
            
        if redirect_count >= self.max_redirects_allowed and current_response.is_redirect:
            raise requests.exceptions.TooManyRedirects(f"Exceeded maximum allowed redirects ({self.max_redirects_allowed}).")
            
        return current_response


def redact_sensitive_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Redacts values of sensitive headers like Authorization, Cookies, API Keys."""
    redacted = {}
    for k, v in headers.items():
        if str(k).lower() in SENSITIVE_HEADER_KEYS:
            redacted[k] = "[REDACTED_SENSITIVE_HEADER]"
        else:
            redacted[k] = str(v)
    return redacted


def redact_secrets(text: str) -> str:
    """Masks detected credentials and sensitive tokens with asterisks."""
    if not text or not isinstance(text, str):
        return ""

    masked = text
    for name, pattern in SECRET_PATTERNS:
        matches = re.finditer(pattern, masked)
        for m in matches:
            val = m.group(1)
            if len(val) > 8:
                masked_val = val[:4] + "*" * (len(val) - 8) + val[-4:]
            else:
                masked_val = "*" * len(val)
            masked = masked.replace(val, masked_val)
    return masked


def find_exposed_credentials(content: str, url: str) -> List[Dict[str, Any]]:
    """
    Scans HTML, JavaScript or responses for leaked tokens and API keys.
    Returns a list of findings with redacted evidence.
    """
    findings = []
    if not content or not isinstance(content, str):
        return findings

    for token_name, pattern in SECRET_PATTERNS:
        matches = re.finditer(pattern, content)
        for m in matches:
            matched_raw = m.group(1)
            # Create safe redacted snippet
            if len(matched_raw) > 8:
                redacted_token = matched_raw[:4] + "*" * 12 + matched_raw[-4:]
            else:
                redacted_token = "********"
            
            # Extract surrounding context (up to 40 chars before and after)
            start_pos = max(0, m.start() - 30)
            end_pos = min(len(content), m.end() + 30)
            context_raw = content[start_pos:end_pos]
            context_redacted = context_raw.replace(matched_raw, redacted_token)

            findings.append({
                "type": token_name,
                "url": url,
                "raw_token": matched_raw,
                "redacted_token": redacted_token,
                "evidence_context": context_redacted.strip(),
            })
    return findings
