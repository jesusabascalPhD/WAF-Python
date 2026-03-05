#!/usr/bin/env python3
"""
Basic WAF (Web Application Firewall) in Python for Linux
Blocks malicious HTTP requests using pattern matching and heuristics.
Usage: python3 waf.py [--host HOST] [--port PORT] [--target-host HOST] [--target-port PORT]
"""

import re
import json
import time
import logging
import argparse
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, parse_qs, unquote_plus
import urllib.request


# ─────────────────────────────────────────────────────────────
#  Logging setup
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("waf.log"),
    ],
)
log = logging.getLogger("WAF")


# ─────────────────────────────────────────────────────────────
#  Attack patterns
# ─────────────────────────────────────────────────────────────
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(\b(select|insert|update|delete|drop|create|alter|exec|union|having|group\s+by)\b)",
        r"(?i)(--|;|'|\")\s*(or|and)\s+[\w'\"=]",
        r"(?i)\bor\b\s+[\d'\"]+\s*=\s*[\d'\"]+",
        r"(?i)(sleep|benchmark|waitfor\s+delay)\s*\(",
        r"(?i)\b(xp_cmdshell|sp_executesql|load_file|into\s+outfile)\b",
        r"(?i)\/\*.*?\*\/",                     # SQL comments
        r"(?i)\bchar\s*\(\s*\d+",              # char() encoding
    ],
    "XSS": [
        r"(?i)<\s*script[^>]*>",
        r"(?i)(javascript|vbscript|data)\s*:",
        r"(?i)on\w+\s*=\s*['\"]",              # onload=, onclick=, etc.
        r"(?i)<\s*(iframe|object|embed|applet|link|meta)[^>]*>",
        r"(?i)expression\s*\(",
        r"(?i)&#x?[0-9a-f]+;",                 # HTML entity encoding
        r"(?i)\\u[0-9a-f]{4}",                 # Unicode escapes in JS
    ],
    "Path Traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"(?i)\.\.[/\\]+(etc|proc|var|root|home|windows|system32)",
        r"(?i)(\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)",
    ],
    "Command Injection": [
        r"(?i)[;&|`$]\s*(ls|cat|rm|wget|curl|bash|sh|nc|python|perl|php)",
        r"(?i)\$\(.*\)",
        r"(?i)`[^`]*`",
        r"(?i)\b(\/bin\/|\/usr\/bin\/)(sh|bash|dash|zsh)",
        r"(?i)(whoami|id|uname|ifconfig|ipconfig|netstat)",
    ],
    "SSRF": [
        r"(?i)(http|https|ftp|file|dict|gopher):\/\/(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)",
        r"(?i)(localhost|127\.0\.0\.1|::1)",
        r"(?i)\/\/(metadata|169\.254\.169\.254)",  # AWS metadata
    ],
    "XXE": [
        r"(?i)<\s*!ENTITY",
        r"(?i)SYSTEM\s+['\"]",
        r"(?i)<!DOCTYPE[^>]*\[",
    ],
    "Log4Shell": [
        r"(?i)\$\{jndi:(ldap|rmi|dns|corba|iiop|nis|nds|http)",
        r"(?i)\$\{.*:.*:\/\/",
    ],
}

# Suspicious headers
SUSPICIOUS_HEADERS = [
    r"(?i)<\s*script",
    r"(?i)select\s+\*\s+from",
    r"(?i)\.\./",
]

# Blocked user agents (bots, scanners)
BLOCKED_USER_AGENTS = [
    r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|burpsuite)",
    r"(?i)(acunetix|netsparker|appscan|webinspect|qualys)",
    r"(?i)(python-requests\/[01]\.|go-http-client\/1\.0)",  # common scanner defaults
]

# Max request limits
MAX_BODY_SIZE = 1 * 1024 * 1024   # 1 MB
MAX_URL_LENGTH = 2048
MAX_PARAM_LENGTH = 512
MAX_HEADER_LENGTH = 8192

# Rate limiting
RATE_LIMIT_WINDOW = 60       # seconds
RATE_LIMIT_MAX_REQUESTS = 100
BLOCK_DURATION = 300         # seconds (5 minutes)


# ─────────────────────────────────────────────────────────────
#  Stats
# ─────────────────────────────────────────────────────────────
stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "passed_requests": 0,
    "attacks_by_type": defaultdict(int),
}


# ─────────────────────────────────────────────────────────────
#  Rate limiter / IP block list
# ─────────────────────────────────────────────────────────────
ip_requests = defaultdict(list)       # ip -> [timestamp, ...]
ip_blocked_until = {}                 # ip -> datetime
ip_attack_count = defaultdict(int)    # ip -> number of attack detections

# Static IP allowlist / blocklist (CIDR supported)
STATIC_WHITELIST: list[str] = []      # e.g. ["127.0.0.1", "10.0.0.0/8"]
STATIC_BLACKLIST: list[str] = []      # e.g. ["1.2.3.4"]


def ip_in_list(ip: str, ip_list: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for entry in ip_list:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                if ip == entry:
                    return True
    except ValueError:
        pass
    return False


def is_rate_limited(ip: str) -> bool:
    now = datetime.now()

    # Check temp block
    if ip in ip_blocked_until:
        if now < ip_blocked_until[ip]:
            return True
        else:
            del ip_blocked_until[ip]

    # Sliding window
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    ip_requests[ip] = [t for t in ip_requests[ip] if t > window_start]
    ip_requests[ip].append(now)

    if len(ip_requests[ip]) > RATE_LIMIT_MAX_REQUESTS:
        ip_blocked_until[ip] = now + timedelta(seconds=BLOCK_DURATION)
        log.warning(f"[RATE-LIMIT] Blocking IP {ip} for {BLOCK_DURATION}s")
        return True

    return False


# ─────────────────────────────────────────────────────────────
#  Core WAF engine
# ─────────────────────────────────────────────────────────────
def check_patterns(value: str, context: str, ip: str) -> tuple[bool, str]:
    """Return (blocked, reason)."""
    decoded = unquote_plus(value)  # decode URL encoding once

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, decoded):
                reason = f"{attack_type} detected in {context}: {decoded[:80]!r}"
                return True, reason
    return False, ""


def inspect_request(method: str, path: str, headers: dict,
                    body: bytes, ip: str) -> tuple[bool, str]:
    """
    Full WAF inspection pipeline.
    Returns (should_block, reason).
    """

    # 1. Static IP lists
    if ip_in_list(ip, STATIC_BLACKLIST):
        return True, "IP in static blacklist"
    if ip_in_list(ip, STATIC_WHITELIST):
        return False, ""   # whitelist bypasses all checks

    # 2. Rate limiting
    if is_rate_limited(ip):
        return True, "Rate limit exceeded"

    # 3. URL length
    if len(path) > MAX_URL_LENGTH:
        return True, f"URL too long ({len(path)} bytes)"

    # 4. Blocked user agents
    ua = headers.get("user-agent", "")
    for pattern in BLOCKED_USER_AGENTS:
        if re.search(pattern, ua):
            return True, f"Blocked user-agent: {ua[:60]!r}"

    # 5. Suspicious headers
    for header_name, header_value in headers.items():
        combined = f"{header_name}: {header_value}"
        if len(combined) > MAX_HEADER_LENGTH:
            return True, f"Header too long: {header_name}"
        for pattern in SUSPICIOUS_HEADERS:
            if re.search(pattern, combined):
                return True, f"Malicious content in header {header_name!r}"

    # 6. URL / query string
    blocked, reason = check_patterns(path, "URL", ip)
    if blocked:
        return True, reason

    # 7. Query parameters
    parsed = urlparse(path)
    params = parse_qs(parsed.query)
    for key, values in params.items():
        for val in values:
            if len(val) > MAX_PARAM_LENGTH:
                return True, f"Parameter {key!r} too long"
            for context_str, target in [(f"param[{key}]", val), (f"param-key", key)]:
                blocked, reason = check_patterns(target, context_str, ip)
                if blocked:
                    return True, reason

    # 8. Request body
    if body:
        if len(body) > MAX_BODY_SIZE:
            return True, f"Request body too large ({len(body)} bytes)"
        try:
            body_str = body.decode("utf-8", errors="replace")
        except Exception:
            body_str = ""

        # Try to parse as JSON and check values
        try:
            data = json.loads(body_str)
            flat = json.dumps(data)
            blocked, reason = check_patterns(flat, "JSON body", ip)
            if blocked:
                return True, reason
        except json.JSONDecodeError:
            pass

        # Raw body check
        blocked, reason = check_patterns(body_str, "body", ip)
        if blocked:
            return True, reason

    return False, ""


# ─────────────────────────────────────────────────────────────
#  Proxy / handler
# ─────────────────────────────────────────────────────────────
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080


class WAFHandler(BaseHTTPRequestHandler):
    server_version = "WAF/1.0"
    log_message = lambda self, *a: None   # silence default access log

    # ── helpers ──────────────────────────────────────────────

    def get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def send_block(self, reason: str, code: int = 403):
        body = json.dumps({
            "error": "Forbidden",
            "reason": reason,
            "waf": True,
        }).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-WAF-Blocked", "true")
        self.end_headers()
        self.wfile.write(body)

    def get_headers_dict(self) -> dict:
        return {k.lower(): v for k, v in self.headers.items()}

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_SIZE + 1:
            return b""   # will be caught later
        return self.rfile.read(length) if length else b""

    # ── main inspection ──────────────────────────────────────

    def handle_request(self):
        stats["total_requests"] += 1
        ip = self.get_client_ip()
        headers = self.get_headers_dict()
        body = self.read_body()

        blocked, reason = inspect_request(
            self.command, self.path, headers, body, ip
        )

        if blocked:
            stats["blocked_requests"] += 1
            ip_attack_count[ip] += 1
            # Auto-blacklist after 10 attacks
            if ip_attack_count[ip] >= 10:
                if ip not in STATIC_BLACKLIST:
                    STATIC_BLACKLIST.append(ip)
                    log.warning(f"[BLACKLIST] Auto-blacklisted {ip} after repeated attacks")
            # Detect attack type for stats
            for attack_type in ATTACK_PATTERNS:
                if attack_type.lower() in reason.lower():
                    stats["attacks_by_type"][attack_type] += 1
                    break
            log.warning(f"[BLOCKED] {ip} {self.command} {self.path[:80]} | {reason}")
            self.send_block(reason)
            return

        # ── forward to upstream ──────────────────────────────
        stats["passed_requests"] += 1
        target_url = f"http://{TARGET_HOST}:{TARGET_PORT}{self.path}"
        req = Request(target_url, data=body or None, method=self.command)

        # Copy safe headers
        hop_by_hop = {"connection", "keep-alive", "proxy-authenticate",
                      "proxy-authorization", "te", "trailers",
                      "transfer-encoding", "upgrade"}
        for k, v in self.headers.items():
            if k.lower() not in hop_by_hop:
                req.add_header(k, v)
        req.add_header("X-Forwarded-For", ip)
        req.add_header("X-WAF-Checked", "true")

        try:
            with urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in hop_by_hop | {"content-length"}:
                        self.send_header(k, v)
                resp_body = resp.read()
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
        except HTTPError as e:
            resp_body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except URLError as e:
            err = json.dumps({"error": "Bad Gateway", "detail": str(e)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)

        log.info(f"[PASS] {ip} {self.command} {self.path[:80]}")

    # Dispatch all HTTP methods
    def do_GET(self):     self.handle_request()
    def do_POST(self):    self.handle_request()
    def do_PUT(self):     self.handle_request()
    def do_DELETE(self):  self.handle_request()
    def do_PATCH(self):   self.handle_request()
    def do_HEAD(self):    self.handle_request()
    def do_OPTIONS(self): self.handle_request()

    # WAF status page
    def do_WAF_STATUS(self):
        body = json.dumps({
            "stats": {
                **stats,
                "attacks_by_type": dict(stats["attacks_by_type"]),
            },
            "blocked_ips": list(STATIC_BLACKLIST),
            "temp_blocked_ips": {
                ip: dt.isoformat()
                for ip, dt in ip_blocked_until.items()
            },
        }, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────
def main():
    global TARGET_HOST, TARGET_PORT

    parser = argparse.ArgumentParser(description="Basic Python WAF Proxy")
    parser.add_argument("--host", default="0.0.0.0", help="WAF listen address")
    parser.add_argument("--port", type=int, default=8000, help="WAF listen port")
    parser.add_argument("--target-host", default="127.0.0.1", help="Upstream host")
    parser.add_argument("--target-port", type=int, default=8080, help="Upstream port")
    parser.add_argument("--whitelist", nargs="*", default=[], help="Whitelisted IPs/CIDRs")
    parser.add_argument("--blacklist", nargs="*", default=[], help="Blacklisted IPs/CIDRs")
    args = parser.parse_args()

    TARGET_HOST = args.target_host
    TARGET_PORT = args.target_port
    STATIC_WHITELIST.extend(args.whitelist)
    STATIC_BLACKLIST.extend(args.blacklist)

    server = HTTPServer((args.host, args.port), WAFHandler)
    log.info("=" * 60)
    log.info(f"  WAF listening on  http://{args.host}:{args.port}")
    log.info(f"  Forwarding to     http://{TARGET_HOST}:{TARGET_PORT}")
    log.info(f"  Rate limit        {RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW}s per IP")
    log.info(f"  Max body size     {MAX_BODY_SIZE // 1024} KB")
    log.info("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("WAF stopped.")
        log.info(f"Final stats: {stats}")


if __name__ == "__main__":
    main()
