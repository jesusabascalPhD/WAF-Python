# 🛡️ PyWAF — Basic Web Application Firewall in Python

A lightweight, zero-dependency **reverse-proxy WAF** written in pure Python 3 for Linux.  
It sits in front of your web application and inspects every HTTP request before forwarding it upstream, blocking attacks in real time.

```
  Client  ──►  PyWAF (:8000)  ──►  Your App (:8080)
                   │
              [blocks 403]
```

---

## ✨ Features

| Category | Details |
|---|---|
| **Attack detection** | SQL Injection, XSS, Path Traversal, Command Injection, SSRF, XXE, Log4Shell |
| **Rate limiting** | Sliding-window counter per IP — auto-blocks on threshold breach |
| **Auto-blacklist** | IPs triggering ≥ 10 attacks are permanently blacklisted at runtime |
| **Scanner blocking** | Drops requests from known tools: sqlmap, nikto, acunetix, burpsuite… |
| **Size limits** | Max URL length, body size, param length and header length enforced |
| **IP lists** | Static whitelist / blacklist with full CIDR range support |
| **Stats endpoint** | Live JSON stats via a special `WAF_STATUS` method |
| **Logging** | Structured log to console + `waf.log` file |
| **No dependencies** | Uses only Python 3 standard library |

---

## 🔍 Detected Attack Types

### SQL Injection
Matches `UNION SELECT`, `OR 1=1`, time-based blind (`sleep()`, `benchmark()`), dangerous stored procedures (`xp_cmdshell`, `load_file`), SQL comments and `char()` encoding.

### Cross-Site Scripting (XSS)
Detects `<script>` tags, `javascript:` URIs, inline event handlers (`onerror=`, `onload=`), dangerous HTML tags (`<iframe>`, `<object>`, `<embed>`), HTML entity encoding and Unicode escapes.

### Path Traversal
Catches `../`, URL-encoded variants (`%2e%2e%2f`, `%252e%252e%252f`) and direct references to sensitive paths like `/etc/passwd`, `/etc/shadow`, `boot.ini`.

### Command Injection
Catches shell metacharacters (`;`, `|`, `` ` ``), `$()` subshell expansion, common binaries (`ls`, `cat`, `wget`, `curl`, `bash`) and recon commands (`whoami`, `id`, `uname`).

### SSRF
Blocks requests embedding private/loopback addresses (`127.x`, `192.168.x`, `10.x`, `172.16-31.x`), `localhost`, `::1` and the AWS EC2 metadata endpoint (`169.254.169.254`).

### XXE (XML External Entities)
Detects `<!ENTITY`, `SYSTEM "..."` declarations and malformed `<!DOCTYPE>` blocks.

### Log4Shell (CVE-2021-44228)
Identifies `${jndi:ldap://...}` and similar JNDI lookup payloads in any part of the request.

---

## 🚀 Quick Start

**Requirements:** Python 3.10+ · Linux · No external packages needed.

```bash
# Clone the repo
git clone https://github.com/your-username/pywaf.git
cd pywaf

# Start WAF on port 8000, forwarding to your app on port 8080
python3 waf.py --port 8000 --target-port 8080
```

The WAF is now intercepting all traffic on `:8000` and proxying clean requests to `:8080`.

---

## ⚙️ CLI Options

```
python3 waf.py [OPTIONS]

Options:
  --host          HOST   Address to listen on           (default: 0.0.0.0)
  --port          PORT   Port to listen on              (default: 8000)
  --target-host   HOST   Upstream application host      (default: 127.0.0.1)
  --target-port   PORT   Upstream application port      (default: 8080)
  --whitelist     CIDR   One or more IPs / CIDR ranges to always allow
  --blacklist     CIDR   One or more IPs / CIDR ranges to always block
```

### Examples

```bash
# Custom ports
python3 waf.py --port 80 --target-port 3000

# Whitelist internal network, blacklist a known bad IP
python3 waf.py --whitelist 10.0.0.0/8 --blacklist 203.0.113.99

# Protect a remote upstream
python3 waf.py --target-host 192.168.1.50 --target-port 8080
```

---

## 📊 Live Stats

Query WAF metrics at any time using the special `WAF_STATUS` HTTP method:

```bash
curl -X WAF_STATUS http://localhost:8000/
```

Response:

```json
{
  "stats": {
    "total_requests": 142,
    "blocked_requests": 8,
    "passed_requests": 134,
    "attacks_by_type": {
      "SQL Injection": 3,
      "XSS": 2,
      "Path Traversal": 1,
      "Command Injection": 2
    }
  },
  "blocked_ips": ["203.0.113.99"],
  "temp_blocked_ips": {
    "1.2.3.4": "2025-06-01T14:32:00"
  }
}
```

---

## 🔒 Default Limits

| Parameter | Default |
|---|---|
| Max URL length | 2 048 bytes |
| Max body size | 1 MB |
| Max parameter length | 512 bytes |
| Max header length | 8 192 bytes |
| Rate limit window | 60 seconds |
| Max requests per window | 100 |
| Temp block duration | 5 minutes |
| Auto-blacklist threshold | 10 attacks |

All constants are at the top of `waf.py` and easy to adjust.

---

## 📁 Project Structure

```
pywaf/
├── waf.py          # Main WAF reverse proxy
├── test_waf.py     # Automated test suite (21 test cases)
├── waf.log         # Generated at runtime
└── README.md
```

---

## 🧪 Running the Tests

The test suite covers both attack scenarios (expected 403) and legitimate traffic (expected 2xx). It requires a live WAF instance to be running.

```bash
# Terminal 1 — start the WAF (no upstream needed for basic tests)
python3 waf.py --port 8000

# Terminal 2 — run tests
python3 test_waf.py --waf-url http://localhost:8000
```

Example output:

```
────────────────────────────────────────────────────────────
  WAF Test Suite  →  http://localhost:8000
────────────────────────────────────────────────────────────

  Result   Expected  Test
  ──────   ────────  ────
  ✔ block    SQLi: UNION SELECT                          (HTTP 403)
  ✔ block    SQLi: OR 1=1                                (HTTP 403)
  ✔ block    XSS: script tag                             (HTTP 403)
  ✔ block    PathTraversal: ../etc                       (HTTP 403)
  ✔ block    CMDi: semicolon+ls                          (HTTP 403)
  ✔ block    SSRF: localhost                             (HTTP 403)
  ✔ block    Log4Shell: jndi ldap                        (HTTP 403)
  ✔ block    BlockedUA: sqlmap                           (HTTP 403)
  ✔ pass     Legit: normal GET                           (HTTP 502)
  ✔ pass     Legit: search param                         (HTTP 502)
  ...

  Results: 21/21 passed
  ✔ All tests passed!
```

> **Note:** Legitimate requests return `502 Bad Gateway` when no upstream is running — this is expected and still counts as "passed" (the WAF correctly did not block them).

---

## 🚦 How It Works

Each incoming request goes through an ordered inspection pipeline:

```
Request
  │
  ├─ 1. Static IP blacklist / whitelist
  ├─ 2. Rate limiter (sliding window per IP)
  ├─ 3. URL length check
  ├─ 4. User-Agent blocklist (scanners / bots)
  ├─ 5. Header inspection
  ├─ 6. URL & query string pattern matching
  ├─ 7. Query parameter inspection (key + value)
  └─ 8. Request body (raw + JSON-aware)
         │
         ├─ BLOCKED → 403 + JSON error + log warning
         └─ CLEAN   → forward to upstream + log info
```

URL-encoded values are decoded before matching to prevent bypass attempts via `%2f`, `%3c`, etc.

---

## 📋 Blocked Response Format

When a request is blocked the WAF returns HTTP `403 Forbidden` with a JSON body:

```json
{
  "error": "Forbidden",
  "reason": "SQL Injection detected in param[id]: '1 UNION SELECT * FROM users'",
  "waf": true
}
```

The response also includes the header `X-WAF-Blocked: true`.

---

## ⚠️ Disclaimer

This project is intended for **educational purposes** and as a **starting point** for understanding WAF concepts. It is **not a replacement** for production-grade solutions (ModSecurity, AWS WAF, Cloudflare, etc.).

Notable limitations to be aware of:

- In-memory only — stats and dynamic blacklists reset on restart.
- Single-threaded server — not suitable for high-traffic production use.
- Regex-based detection can produce false positives in some edge cases.
- Does not handle HTTPS termination (use nginx/caddy in front for TLS).

---

## 🤝 Contributing

Contributions are welcome. Some ideas for improvement:

- Add persistent rule storage (SQLite / JSON file)
- Multithreaded or async server (`asyncio`)
- HTTPS support via `ssl.wrap_socket`
- Prometheus metrics endpoint
- YAML/TOML configuration file
- IP geolocation-based blocking

Please open an issue before submitting large pull requests.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
