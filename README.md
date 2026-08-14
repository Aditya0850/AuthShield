# AuthShield

> **Web Authentication Security Auditor** — Conservative, testable scanner for authentication, session, CORS, and JWT misconfigurations.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AuthShield is a **passive-first** security scanner that audits web applications for common authentication and session management vulnerabilities. It prioritizes **correctness over coverage** — every check has a clear, documented methodology and avoids unreliable or destructive testing approaches.

---

## Quick Start

```bash
# Install
pip install authshield

# Scan a target
authshield scan http://localhost:5000

# With custom options
authshield scan http://example.com \
  -e "/login,/register,/api/auth" \
  -c "session=abc123" \
  -H "Authorization: Bearer token" \
  --exclude-checks RATE-001,JWT-004 \
  -f both \
  -o my-report
```

On an interactive terminal, the scan shows per-category progress (e.g. Authentication checks → JWT checks). Progress is suppressed when stdout is not a TTY (CI / piped output).

---

## Implemented Security Checks

AuthShield implements **11 conservative checks** across 6 categories. Each check has a documented methodology and request budget.

| Check ID | Title | Category | Severity | Methodology |
|----------|-------|----------|----------|-------------|
| **AUTH-001** | Weak Password Policy Indicator | Authentication | MEDIUM | Passive regex scan of registration pages for "at least X chars" where X ≤ 5 |
| **RATE-001** | Missing Rate Limiting on Login | Rate Limiting | HIGH | Sends 5 rapid POST requests to login endpoint; checks if all return 2xx/4xx (success/unblocked) |
| **ENUM-001** | Username Enumeration via Error Messages | User Enumeration | MEDIUM | Compares error response signatures (status code + normalized error text) for valid vs invalid usernames |
| **COOKIE-001** | Missing Secure Flag on Session Cookie | Session | HIGH | Inspects `Set-Cookie` headers; flags session cookies without `Secure` attribute |
| **COOKIE-002** | Missing HttpOnly Flag on Session Cookie | Session | HIGH | Inspects `Set-Cookie` headers; flags session cookies without `HttpOnly` attribute |
| **COOKIE-003** | Missing or Insecure SameSite Attribute | Session | HIGH | Inspects `Set-Cookie` headers; flags `SameSite=None` without `Secure`, or missing `SameSite` |
| **CORS-001** | CORS Reflects Arbitrary Origin with Credentials | CORS/Headers | HIGH | Sends request with `Origin: https://evil.com`; checks if reflected with `Access-Control-Allow-Credentials: true` |
| **CORS-002** | Missing or Weak Security Headers | CORS/Headers | HIGH | Checks for: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP |
| **JWT-001** | JWT Algorithm Confusion Risk (RS256 + Public JWKS) | JWT | MEDIUM | Passive: detects RS256/ES256 tokens AND publicly accessible JWKS endpoint |
| **JWT-003** | Missing or Excessive Expiration Claim | JWT | HIGH/MEDIUM | Passive: decodes JWT payload; flags missing `exp` (HIGH) or `exp` > 7 days (MEDIUM) |
| **JWT-004** | Endpoint Accepts `none` Algorithm JWT | JWT | CRITICAL | Active (safe): crafts `alg=none` token, sends to protected endpoint; checks if accepted (200 OK) |

### Checks Intentionally NOT Implemented

| Check | Reason |
|-------|--------|
| Credential Stuffing / Brute Force | Unethical, unreliable, often blocked by WAFs |
| Default Credentials (AUTH-003) | Requires credential lists; high false positive rate |
| MFA Detection (AUTH-002) | Cannot reliably detect without authentication |
| Timing-based Enum (ENUM-002) | Network variance makes timing unreliable over internet |
| Weak Secret Brute-force (JWT-002) | Computationally infeasible; not a scanner's role |
| JWT-002 (Weak Secret) | Requires offline cracking; out of scope |

---

## Output Formats

### JSON Report (`-f json` or `-f both`)
Machine-readable structured output with findings, evidence, and remediation guidance.

```json
{
  "target": "http://localhost:5000",
  "scan_time": "2026-08-11T07:39:12.478650Z",
  "scan_duration": 38.81,
  "summary": { "critical": 0, "high": 5, "medium": 1, "low": 0, "info": 0, "total": 6 },
  "findings": [
    {
      "id": "COOKIE-001",
      "title": "Missing Secure Flag on Session Cookie",
      "severity": "HIGH",
      "category": "session",
      "evidence": { "description": "...", "raw_data": {...} },
      "fix": "Set Secure flag on all session cookies...",
      "references": ["https://owasp.org/..."]
    }
  ]
}
```

### HTML Report (`-f html` or `-f both`)
Human-readable report grouped by severity and category. Includes interactive severity/category filters and a dark/light mode toggle (persisted via localStorage) — pure JS/CSS, renders as a static file with no server required.

---

## Local Testing with VulnApp

AuthShield includes a **deliberately vulnerable Flask application** (`vuln_app.py`) that demonstrates all detectable issues.

```bash
# Terminal 1: Start the vulnerable app
pip install flask pyjwt cryptography werkzeug
python vuln_app.py
# Running on http://localhost:5000

# Terminal 2: Run AuthShield scan
authshield scan http://localhost:5000 -f both -o vulnapp-report

# Optional: skip noisy checks
# authshield scan http://localhost:5000 --exclude-checks RATE-001 -f both

# Expected findings (often 6+; RATE-001/ENUM-001 also common):
# - 1 MEDIUM: AUTH-001 (weak password policy: min 4 chars)
# - 3 HIGH:   COOKIE-001, COOKIE-002, COOKIE-003 (insecure session cookies)
# - 2 HIGH:   CORS-001 (reflects arbitrary origin + credentials), CORS-002 (missing security headers)
```

> **WARNING**: `vuln_app.py` contains INTENTIONAL vulnerabilities. Never deploy to production. For local testing only.

### VulnApp Endpoints

| Endpoint | Purpose | Vulnerabilities Demonstrated |
|----------|---------|------------------------------|
| `GET /` | Home page | Sets insecure cookies (COOKIE-001/002/003) |
| `GET /register` | Registration page | AUTH-001 (min 4 char password) |
| `POST /login` | Login | RATE-001 (no rate limit), ENUM-001 (user enumeration via error diff) |
| `GET /api/*` | Protected APIs | JWT-003 (30-day token expiry) |
| `GET /.well-known/jwks.json` | JWKS | JWT-001 (public JWKS + RS256) |
| `OPTIONS /api/*` | CORS preflight | CORS-001 (reflects any origin + credentials), CORS-002 (no security headers) |

---

## Design Principles

### Conservative by Default
- **No brute force** — No credential stuffing, password spraying, or secret cracking
- **No destructive actions** — Only GET/POST requests that mimic normal browser behavior
- **Request budgets** — Default max 100 requests per scan (scanner `max_requests`)
- **Passive-first** — 8 of 11 checks are purely passive observation

### Testable & Explainable
- **50+ unit tests** with mocked HTTP responses — zero external dependencies
- **Every finding includes** raw evidence, clear fix guidance, and OWASP references
- **Clear methodology** documented per-check in source code (`authshield/checks/*.py`)

### Reliability Over Coverage
- Removed timing-based checks (network variance over internet is too high)
- Removed checks requiring credential lists (high false positives)
- Active tests (JWT-004, RATE-001) are safe and clearly documented

---

## Configuration

### CLI Options

```
Usage: authshield scan [OPTIONS] TARGET

Arguments:
  TARGET                  Target URL (e.g., http://example.com)

Options:
  -e, --endpoints TEXT    Comma-separated endpoints to scan
  -c, --cookie TEXT       Cookies in format 'name=value' (multiple)
  -H, --header TEXT       Headers in format 'Name: Value' (multiple)
  -t, --timeout INT       Request timeout in seconds (default: 10)
  --no-ssl-verify         Disable SSL certificate verification
  -f, --format [json|html|both]  Output format (default: both)
  -o, --output TEXT       Output file path (without extension)
  --exclude-checks TEXT   Comma-separated check IDs to skip (e.g. RATE-001,JWT-004)
  -v, --verbose           Verbose output
  --help                  Show this message and exit.
```

### Exclude Specific Checks
Skip noisy or irrelevant checks by ID. Unknown IDs print a warning and are ignored; valid exclusions appear in the scan summary.

```bash
authshield scan http://example.com --exclude-checks RATE-001,COOKIE-002
authshield checks   # list valid check IDs
```

### List All Checks
```bash
authshield checks
```

### Quick Scan (minimal output)
```bash
authshield quick http://example.com
```

---

## Development

### Requirements
- Python 3.10+
- Dependencies: `click`, `requests`, `pydantic`, `rich`, `jinja2`, `pyjwt`, `beautifulsoup4`

### Install in Development Mode
```bash
git clone https://github.com/Aditya0850/AuthShield
cd AuthShield
pip install -e ".[dev]"
```

### Run Tests
```bash
# All tests with coverage
pytest --cov=authshield --cov-report=term-missing

# Specific module
pytest tests/test_authshield.py::test_auth_checks -v
```

### Linting & Type Checking
```bash
ruff check .
mypy authshield/
```

### Project Structure
```
authshield/
├── cli.py                 # Click CLI entry point
├── core/
│   ├── http_client.py     # Conservative HTTP client (budget, retries, pooling)
│   ├── models.py          # Pydantic models (Finding, ScanResult, Severity)
│   └── scanner.py         # Main orchestration (request budget aware)
├── checks/
│   ├── auth.py            # AUTH-001: Weak password policy
│   ├── rate_limit.py      # RATE-001: Login rate limiting
│   ├── enum.py            # ENUM-001: User enumeration via error messages
│   ├── cookies.py         # COOKIE-001/002/003: Session cookie flags
│   ├── cors.py            # CORS-001/002: CORS & security headers
│   └── jwt.py             # JWT-001/003/004: JWT security
├── reporting/
│   ├── html_report.py     # Jinja2 HTML reporter
│   └── json_report.py     # JSON reporter
└── __init__.py
```

---

## Limitations & Known Gaps

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No JavaScript rendering | Misses SPA-rendered auth forms | Provide endpoints manually via `-e` |
| No authentication flow | Cannot test logged-in paths | Provide session cookies via `-c` |
| Single-threaded | Slower on large targets | Use focused endpoint lists |
| No WAF evasion | May be blocked by WAFs | Run from allowed IP; adjust timeout |
| JWT-004 active test | Sends one malformed request | Safe: only tests algorithm confusion; no data access |

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new checks (mocked HTTP responses required)
4. Ensure `ruff check .` and `mypy authshield/` pass
5. Submit PR with clear description of check methodology

### Adding a New Check
1. Create `authshield/checks/new_check.py` with `NewChecks` class
2. Implement `run_all()` method using `scanner.make_request()`
3. Add findings via `scanner.add_finding(make_finding(...))`
4. Register in `scanner.py` `__init__`
5. Add mocked tests in `tests/test_authshield.py`

---

## Changelog

### Unreleased
- `--exclude-checks` CLI flag to skip selected check IDs (#1)
- Per-category scan progress indicator on interactive terminals (#2)
- HTML report: severity/category filtering and dark mode toggle (#3)

### v0.1.0 (2026-08-11)
- Initial release with 11 checks across 6 categories
- JSON + HTML reporting
- VulnApp for local testing
- Full test suite (50+ tests)
- Conservative design: no brute force, no unreliable checks

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Roadmap

### v0.1 (current) — Auth Security Auditing
- Auth, sessions/cookies, CORS, JWT, security headers
- JSON/HTML reports
- `--exclude-checks` to skip selected check IDs
- Per-category scan progress on interactive terminals

### v0.2 — Web Security Expansion
- SQL injection detection
- XSS detection (reflected, stored, DOM indicators)
- CSRF protection analysis
- SSRF indicators
- Open redirect detection
- Path traversal heuristics
- IDOR/BOLA heuristics
- File upload weakness detection
- HTTP method misconfiguration
- Information disclosure checks
- Sensitive data exposure indicators
- API security checks

### v0.3 — Attack Surface Intelligence
- Endpoint discovery (crawling, JS analysis)
- robots.txt / sitemap.xml analysis
- JavaScript endpoint extraction
- API route discovery
- Parameter discovery
- Technology fingerprinting (framework, CMS, WAF)
- Auth flow mapping
- Attack surface visualization

### v0.4 — Safe Validation & Remediation Intelligence
- **Detect → Validate Safely → Collect Evidence → Rate Confidence → Explain Impact**
- Every finding moves toward:
  - What happened
  - Why it matters
  - Evidence
  - Severity
  - Confidence
  - How to reproduce safely
  - How to fix
  - References
- **Strict rule**: AuthShield only operates against systems the user owns, authorized targets, or intentionally vulnerable labs — no automated exploitation, non-destructive validation only

---

AuthShield: **Web Application Security Auditor — From Auth Audit to Safe Validation**

---

## Disclaimer

AuthShield is a **security auditing tool** for authorized testing only. The authors are not responsible for misuse. Always obtain explicit permission before scanning targets you do not own. The included `vuln_app.py` is for educational purposes only — never deploy to production.
