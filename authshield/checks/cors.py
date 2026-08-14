from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Confidence, EvidenceType, Exploitability, Severity


class CORSChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        if not self.scanner.is_check_excluded("CORS-001"):
            self.check_cors_policy()
        if not self.scanner.is_check_excluded("CORS-002"):
            self.check_security_headers()

    def check_cors_policy(self):
        """CORS-001: Check for overly permissive CORS policy"""
        # Test with different origins
        test_origins = [
            "https://evil.com",
            "https://subdomain.evil.com",
            "null",
            "https://attacker.example.com",
        ]

        for endpoint in ["/api/", "/api/user", "/api/auth", "/"]:
            for origin in test_origins:
                resp = self.scanner.make_request("OPTIONS", endpoint, headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                })

                if resp is not None:
                    acao = resp.headers.get("Access-Control-Allow-Origin")
                    acac = resp.headers.get("Access-Control-Allow-Credentials")

                    if acao == "*" and acac == "true":
                        self.scanner.add_finding(make_finding(
                            check_id="CORS-001",
                            title="Dangerous CORS: Wildcard with Credentials",
                            severity=Severity.CRITICAL,
                            category=Category.CORS_HEADERS,
                            evidence_desc=f"Endpoint {endpoint} allows any origin (*) with credentials",
                            fix="Never use '*' with credentials. Specify exact allowed origins. Set Access-Control-Allow-Credentials: true only for trusted origins.",
                            references=["https://owasp.org/www-project-cors-security-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "origin": origin, "acao": acao, "acac": acac},
                            confidence=Confidence.HIGH,
                            evidence_type=EvidenceType.PROOF,
                            exploitability=Exploitability.PROVEN,
                            context={"check_type": "cors_policy_validation", "vulnerability": "wildcard_with_credentials"},
                        ))
                        return

                    elif acao and origin in acao and acac == "true":
                        self.scanner.add_finding(make_finding(
                            check_id="CORS-001",
                            title="CORS Reflects Arbitrary Origin with Credentials",
                            severity=Severity.HIGH,
                            category=Category.CORS_HEADERS,
                            evidence_desc=f"Endpoint {endpoint} reflects attacker origin '{origin}' with credentials",
                            fix="Validate Origin header against whitelist. Don't dynamically reflect Origin header.",
                            references=["https://owasp.org/www-project-cors-security-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "origin": origin, "acao": acao, "acac": acac},
                            confidence=Confidence.HIGH,
                            evidence_type=EvidenceType.PROOF,
                            exploitability=Exploitability.PROVEN,
                            context={"check_type": "cors_policy_validation", "vulnerability": "reflected_origin_with_credentials"},
                        ))
                        return

                    elif acao == "*":
                        self.scanner.add_finding(make_finding(
                            check_id="CORS-001",
                            title="Overly Permissive CORS: Wildcard Origin",
                            severity=Severity.MEDIUM,
                            category=Category.CORS_HEADERS,
                            evidence_desc=f"Endpoint {endpoint} allows any origin (*)",
                            fix="Restrict CORS to specific trusted origins only",
                            references=["https://owasp.org/www-project-cors-security-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "acao": acao},
                            confidence=Confidence.MEDIUM,
                            evidence_type=EvidenceType.INDICATOR,
                            exploitability=Exploitability.THEORETICAL,
                            context={"check_type": "cors_policy_validation", "vulnerability": "wildcard_origin"},
                        ))
                        return

    def check_security_headers(self):
        """CORS-002: Check for missing security headers with context-aware severity"""
        resp = self.scanner.make_request("GET", "/")
        if not resp:
            return

        headers = resp.headers
        content_type = headers.get("Content-Type", "").lower()

        # Classify site type for context-aware severity
        site_type = self._classify_site_type(resp, headers, content_type)
        is_api = "application/json" in content_type or "application/xml" in content_type
        is_html = "text/html" in content_type
        is_https = self.scanner.target.startswith("https://")

        missing = []
        issues = []
        header_details = {}

        # CSP - critical for HTML-serving apps, less critical for APIs
        csp = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only")
        if not csp:
            missing.append("Content-Security-Policy")
            header_details["Content-Security-Policy"] = {"present": False, "site_type": site_type}
        else:
            header_details["Content-Security-Policy"] = {"present": True, "value": csp, "site_type": site_type}
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                issues.append("CSP contains unsafe directives")
                header_details["Content-Security-Policy"]["issues"] = ["unsafe-inline" if "unsafe-inline" in csp else "unsafe-eval"]

        # HSTS - only applicable for HTTPS sites
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            if is_https:
                missing.append("Strict-Transport-Security (HSTS)")
            header_details["Strict-Transport-Security"] = {"present": False, "https": is_https, "site_type": site_type}
        else:
            header_details["Strict-Transport-Security"] = {"present": True, "value": hsts, "site_type": site_type}
            if "max-age" not in hsts.lower():
                issues.append("HSTS missing max-age")
                header_details["Strict-Transport-Security"]["issues"] = ["missing_max_age"]

        # X-Frame-Options - critical for frameable HTML pages
        xfo = headers.get("X-Frame-Options")
        if not xfo:
            missing.append("X-Frame-Options")
            header_details["X-Frame-Options"] = {"present": False, "site_type": site_type}
        else:
            header_details["X-Frame-Options"] = {"present": True, "value": xfo, "site_type": site_type}
            if xfo.upper() not in ["DENY", "SAMEORIGIN"]:
                issues.append("X-Frame-Options has weak value")
                header_details["X-Frame-Options"]["issues"] = ["weak_value"]

        # X-Content-Type-Options
        xcto = headers.get("X-Content-Type-Options")
        if not xcto or xcto.lower() != "nosniff":
            missing.append("X-Content-Type-Options (nosniff)")
            header_details["X-Content-Type-Options"] = {"present": False, "site_type": site_type}
        else:
            header_details["X-Content-Type-Options"] = {"present": True, "value": xcto, "site_type": site_type}

        # Referrer-Policy
        rp = headers.get("Referrer-Policy")
        if not rp:
            missing.append("Referrer-Policy")
            header_details["Referrer-Policy"] = {"present": False, "site_type": site_type}
        else:
            header_details["Referrer-Policy"] = {"present": True, "value": rp, "site_type": site_type}

        # Permissions-Policy
        pp = headers.get("Permissions-Policy")
        if not pp:
            missing.append("Permissions-Policy")
            header_details["Permissions-Policy"] = {"present": False, "site_type": site_type}
        else:
            header_details["Permissions-Policy"] = {"present": True, "value": pp, "site_type": site_type}

        # Cross-Origin-Opener-Policy
        coop = headers.get("Cross-Origin-Opener-Policy")
        if not coop:
            missing.append("Cross-Origin-Opener-Policy")
            header_details["Cross-Origin-Opener-Policy"] = {"present": False, "site_type": site_type}
        else:
            header_details["Cross-Origin-Opener-Policy"] = {"present": True, "value": coop, "site_type": site_type}

        # Cross-Origin-Resource-Policy
        corp = headers.get("Cross-Origin-Resource-Policy")
        if not corp:
            missing.append("Cross-Origin-Resource-Policy")
            header_details["Cross-Origin-Resource-Policy"] = {"present": False, "site_type": site_type}
        else:
            header_details["Cross-Origin-Resource-Policy"] = {"present": True, "value": corp, "site_type": site_type}

        if missing or issues:
            # Context-aware severity calculation
            severity = self._calculate_header_severity(
                missing, issues, site_type, is_api, is_html, is_https, header_details
            )

            self.scanner.add_finding(make_finding(
                check_id="CORS-002",
                title="Missing or Weak Security Headers",
                severity=severity,
                category=Category.CORS_HEADERS,
                evidence_desc=(
                    f"Site type: {site_type}. "
                    f"Missing headers: {', '.join(missing) if missing else 'None'}. "
                    f"Issues: {', '.join(issues) if issues else 'None'}"
                ),
                fix=self._generate_header_fix(missing, issues, site_type, is_api, is_html, is_https),
                references=["https://owasp.org/www-project-secure-headers-project/"],
                raw_data={
                    "missing": missing,
                    "issues": issues,
                    "header_details": header_details,
                    "site_type": site_type,
                    "is_api": is_api,
                    "is_html": is_html,
                    "is_https": is_https,
                },
                confidence=Confidence.LOW,
                evidence_type=EvidenceType.INDICATOR,
                exploitability=Exploitability.THEORETICAL,
                context={
                    "check_type": "security_header_analysis",
                    "site_classification": site_type,
                    "target_protocol": "https" if is_https else "http",
                },
            ))

    def _classify_site_type(self, resp, headers, content_type: str) -> str:
        """Classify the target site type for context-aware severity."""
        # Check for API indicators
        if "application/json" in content_type or "application/xml" in content_type:
            return "api"

        # Check for SPA indicators
        if "text/html" in content_type:
            html = resp.text.lower()
            # Common SPA patterns
            if any(pattern in html for pattern in ["<script src=", "webpack", "vite", "next.js", "nuxt", "react", "vue", "angular", "__NEXT_DATA__"]):
                return "spa"
            # Traditional server-rendered app
            if "<form" in html or "csrf" in html or "token" in html:
                return "traditional_web_app"
            # Static site
            if len(html) < 5000 and not any(p in html for p in ["<script", "<form", "login", "register"]):
                return "static"
            return "traditional_web_app"

        # Default
        return "unknown"

    def _calculate_header_severity(
        self, missing: list, issues: list, site_type: str,
        is_api: bool, is_html: bool, is_https: bool, header_details: dict
    ) -> Severity:
        """Calculate context-aware severity for missing/weak security headers."""

        # Static sites or unknown - lowest severity
        if site_type in ("static", "unknown"):
            return Severity.INFO

        # API endpoints - different header priorities
        if site_type == "api" or is_api:
            # CSP less critical for APIs, HSTS important if HTTPS
            if is_https and "Strict-Transport-Security (HSTS)" in missing:
                return Severity.MEDIUM
            return Severity.LOW

        # SPA - CSP is critical, HSTS important if HTTPS
        if site_type == "spa":
            if is_https and "Strict-Transport-Security (HSTS)" in missing:
                return Severity.HIGH
            if "Content-Security-Policy" in missing:
                return Severity.HIGH
            if issues:  # unsafe CSP
                return Severity.MEDIUM
            return Severity.MEDIUM

        # Traditional web app - all headers matter
        if site_type == "traditional_web_app":
            critical_missing = []
            if is_https:
                critical_missing.append("Strict-Transport-Security (HSTS)")
            critical_missing.append("Content-Security-Policy")
            critical_missing.append("X-Frame-Options")

            if any(h in missing for h in critical_missing):
                return Severity.HIGH
            if issues:  # unsafe directives
                return Severity.MEDIUM
            return Severity.MEDIUM

        return Severity.LOW

    def _generate_header_fix(
        self, missing: list, issues: list, site_type: str,
        is_api: bool, is_html: bool, is_https: bool
    ) -> str:
        """Generate context-aware remediation guidance."""
        fixes = []

        if "Content-Security-Policy" in missing:
            if site_type == "api":
                fixes.append("CSP is optional for JSON APIs but recommended for defense-in-depth")
            else:
                fixes.append("Implement CSP: start with 'default-src self; script-src self' and refine")

        if "Strict-Transport-Security (HSTS)" in missing and is_https:
            fixes.append("Add HSTS header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'")

        if "X-Frame-Options" in missing:
            fixes.append("Set X-Frame-Options: DENY (or SAMEORIGIN if framing is required)")

        if "X-Content-Type-Options (nosniff)" in missing:
            fixes.append("Add X-Content-Type-Options: nosniff")

        if "Referrer-Policy" in missing:
            fixes.append("Add Referrer-Policy: strict-origin-when-cross-origin")

        if "Permissions-Policy" in missing:
            fixes.append("Add Permissions-Policy with minimal required features")

        if "Cross-Origin-Opener-Policy" in missing and site_type != "api":
            fixes.append("Consider COOP: same-origin for cross-origin isolation")

        if "Cross-Origin-Resource-Policy" in missing:
            fixes.append("Add CORP header for sensitive resources")

        if issues:
            fixes.append("Fix CSP unsafe directives: remove 'unsafe-inline'/'unsafe-eval', use nonces/hashes")

        return " | ".join(fixes) if fixes else "All critical headers present"