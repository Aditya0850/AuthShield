from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Severity


class CORSChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_cors_policy()
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

                if resp:
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
                        ))
                        return

    def check_security_headers(self):
        """CORS-002: Check for missing security headers"""
        resp = self.scanner.make_request("GET", "/")
        if not resp:
            return

        headers = resp.headers
        missing = []
        issues = []

        # CSP
        csp = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only")
        if not csp:
            missing.append("Content-Security-Policy")
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            issues.append(f"CSP contains unsafe directives: {csp}")

        # HSTS
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            missing.append("Strict-Transport-Security (HSTS)")
        elif "max-age" not in hsts.lower():
            issues.append(f"HSTS missing max-age: {hsts}")

        # X-Frame-Options
        xfo = headers.get("X-Frame-Options")
        if not xfo:
            missing.append("X-Frame-Options")
        elif xfo.upper() not in ["DENY", "SAMEORIGIN"]:
            issues.append(f"X-Frame-Options has weak value: {xfo}")

        # X-Content-Type-Options
        xcto = headers.get("X-Content-Type-Options")
        if not xcto or xcto.lower() != "nosniff":
            missing.append("X-Content-Type-Options (nosniff)")

        # Referrer-Policy
        rp = headers.get("Referrer-Policy")
        if not rp:
            missing.append("Referrer-Policy")

        # Permissions-Policy
        pp = headers.get("Permissions-Policy")
        if not pp:
            missing.append("Permissions-Policy")

        # Cross-Origin-Opener-Policy
        coop = headers.get("Cross-Origin-Opener-Policy")
        if not coop:
            missing.append("Cross-Origin-Opener-Policy")

        # Cross-Origin-Resource-Policy
        corp = headers.get("Cross-Origin-Resource-Policy")
        if not corp:
            missing.append("Cross-Origin-Resource-Policy")

        if missing or issues:
            severity = Severity.HIGH if "Content-Security-Policy" in missing or "Strict-Transport-Security" in missing else Severity.MEDIUM
            self.scanner.add_finding(make_finding(
                check_id="CORS-002",
                title="Missing or Weak Security Headers",
                severity=severity,
                category=Category.CORS_HEADERS,
                evidence_desc=f"Missing headers: {', '.join(missing) if missing else 'None'}. Issues: {', '.join(issues) if issues else 'None'}",
                fix="Implement all security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP",
                references=["https://owasp.org/www-project-secure-headers-project/"],
                raw_data={"missing": missing, "issues": issues},
            ))