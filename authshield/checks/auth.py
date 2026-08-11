from __future__ import annotations

from typing import List, Dict, Any, Optional, TYPE_CHECKING
import re

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.models import Finding, Severity, Category
from authshield.core.http_client import make_finding


class AuthChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_weak_password_policy()
        self.check_missing_mfa()
        self.check_default_credentials()

    def check_weak_password_policy(self):
        """AUTH-001: Check for weak password policies"""
        for endpoint in ["/login", "/signin", "/register", "/signup"]:
            resp = self.scanner.make_request("GET", endpoint)
            if not resp:
                continue

            # Check for password requirements in page content
            content = resp.text.lower()
            weak_indicators = [
                "minlength", "min-length", "minimum.*[0-7]",
                "at least.*[0-7]", "password.*[0-7].*character"
            ]

            for indicator in weak_indicators:
                if re.search(indicator, content):
                    self.scanner.add_finding(make_finding(
                        check_id="AUTH-001",
                        title="Weak Password Policy Detected",
                        severity=Severity.HIGH,
                        category=Category.AUTHENTICATION,
                        evidence_desc=f"Page at {endpoint} suggests weak password requirements",
                        fix="Enforce minimum 12-character passwords with complexity requirements (uppercase, lowercase, numbers, special chars)",
                        references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                        raw_data={"endpoint": endpoint, "indicator": indicator},
                        response=content[:500],
                    ))
                    return

            # Try to submit weak password
            resp = self.scanner.make_request("POST", endpoint, data={
                "username": "test", "password": "123", "email": "test@test.com"
            })
            if resp and resp.status_code == 200:
                if "weak" not in resp.text.lower() and "short" not in resp.text.lower():
                    self.scanner.add_finding(make_finding(
                        check_id="AUTH-001",
                        title="Weak Password Policy - Accepts Short Passwords",
                        severity=Severity.HIGH,
                        category=Category.AUTHENTICATION,
                        evidence_desc=f"Endpoint {endpoint} accepted a 3-character password",
                        fix="Enforce minimum 12-character passwords with complexity requirements",
                        references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                        raw_data={"endpoint": endpoint, "test_password": "123"},
                    ))
                    return

    def check_missing_mfa(self):
        """AUTH-002: Check for missing Multi-Factor Authentication"""
        for endpoint in ["/login", "/signin", "/account", "/profile", "/settings"]:
            resp = self.scanner.make_request("GET", endpoint)
            if not resp:
                continue

            content = resp.text.lower()
            mfa_keywords = ["2fa", "two-factor", "multi-factor", "mfa", "authenticator",
                           "totp", "google authenticator", "authy", "backup codes"]

            has_mfa = any(kw in content for kw in mfa_keywords)

            if not has_mfa and ("login" in endpoint or "signin" in endpoint):
                self.scanner.add_finding(make_finding(
                    check_id="AUTH-002",
                    title="Missing Multi-Factor Authentication",
                    severity=Severity.MEDIUM,
                    category=Category.AUTHENTICATION,
                    evidence_desc=f"No MFA/2FA options detected on authentication page {endpoint}",
                    fix="Implement TOTP-based MFA with backup codes. Support authenticator apps (Google Authenticator, Authy, etc.)",
                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                    raw_data={"endpoint": endpoint},
                ))
                return

    def check_default_credentials(self):
        """AUTH-003: Check for common default credentials"""
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
            ("test", "test"), ("user", "user"), ("guest", "guest"),
            ("admin", ""), ("", "admin"),
        ]

        for endpoint in ["/login", "/signin", "/admin", "/administrator"]:
            for username, password in default_creds[:5]:  # Limit attempts
                resp = self.scanner.make_request("POST", endpoint, data={
                    "username": username, "password": password
                })
                if resp and resp.status_code == 200:
                    if "logout" in resp.text.lower() or "dashboard" in resp.text.lower() or "welcome" in resp.text.lower():
                        self.scanner.add_finding(make_finding(
                            check_id="AUTH-003",
                            title="Default Credentials Work",
                            severity=Severity.CRITICAL,
                            category=Category.AUTHENTICATION,
                            evidence_desc=f"Default credentials '{username}:{password}' work on {endpoint}",
                            fix="Change all default credentials immediately. Enforce password change on first login.",
                            references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "username": username, "password": password},
                        ))
                        return