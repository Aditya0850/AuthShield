from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Confidence, EvidenceType, Exploitability, Severity


class AuthChecks:
    """Authentication security checks.

    Only performs SAFE, PASSIVE checks.
    Does NOT attempt to create accounts or brute-force passwords.
    """

    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_weak_password_policy()
        # MFA detection removed - cannot reliably detect from black-box
        # Default credentials removed - IS credential stuffing

    def check_weak_password_policy(self):
        """AUTH-001: Check for weak password policy indicators on registration pages.

        Only examines REGISTRATION pages for client-side password requirements.
        Does NOT submit passwords - that would be account creation/testing.
        """
        registration_endpoints = ["/register", "/signup", "/auth/register", "/api/register"]

        for endpoint in registration_endpoints:
            resp = self.scanner.make_request("GET", endpoint)
            if not resp or resp.status_code >= 400:
                continue

            content = resp.text.lower()

            # Look for explicit weak password requirements in page text
            # e.g., "minimum 6 characters", "at least 4 chars", "minlength=4"
            weak_patterns = [
                (r"minimum\s+[0-5]\s*(character|char)", "minimum X characters where X <= 5"),
                (r"at\s+least\s+[0-5]\s*(character|char)", "at least X characters where X <= 5"),
                (r"minlength\s*[:=]\s*[0-5](?!\d)", "minlength attribute <= 5"),
                (r"min-length\s*[:=]\s*[0-5](?!\d)", "min-length attribute <= 5"),
                (r"password\s+.{0,20}?\b[0-5]\b\s*(character|char)", "password requirement <= 5 characters"),
                (r"between\s+[0-5]\s+and", "length range starting <= 5"),
            ]

            for pattern, description in weak_patterns:
                if re.search(pattern, content):
                    self.scanner.add_finding(make_finding(
                        check_id="AUTH-001",
                        title="Weak Password Policy Indicator",
                        severity=Severity.MEDIUM,
                        category=Category.AUTHENTICATION,
                        evidence_desc=f"Registration page {endpoint} contains weak password requirement: {description}",
                        fix="Enforce minimum 12-character passwords with complexity requirements. "
                            "Show real-time strength meter. Reject common passwords.",
                        references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                        raw_data={"endpoint": endpoint, "pattern": pattern, "description": description},
                        response=content[:500],
                        confidence=Confidence.LOW,
                        evidence_type=EvidenceType.INDICATOR,
                        exploitability=Exploitability.THEORETICAL,
                        context={"check_type": "passive_content_analysis"},
                    ))
                    return  # Only report once per scan