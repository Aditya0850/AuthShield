from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Confidence, EvidenceType, Exploitability, Severity


class EnumChecks:
    """Username enumeration checks.

    Only uses SAFE methods:
    - Error message comparison (passive observation of responses)
    - HTTP status code analysis
    - Response length/timing NOT used (unreliable over network)
    """

    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client
        # Common usernames to test - small, controlled set
        self.TEST_USERNAMES: list[str] = [
            "admin",
            "administrator",
            "test",
            "user",
            "nonexistentuser12345",  # Known invalid
        ]

    def run_all(self):
        self.check_username_enumeration_error_messages()
        # Timing attack removed - unreliable over network, high false positive rate

    def check_username_enumeration_error_messages(self):
        """ENUM-001: Username enumeration via error message/status differences.

        Methodology:
        - Submits same wrong password for multiple usernames
        - Compares HTTP status codes AND error message content
        - Reports if DIFFERENT responses for valid vs invalid users
        - Also detects when error messages REFLECT the username back (enumeration vector)
        """
        responses = {}

        for username in self.TEST_USERNAMES:
            resp = self.scanner.make_request("POST", "/login", json={
                "username": username, "password": "wrongpassword123"
            })
            # If 415, try form-encoded
            if resp is not None and resp.status_code == 415:
                resp = self.scanner.make_request("POST", "/login", data={
                    "username": username, "password": "wrongpassword123"
                })
            if resp is None:
                return  # Network issue - abort cleanly

            responses[username] = {
                "status": resp.status_code,
                "length": len(resp.text),
                "content": resp.text[:500],
            }

        if len(responses) < 2:
            return

        # Check 1: Different status codes or error signatures for different users
        signatures = {}
        for user, data in responses.items():
            content = data["content"].lower()
            error_sig = self._extract_error_signature(content, data["status"])
            signatures[user] = error_sig

        invalid_sig = signatures.get("nonexistentuser12345")
        if not invalid_sig:
            return

        for user, sig in signatures.items():
            if user == "nonexistentuser12345":
                continue
            if sig != invalid_sig:
                # Different response for this user vs known-invalid
                self.scanner.add_finding(make_finding(
                    check_id="ENUM-001",
                    title="Username Enumeration via Response Differences",
                    severity=Severity.MEDIUM,
                    category=Category.USER_ENUMERATION,
                    evidence_desc=(
                        f"Different response for '{user}' vs known-invalid username. "
                        f"Invalid sig: {invalid_sig}, User sig: {sig}. "
                        f"This allows username enumeration."
                    ),
                    fix=(
                        "Use identical generic error messages and HTTP status codes "
                        "for all failed login attempts (e.g., 'Invalid username or password', 401)."
                    ),
                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                    raw_data={"signatures": signatures, "methodology": "status + error content comparison"},
                    confidence=Confidence.MEDIUM,
                    evidence_type=EvidenceType.BEHAVIORAL,
                    exploitability=Exploitability.LIKELY,
                    context={"check_type": "error_signature_comparison"},
                ))
                return

        # Check 2: Error messages REFLECT the username back (enumeration via reflection)
        # Even if status codes match, if the error message includes the submitted username,
        # that's an enumeration vector
        for user, data in responses.items():
            if user == "nonexistentuser12345":
                continue
            content = data["content"].lower()
            # Check if the username appears in the error message
            if user.lower() in content and "not found" in content:
                # Found reflection: error message says "User not found: {username}"
                self.scanner.add_finding(make_finding(
                    check_id="ENUM-001",
                    title="Username Enumeration via Error Message Reflection",
                    severity=Severity.MEDIUM,
                    category=Category.USER_ENUMERATION,
                    evidence_desc=(
                        f"Error message for failed login reflects the submitted username: "
                        f"'{user}' appears in response. This allows username enumeration."
                    ),
                    fix=(
                        "Use identical generic error messages for all failed login attempts. "
                        "Never include the submitted username in error responses."
                    ),
                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                    raw_data={"reflected_username": user, "methodology": "username reflection in error message"},
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.PROOF,
                    exploitability=Exploitability.PROVEN,
                    context={"check_type": "username_reflection_detection"},
                ))
                return

    def _extract_error_signature(self, content: str, status: int) -> str:
        """Normalize error response into a comparable signature."""
        # Extract the core error message
        error_msg = "no_error"
        if "invalid" in content or "incorrect" in content or "wrong" in content:
            match = re.search(r'(invalid|incorrect|wrong)[^.]*?(username|user|email|password|credential)', content)
            if match:
                # Normalize: replace specifics with placeholders
                error_msg = match.group(0)
                error_msg = re.sub(r'\b\w{4,}\b', '<value>', error_msg)
            else:
                error_msg = "generic_auth_error"
        elif "rate" in content or "limit" in content:
            error_msg = "rate_limit"
        elif "captcha" in content:
            error_msg = "captcha"
        elif "not found" in content:
            # Normalize "user not found: <username>" to just "user not found"
            error_msg = "user_not_found"
        return f"{status}:{error_msg}"