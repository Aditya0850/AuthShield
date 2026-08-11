from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Severity


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
        - Reports only if DIFFERENT responses for valid vs invalid users
        """
        responses = {}

        for username in self.TEST_USERNAMES:
            resp = self.scanner.make_request("POST", "/login", data={
                "username": username, "password": "wrongpassword123"
            })
            if not resp:
                return  # Network issue - abort cleanly

            responses[username] = {
                "status": resp.status_code,
                "length": len(resp.text),
                "content": resp.text[:500],
            }

        if len(responses) < 2:
            return

        # Extract error signature from each response
        signatures = {}
        for user, data in responses.items():
            content = data["content"].lower()
            # Create a signature: status + normalized error message
            error_sig = self._extract_error_signature(content, data["status"])
            signatures[user] = error_sig

        # Check if known-invalid user has different signature than potential valid users
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
                ))
                return

    def _extract_error_signature(self, content: str, status: int) -> str:
        """Normalize error response into a comparable signature."""
        # Extract the core error message
        error_msg = "no_error"
        if "invalid" in content or "incorrect" in content or "wrong" in content:
            import re
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
        return f"{status}:{error_msg}"