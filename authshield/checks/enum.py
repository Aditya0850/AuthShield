from __future__ import annotations

import time
import statistics
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.models import Finding, Severity, Category
from authshield.core.http_client import make_finding


class EnumChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_username_enumeration_error_messages()
        self.check_username_enumeration_timing()

    def check_username_enumeration_error_messages(self):
        """ENUM-001: Username enumeration via error message differences"""
        test_users = ["admin", "administrator", "test", "user", "john", "jane", "nonexistentuser12345"]

        responses = {}
        for user in test_users:
            resp = self.scanner.make_request("POST", "/login", data={
                "username": user, "password": "wrongpassword123"
            })
            if resp:
                responses[user] = {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "content": resp.text[:500]
                }
            time.sleep(0.1)

        if len(responses) < 2:
            return

        # Check for different error messages for valid vs invalid users
        error_messages = {}
        for user, data in responses.items():
            # Extract error message from response
            content = data["content"].lower()
            # Common error patterns
            if "invalid" in content or "incorrect" in content or "wrong" in content:
                # Try to extract the actual error message
                import re
                error_match = re.search(r'(invalid|incorrect|wrong).*?(username|user|email|password|credentials)', content)
                if error_match:
                    error_messages[user] = error_match.group(0)
                else:
                    error_messages[user] = "generic_error"
            else:
                error_messages[user] = "no_error"

        # Check if different users get different error messages
        unique_errors = set(error_messages.values())
        if len(unique_errors) > 1:
            self.scanner.add_finding(make_finding(
                check_id="ENUM-001",
                title="Username Enumeration via Error Messages",
                severity=Severity.MEDIUM,
                category=Category.USER_ENUMERATION,
                evidence_desc=f"Different error messages returned for different usernames: {error_messages}",
                fix="Use generic error messages like 'Invalid username or password' for all failed login attempts",
                references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                raw_data={"error_messages": error_messages},
            ))

    def check_username_enumeration_timing(self):
        """ENUM-002: Username enumeration via timing attacks"""
        valid_user = "admin"  # Common username
        invalid_user = "nonexistentuser123456789"

        # Measure response times for valid username (wrong password)
        valid_times = []
        for _ in range(5):
            start = time.time()
            resp = self.scanner.make_request("POST", "/login", data={
                "username": valid_user, "password": "wrongpassword"
            })
            valid_times.append(time.time() - start)
            time.sleep(0.2)

        # Measure response times for invalid username
        invalid_times = []
        for _ in range(5):
            start = time.time()
            resp = self.scanner.make_request("POST", "/login", data={
                "username": invalid_user, "password": "wrongpassword"
            })
            invalid_times.append(time.time() - start)
            time.sleep(0.2)

        if valid_times and invalid_times:
            avg_valid = statistics.mean(valid_times)
            avg_invalid = statistics.mean(invalid_times)

            # If valid user takes significantly longer (password hashing), might indicate user exists
            if avg_valid > avg_invalid * 1.5 and avg_valid > 0.5:
                self.scanner.add_finding(make_finding(
                    check_id="ENUM-002",
                    title="Potential Username Enumeration via Timing Attack",
                    severity=Severity.MEDIUM,
                    category=Category.USER_ENUMERATION,
                    evidence_desc=f"Valid username avg response: {avg_valid:.3f}s, Invalid username avg: {avg_invalid:.3f}s",
                    fix="Use constant-time comparison for password verification. Hash passwords for non-existent users too.",
                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                    raw_data={"valid_avg": avg_valid, "invalid_avg": avg_invalid, "ratio": avg_valid/avg_invalid if avg_invalid > 0 else 0},
                ))