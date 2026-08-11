from __future__ import annotations

import time
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.models import Finding, Severity, Category
from authshield.core.http_client import make_finding


class RateLimitChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_missing_rate_limit()
        self.check_weak_rate_limit()

    def check_missing_rate_limit(self):
        """RATE-001: Check for missing rate limiting on auth endpoints"""
        for endpoint in ["/login", "/signin", "/register", "/signup", "/password/reset", "/forgot-password"]:
            # Make rapid requests
            blocked = False
            for i in range(15):
                resp = self.scanner.make_request("POST", endpoint, data={
                    "username": f"test{i}", "password": "wrongpassword"
                })
                if resp and resp.status_code == 429:
                    blocked = True
                    break
                time.sleep(0.1)

            if not blocked:
                self.scanner.add_finding(make_finding(
                    check_id="RATE-001",
                    title="Missing Rate Limiting on Authentication Endpoint",
                    severity=Severity.HIGH,
                    category=Category.RATE_LIMITING,
                    evidence_desc=f"Endpoint {endpoint} allowed 15 rapid failed login attempts without rate limiting",
                    fix="Implement rate limiting: max 5 attempts per minute per IP/account. Use exponential backoff.",
                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                    raw_data={"endpoint": endpoint, "attempts": 15},
                ))
                return

    def check_weak_rate_limit(self):
        """RATE-002: Check for weak rate limiting configuration"""
        for endpoint in ["/login", "/signin"]:
            # Test if rate limit resets too quickly or is too generous
            for i in range(10):
                resp = self.scanner.make_request("POST", endpoint, data={
                    "username": f"ratetest{i}", "password": "wrong"
                })
                if resp and resp.status_code == 429:
                    # Check headers for rate limit info
                    retry_after = resp.headers.get("Retry-After")
                    x_rate_limit = resp.headers.get("X-RateLimit-Limit") or resp.headers.get("RateLimit-Limit")

                    if retry_after:
                        try:
                            wait_time = int(retry_after)
                            if wait_time < 60:
                                self.scanner.add_finding(make_finding(
                                    check_id="RATE-002",
                                    title="Weak Rate Limiting - Short Lockout Duration",
                                    severity=Severity.MEDIUM,
                                    category=Category.RATE_LIMITING,
                                    evidence_desc=f"Rate limit lockout only {wait_time} seconds on {endpoint}",
                                    fix="Increase lockout duration to at least 15 minutes after 5 failed attempts",
                                    references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                                    raw_data={"endpoint": endpoint, "retry_after": wait_time},
                                ))
                        except ValueError:
                            pass
                    break
                time.sleep(0.1)