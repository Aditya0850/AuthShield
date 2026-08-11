from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Severity


class RateLimitChecks:
    """Rate limiting checks.

    Uses SAFE, LIMITED request counts.
    Methodology: 5 rapid requests, observes if 429 received.
    Does NOT hammer endpoints or test lockout duration.
    """

    MAX_TEST_REQUESTS = 5  # Conservative: 5 requests to detect basic rate limiting
    REQUEST_DELAY = 0.1    # 100ms between requests

    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_missing_rate_limit()

    def check_missing_rate_limit(self):
        """RATE-001: Check for missing rate limiting on auth endpoints.

        Methodology:
        - Sends 5 rapid failed login attempts to each endpoint
        - If NO 429 response after 5 attempts, reports potential missing rate limit
        - Does NOT test lockout duration or bypasses
        """
        auth_endpoints = ["/login", "/signin", "/register", "/signup"]

        for endpoint in auth_endpoints:
            blocked = False
            responses = []

            # Send limited rapid requests
            for i in range(self.MAX_TEST_REQUESTS):
                # Try JSON first (modern APIs), fall back to form data
                resp = self.scanner.make_request("POST", endpoint, json={
                    "username": f"ratetest{i}", "password": "wrongpassword"
                })
                # If 415 (Unsupported Media Type), try form-encoded
                if resp is not None and resp.status_code == 415:
                    resp = self.scanner.make_request("POST", endpoint, data={
                        "username": f"ratetest{i}", "password": "wrongpassword"
                    })
                if resp is not None:
                    responses.append({
                        "attempt": i + 1,
                        "status": resp.status_code,
                    })
                    if resp.status_code == 429:
                        blocked = True
                        break
                else:
                    responses.append({
                        "attempt": i + 1,
                        "status": "error",
                    })
                    break
                time.sleep(self.REQUEST_DELAY)

            if not blocked:
                # No rate limiting detected after 5 attempts
                statuses = [r["status"] for r in responses if isinstance(r["status"], int)]
                # Accept 401, 400, 403, 415, 422 as "valid responses" (not server errors)
                valid_statuses = (200, 201, 400, 401, 403, 415, 422)
                all_ok = all(s in valid_statuses for s in statuses)

                if all_ok and len(statuses) == self.MAX_TEST_REQUESTS:
                    self.scanner.add_finding(make_finding(
                        check_id="RATE-001",
                        title="Missing Rate Limiting on Authentication Endpoint",
                        severity=Severity.HIGH,
                        category=Category.RATE_LIMITING,
                        evidence_desc=(
                            f"Endpoint {endpoint} accepted {self.MAX_TEST_REQUESTS} "
                            f"rapid failed login attempts without returning 429. "
                            f"Status codes: {statuses}"
                        ),
                        fix=(
                            "Implement rate limiting: max 5 attempts per minute per IP/account. "
                            "Return 429 with Retry-After header. Use exponential backoff."
                        ),
                        references=["https://owasp.org/www-project-authentication-cheat-sheet/"],
                        raw_data={
                            "endpoint": endpoint,
                            "methodology": f"{self.MAX_TEST_REQUESTS} rapid POST requests (JSON + form fallback)",
                            "responses": responses,
                        },
                    ))