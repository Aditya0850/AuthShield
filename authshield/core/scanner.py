from __future__ import annotations

import time
from typing import Any, ClassVar
from urllib.parse import urljoin

from authshield.core.http_client import HTTPClient, HTTPClientError
from authshield.core.models import Finding, ScanResult, Severity


class Scanner:
    """Main scanner orchestration.

    Responsibilities:
    - Manage HTTP client lifecycle
    - Coordinate check modules
    - Aggregate findings
    - Handle scan-level errors
    """
    # Default auth-related endpoints to test - defined as class attribute
    DEFAULT_ENDPOINTS: ClassVar[list[str]] = [
        "/login", "/signin", "/auth/login", "/api/login",
        "/register", "/signup", "/auth/register", "/api/register",
        "/password/reset", "/forgot-password", "/api/password/reset",
    ]

    def __init__(
        self,
        target: str,
        endpoints: list[str] | None = None,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        verbose: bool = False,
        max_requests: int = 100,
        excluded_checks: list[str] | None = None,
    ):
        self.target = target.rstrip("/")
        self.endpoints = endpoints or self.DEFAULT_ENDPOINTS
        self.client = HTTPClient(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            verify_ssl=verify_ssl,
            max_requests=max_requests,
        )
        self.verbose = verbose
        self.result = ScanResult(target=target)
        self._scan_start_time: float | None = None
        self.excluded_checks = set(excluded_checks) if excluded_checks else set()

        # Initialize check modules - imports here to avoid circular imports
        from authshield.checks.auth import AuthChecks
        from authshield.checks.cookies import CookieChecks
        from authshield.checks.cors import CORSChecks
        from authshield.checks.enum import EnumChecks
        from authshield.checks.jwt import JWTChecks
        from authshield.checks.rate_limit import RateLimitChecks

        self.auth_checks = AuthChecks(self)
        self.rate_limit_checks = RateLimitChecks(self)
        self.enum_checks = EnumChecks(self)
        self.cookie_checks = CookieChecks(self)
        self.cors_checks = CORSChecks(self)
        self.jwt_checks = JWTChecks(self)

    def log(self, message: str):
        if self.verbose:
            print(f"  [+] {message}")

    def scan(self) -> ScanResult:
        """Execute full scan and return results."""
        self._scan_start_time = time.time()
        print(f"[*] Starting scan on {self.target}")

        try:
            self.log("Running authentication checks...")
            self.auth_checks.run_all()

            self.log("Running rate limiting checks...")
            self.rate_limit_checks.run_all()

            self.log("Running user enumeration checks...")
            self.enum_checks.run_all()

            self.log("Running session cookie checks...")
            self.cookie_checks.run_all()

            self.log("Running CORS & security header checks...")
            self.cors_checks.run_all()

            self.log("Running JWT checks...")
            self.jwt_checks.run_all()

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:  # noqa: BLE001 - top-level scan error handler
            print(f"[!] Scan error: {e}")
        finally:
            self.client.close()
            if self._scan_start_time:
                self.result.scan_duration = time.time() - self._scan_start_time

        print(f"[*] Scan completed in {self.result.scan_duration:.2f}s")
        print(f"[*] Found {self.result.summary.total()} issues "
              f"(Critical: {self.result.summary.critical}, "
              f"High: {self.result.summary.high}, "
              f"Medium: {self.result.summary.medium}, "
              f"Low: {self.result.summary.low}, "
              f"Info: {self.result.summary.info})")

        return self.result

    def add_finding(self, finding: Finding):
        """Add a finding and print summary."""
        self.result.add_finding(finding)
        severity_marker = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.HIGH: "[HIGH]",
            Severity.MEDIUM: "[MEDIUM]",
            Severity.LOW: "[LOW]",
            Severity.INFO: "[INFO]",
        }
        marker = severity_marker.get(finding.severity, "")
        if self.verbose or finding.severity in (Severity.CRITICAL, Severity.HIGH):
            print(f"  {marker} {finding.id}: {finding.title}")

    def get_full_url(self, endpoint: str) -> str:
        if endpoint.startswith("http"):
            return endpoint
        return urljoin(self.target + "/", endpoint.lstrip("/"))

    def make_request(self, method: str, endpoint: str, **kwargs) -> Any | None:
        """Make HTTP request with error handling."""
        url = self.get_full_url(endpoint)
        try:
            return getattr(self.client, method.lower())(url, **kwargs)
        except HTTPClientError as e:
            self.log(f"Request failed for {url}: {e}")
            return None

    def is_check_excluded(self, check_id: str) -> bool:
        """Check if a check ID is in the excluded list."""
        return check_id in self.excluded_checks

    def get_relevant_endpoints(self, category: str) -> list[str]:
        """Get endpoints relevant to a check category."""
        # Override in subclasses or checks as needed
        return self.endpoints