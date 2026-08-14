from __future__ import annotations

import time
from collections.abc import Callable, Iterable
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

    # All check IDs implemented by the scanner, used to validate --exclude-checks
    KNOWN_CHECK_IDS: ClassVar[frozenset[str]] = frozenset({
        "AUTH-001",
        "RATE-001",
        "ENUM-001",
        "COOKIE-001", "COOKIE-002", "COOKIE-003",
        "CORS-001", "CORS-002",
        "JWT-001", "JWT-003", "JWT-004",
    })

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
        exclude_checks: Iterable[str] | None = None,
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
        self.excluded_checks: set[str] = {
            check_id.strip().upper()
            for check_id in (exclude_checks or [])
            if check_id.strip()
        }
        self.result = ScanResult(target=target)
        self._scan_start_time: float | None = None

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

    def is_check_excluded(self, check_id: str) -> bool:
        """Return True if the given check ID was excluded for this scan."""
        return check_id.upper() in self.excluded_checks

    def get_check_categories(self) -> list[tuple[str, Any, frozenset[str]]]:
        """Return ordered check categories as (label, module, check_ids) tuples."""
        return [
            ("Authentication checks", self.auth_checks, frozenset({"AUTH-001"})),
            ("Rate limiting checks", self.rate_limit_checks, frozenset({"RATE-001"})),
            ("User enumeration checks", self.enum_checks, frozenset({"ENUM-001"})),
            ("Session cookie checks", self.cookie_checks,
             frozenset({"COOKIE-001", "COOKIE-002", "COOKIE-003"})),
            ("CORS & security header checks", self.cors_checks,
             frozenset({"CORS-001", "CORS-002"})),
            ("JWT checks", self.jwt_checks,
             frozenset({"JWT-001", "JWT-003", "JWT-004"})),
        ]

    def scan(
        self,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> ScanResult:
        """Execute full scan and return results.

        Args:
            progress_callback: Optional callable invoked before each check
                category runs, with (category_label, category_index, total).
        """
        self._scan_start_time = time.time()
        print(f"[*] Starting scan on {self.target}")
        if self.excluded_checks:
            print(f"[*] Excluded checks: {', '.join(sorted(self.excluded_checks))}")

        categories = self.get_check_categories()
        total_categories = len(categories)

        try:
            for index, (label, module, check_ids) in enumerate(categories, start=1):
                if progress_callback:
                    progress_callback(label, index, total_categories)
                if check_ids and check_ids <= self.excluded_checks:
                    self.log(f"Skipping {label.lower()} (all checks excluded)")
                    continue
                self.log(f"Running {label.lower()}...")
                module.run_all()

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:  # noqa: BLE001 - top-level scan error handler
            print(f"[!] Scan error: {e}")
        finally:
            self.client.close()
            if self._scan_start_time:
                self.result.scan_duration = time.time() - self._scan_start_time

        print(f"[*] Scan completed in {self.result.scan_duration:.2f}s")
        if self.excluded_checks:
            print(f"[*] Skipped excluded checks: {', '.join(sorted(self.excluded_checks))}")
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

    def get_relevant_endpoints(self, category: str) -> list[str]:
        """Get endpoints relevant to a check category."""
        # Override in subclasses or checks as needed
        return self.endpoints