from __future__ import annotations

from typing import List, Dict, Any, Optional, Callable
import time
from urllib.parse import urljoin, urlparse

from authshield.core.models import Finding, ScanResult, Severity, Category
from authshield.core.http_client import HTTPClient, HTTPClientError
from authshield.checks.auth import AuthChecks
from authshield.checks.rate_limit import RateLimitChecks
from authshield.checks.enum import EnumChecks
from authshield.checks.cookies import CookieChecks
from authshield.checks.cors import CORSChecks
from authshield.checks.jwt import JWTChecks


class Scanner:
    def __init__(
        self,
        target: str,
        endpoints: Optional[List[str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.endpoints = endpoints or [
            "/login", "/signin", "/auth/login", "/api/login",
            "/register", "/signup", "/auth/register", "/api/register",
            "/password/reset", "/forgot-password", "/api/password/reset",
        ]
        self.client = HTTPClient(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            verify_ssl=verify_ssl,
        )
        self.verbose = verbose
        self.result = ScanResult(target=target)
        self._checks: List[Callable] = []

        self._register_checks()

    def _register_checks(self):
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
        start_time = time.time()
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

        except Exception as e:
            print(f"[!] Scan error: {e}")
        finally:
            self.client.close()
            self.result.scan_duration = time.time() - start_time

        print(f"[*] Scan completed in {self.result.scan_duration:.2f}s")
        print(f"[*] Found {self.result.summary.total()} issues "
              f"(Critical: {self.result.summary.critical}, "
              f"High: {self.result.summary.high}, "
              f"Medium: {self.result.summary.medium}, "
              f"Low: {self.result.summary.low}, "
              f"Info: {self.result.summary.info})")

        return self.result

    def add_finding(self, finding: Finding):
        self.result.add_finding(finding)
        severity_color = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.HIGH: "[HIGH]",
            Severity.MEDIUM: "[MEDIUM]",
            Severity.LOW: "[LOW]",
            Severity.INFO: "[INFO]",
        }
        print(f"  {severity_color.get(finding.severity, '')} {finding.id}: {finding.title}")

    def get_full_url(self, endpoint: str) -> str:
        if endpoint.startswith("http"):
            return endpoint
        return urljoin(self.target + "/", endpoint.lstrip("/"))

    def make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Any]:
        url = self.get_full_url(endpoint)
        try:
            return getattr(self.client, method.lower())(url, **kwargs)
        except HTTPClientError as e:
            self.log(f"Request failed for {url}: {e}")
            return None