from __future__ import annotations

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from authshield.core.models import Category, Evidence, Finding, Severity


class HTTPClient:
    """Conservative HTTP client for security scanning.

    Features:
    - Strict request limits per session
    - No redirects on state-changing methods
    - Conservative timeouts
    - Connection pooling limits
    - Request counting for safety
    """

    # Safety limits
    MAX_REQUESTS_PER_SESSION = 100
    MAX_RETRIES = 2
    DEFAULT_TIMEOUT = 10
    CONNECT_TIMEOUT = 5

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        backoff_factor: float = 0.5,
        user_agent: str = "AuthShield/0.1.0 (+https://github.com/Aditya0850/AuthShield)",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,  # Safe default: no redirects on POST
        verify_ssl: bool = True,
        max_requests: int = MAX_REQUESTS_PER_SESSION,
    ):
        self.timeout = timeout
        self.max_retries = max_retries  # Store for testing/inspection
        self.max_requests = max_requests
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        # Conservative retry strategy - only on safe methods and specific codes
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 502, 503, 504],  # Removed 500 - might be app error
            allowed_methods=["HEAD", "GET", "OPTIONS"],  # No retry on POST/PUT/DELETE
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=5,
            pool_maxsize=5,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _check_request_budget(self) -> None:
        """Enforce request limit to prevent abuse."""
        if self.request_count >= self.max_requests:
            raise HTTPClientError(
                f"Request limit ({self.max_requests}) reached. "
                "Scan aborted for safety."
            )
        self.request_count += 1

    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """Make HTTP request with safety checks."""
        self._check_request_budget()

        # No redirects on state-changing methods
        if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
            kwargs.setdefault("allow_redirects", False)
        else:
            kwargs.setdefault("allow_redirects", True)

        kwargs.setdefault("timeout", (self.CONNECT_TIMEOUT, self.timeout))
        kwargs.setdefault("verify", True)

        start_time = time.time()
        try:
            response = self.session.request(method, url, **kwargs)
            # Attach timing for analysis
            response.elapsed_time = time.time() - start_time  # type: ignore[attr-defined]
            return response
        except requests.Timeout:
            raise HTTPClientError(f"Request timeout after {self.timeout}s") from None
        except requests.TooManyRedirects:
            raise HTTPClientError("Too many redirects") from None
        except requests.RequestException as e:
            raise HTTPClientError(f"Request failed: {e!s}") from e

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def close(self):
        self.session.close()

    @property
    def requests_remaining(self) -> int:
        return max(0, self.max_requests - self.request_count)


class HTTPClientError(Exception):
    """HTTP client error - safe to display to user."""


def make_finding(
    check_id: str,
    title: str,
    severity: Severity,
    category: Category,
    evidence_desc: str,
    fix: str,
    references: list[str] | None = None,
    raw_data: dict[str, Any] | None = None,
    request: str | None = None,
    response: str | None = None,
    cvss_score: float | None = None,
) -> Finding:
    """Factory for creating Finding objects with consistent structure."""
    return Finding(
        id=check_id,
        title=title,
        severity=severity,
        category=category,
        evidence=Evidence(
            description=evidence_desc,
            raw_data=raw_data,
            request=request,
            response=response,
        ),
        fix=fix,
        references=references or [],
        cvss_score=cvss_score,
    )