from __future__ import annotations

import time
import random
from typing import Optional, Dict, Any, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from authshield.core.models import Finding, Severity, Category, Evidence


class HTTPClient:
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        user_agent: str = "AuthShield/0.1.0",
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        start_time = time.time()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", True)
        kwargs.setdefault("allow_redirects", True)

        try:
            response = self.session.request(method, url, **kwargs)
            response.elapsed_time = time.time() - start_time
            return response
        except requests.RequestException as e:
            raise HTTPClientError(f"Request failed: {str(e)}") from e

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


class HTTPClientError(Exception):
    pass


def make_finding(
    check_id: str,
    title: str,
    severity: Severity,
    category: Category,
    evidence_desc: str,
    fix: str,
    references: Optional[List[str]] = None,
    raw_data: Optional[Dict[str, Any]] = None,
    request: Optional[str] = None,
    response: Optional[str] = None,
    cvss_score: Optional[float] = None,
) -> Finding:
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