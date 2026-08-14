from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Severity


class CookieChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        if not self.scanner.is_check_excluded("COOKIE-001"):
            self.check_secure_flag()
        if not self.scanner.is_check_excluded("COOKIE-002"):
            self.check_httponly_flag()
        if not self.scanner.is_check_excluded("COOKIE-003"):
            self.check_samesite_attribute()

    def check_secure_flag(self):
        """COOKIE-001: Check for missing Secure flag on session cookies"""
        resp = self.scanner.make_request("GET", "/")
        if not resp:
            return

        cookies = resp.cookies
        for cookie in cookies:
            if not cookie.secure and self._is_session_cookie(cookie.name):
                    self.scanner.add_finding(make_finding(
                        check_id="COOKIE-001",
                        title="Missing Secure Flag on Session Cookie",
                        severity=Severity.HIGH,
                        category=Category.SESSION,
                        evidence_desc=f"Session cookie '{cookie.name}' missing Secure flag - transmitted over HTTP",
                        fix="Set Secure flag on all session cookies. Ensure site uses HTTPS only.",
                        references=["https://owasp.org/www-project-session-management-cheat-sheet/"],
                        raw_data={"cookie_name": cookie.name, "cookie_value": cookie.value[:20] + "..."},
                    ))

    def check_httponly_flag(self):
        """COOKIE-002: Check for missing HttpOnly flag on session cookies"""
        resp = self.scanner.make_request("GET", "/")
        if not resp:
            return

        cookies = resp.cookies
        for cookie in cookies:
            if (not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower()
                    and self._is_session_cookie(cookie.name)):
                    self.scanner.add_finding(make_finding(
                        check_id="COOKIE-002",
                        title="Missing HttpOnly Flag on Session Cookie",
                        severity=Severity.HIGH,
                        category=Category.SESSION,
                        evidence_desc=f"Session cookie '{cookie.name}' missing HttpOnly flag - accessible via JavaScript",
                        fix="Set HttpOnly flag on all session cookies to prevent XSS theft",
                        references=["https://owasp.org/www-project-session-management-cheat-sheet/"],
                        raw_data={"cookie_name": cookie.name, "cookie_value": cookie.value[:20] + "..."},
                    ))

    def check_samesite_attribute(self):
        """COOKIE-003: Check for missing SameSite attribute"""
        resp = self.scanner.make_request("GET", "/")
        if not resp:
            return

        cookies = resp.cookies
        for cookie in cookies:
            samesite = getattr(cookie, 'samesite', None)
            if (not samesite or samesite.lower() == "none") and self._is_session_cookie(cookie.name):
                    severity = Severity.HIGH if samesite is None else Severity.MEDIUM
                    self.scanner.add_finding(make_finding(
                        check_id="COOKIE-003",
                        title="Missing or Insecure SameSite Attribute",
                        severity=severity,
                        category=Category.SESSION,
                        evidence_desc=f"Session cookie '{cookie.name}' has SameSite={samesite or 'None (missing)'}",
                        fix="Set SameSite=Strict or SameSite=Lax on session cookies. Use SameSite=None only with Secure for cross-site requests.",
                        references=["https://owasp.org/www-project-session-management-cheat-sheet/"],
                        raw_data={"cookie_name": cookie.name, "samesite": samesite},
                    ))

    def _is_session_cookie(self, name: str) -> bool:
        session_names = [
            "session", "sessionid", "sid", "php_session", "jsessionid",
            "aspsession", "connect.sid", "express.sid", "auth", "token",
            "csrf", "csrftoken", "xsrf", "jwt", "access_token", "refresh_token"
        ]
        name_lower = name.lower()
        return any(s in name_lower for s in session_names)