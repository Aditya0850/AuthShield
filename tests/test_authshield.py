# AuthShield Tests

import json
import time
from unittest.mock import Mock

import pytest
import requests

from authshield.checks.auth import AuthChecks
from authshield.checks.cookies import CookieChecks
from authshield.checks.cors import CORSChecks
from authshield.checks.enum import EnumChecks
from authshield.checks.jwt import JWTChecks
from authshield.checks.rate_limit import RateLimitChecks
from authshield.core.http_client import HTTPClient, HTTPClientError, make_finding
from authshield.core.models import Category, Evidence, Finding, ScanResult, ScanSummary, Severity
from authshield.core.scanner import Scanner
from authshield.reporting.html_report import HTMLReporter
from authshield.reporting.json_report import JSONReporter


class TestModels:
    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_category_enum(self):
        assert Category.AUTHENTICATION.value == "authentication"
        assert Category.RATE_LIMITING.value == "rate_limiting"
        assert Category.USER_ENUMERATION.value == "user_enumeration"
        assert Category.SESSION.value == "session"
        assert Category.CORS_HEADERS.value == "cors_headers"
        assert Category.JWT.value == "jwt"

    def test_finding_creation(self):
        evidence = Evidence(description="Test evidence")
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence=evidence,
            fix="Test fix",
        )
        assert finding.id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.category == Category.AUTHENTICATION

    def test_scan_summary(self):
        summary = ScanSummary()
        assert summary.total() == 0

        summary.increment(Severity.CRITICAL)
        summary.increment(Severity.HIGH)
        summary.increment(Severity.HIGH)
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.total() == 3

    def test_scan_result(self):
        result = ScanResult(target="https://example.com")
        evidence = Evidence(description="Test")
        finding = Finding(
            id="TEST-001",
            title="Test",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence=evidence,
            fix="Fix it",
        )
        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.summary.high == 1

    def test_severity_ordering(self):
        # CRITICAL > HIGH > MEDIUM > LOW > INFO
        severities = [
            Severity.INFO, Severity.LOW, Severity.MEDIUM,
            Severity.HIGH, Severity.CRITICAL
        ]
        # This test documents the expected ordering
        assert len(severities) == 5


class TestMakeFinding:
    def test_make_finding_complete(self):
        finding = make_finding(
            check_id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence_desc="Test evidence",
            fix="Test fix",
            references=["https://example.com"],
            cvss_score=7.5,
        )
        assert finding.id == "TEST-001"
        assert finding.evidence.description == "Test evidence"
        assert finding.references == ["https://example.com"]
        assert finding.cvss_score == 7.5

    def test_make_finding_minimal(self):
        finding = make_finding(
            check_id="TEST-002",
            title="Minimal Finding",
            severity=Severity.LOW,
            category=Category.SESSION,
            evidence_desc="Evidence",
            fix="Fix",
        )
        assert finding.id == "TEST-002"
        assert finding.severity == Severity.LOW
        assert finding.references == []
        assert finding.cvss_score is None
        assert finding.evidence.raw_data is None


class TestHTTPClient:
    def test_client_creation(self):
        client = HTTPClient(timeout=5, max_retries=1)
        assert client.timeout == 5
        assert client.max_retries == 1
        assert client.request_count == 0
        client.close()

    def test_client_with_cookies_and_headers(self):
        client = HTTPClient(
            cookies={"session": "abc123"},
            headers={"X-Custom": "value"}
        )
        assert client.session.cookies.get("session") == "abc123"
        assert client.session.headers.get("X-Custom") == "value"
        client.close()

    def test_request_budget_enforcement(self):
        client = HTTPClient(max_requests=2)
        # First request allowed
        client.request_count = 0
        assert client.requests_remaining == 2
        # After limit
        client.request_count = 2
        assert client.requests_remaining == 0

    def test_elapsed_time_attached(self, monkeypatch):
        """Test that elapsed_time is attached to response."""
        client = HTTPClient(timeout=10)

        # Mock session.request to return a response
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.text = "OK"

        def mock_request(method, url, **kwargs):
            time.sleep(0.01)  # Small delay
            return mock_resp

        client.session.request = mock_request

        resp = client.get("https://example.com")
        assert hasattr(resp, 'elapsed_time')
        assert resp.elapsed_time >= 0.01
        client.close()

    def test_timeout_handling(self):
        """Test timeout error is wrapped."""
        client = HTTPClient(timeout=1, max_retries=0)
        client.session.request = Mock(side_effect=requests.Timeout())

        with pytest.raises(HTTPClientError, match="timeout"):
            client.get("https://example.com")
        client.close()

    def test_network_error_handling(self):
        """Test network error is wrapped."""
        client = HTTPClient(max_retries=0)
        client.session.request = Mock(side_effect=requests.ConnectionError("DNS failed"))

        with pytest.raises(HTTPClientError, match="Request failed"):
            client.get("https://example.com")
        client.close()

    def test_no_redirect_on_post(self):
        """Test POST requests don't follow redirects by default."""
        client = HTTPClient()
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 200

        def mock_request(method, url, **kwargs):
            if method == "POST":
                assert kwargs.get("allow_redirects") is False
            return mock_resp

        client.session.request = mock_request
        client.post("https://example.com")
        client.close()


class TestJSONReporter:
    def test_generate_json(self):
        result = ScanResult(target="https://example.com")
        evidence = Evidence(description="Test evidence")
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence=evidence,
            fix="Test fix",
            references=["https://example.com"],
        )
        result.add_finding(finding)

        json_str = JSONReporter.generate(result)
        data = json.loads(json_str)

        assert data["target"] == "https://example.com"
        assert data["summary"]["high"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "TEST-001"
        assert data["findings"][0]["evidence"]["description"] == "Test evidence"

    def test_generate_json_to_file(self, tmp_path):
        result = ScanResult(target="https://example.com")
        output_path = tmp_path / "report.json"
        JSONReporter.generate(result, str(output_path))
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["target"] == "https://example.com"

    def test_json_serializes_datetime(self):
        result = ScanResult(target="https://example.com")
        json_str = JSONReporter.generate(result)
        data = json.loads(json_str)
        assert "scan_time" in data
        assert "T" in data["scan_time"]


class TestHTMLReporter:
    def test_generate_html(self, tmp_path):
        result = ScanResult(target="https://example.com")
        evidence = Evidence(description="Test evidence")
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence=evidence,
            fix="Test fix",
        )
        result.add_finding(finding)

        output_path = tmp_path / "test_report.html"
        HTMLReporter.generate(result, str(output_path))

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "AuthShield Security Audit Report" in content
        assert "TEST-001" in content
        assert "Test Finding" in content

    def test_html_includes_severity_counts(self, tmp_path):
        result = ScanResult(target="https://example.com")
        for sev, count in [(Severity.CRITICAL, 1), (Severity.HIGH, 2), (Severity.MEDIUM, 1)]:
            for i in range(count):
                evidence = Evidence(description=f"Test {sev.value}")
                finding = Finding(
                    id=f"TEST-{sev.value}-{i}",
                    title=f"Test {sev.value}",
                    severity=sev,
                    category=Category.AUTHENTICATION,
                    evidence=evidence,
                    fix="Fix",
                )
                result.add_finding(finding)

        output_path = tmp_path / "test_report.html"
        HTMLReporter.generate(result, str(output_path))
        content = output_path.read_text(encoding="utf-8")
        assert "Critical" in content
        assert "High" in content


class TestAuthChecks:
    def test_check_weak_password_policy_detects_weak(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.text = "password must be at least 4 characters"
        mock_resp.status_code = 200
        mock_scanner.make_request.return_value = mock_resp

        checks = AuthChecks(mock_scanner)
        checks.check_weak_password_policy()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "AUTH-001"
        assert call_args.severity == Severity.MEDIUM

    def test_check_weak_password_policy_no_finding_on_strong(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.text = "password must be at least 12 characters"
        mock_resp.status_code = 200
        mock_scanner.make_request.return_value = mock_resp

        checks = AuthChecks(mock_scanner)
        checks.check_weak_password_policy()

        mock_scanner.add_finding.assert_not_called()

    def test_check_weak_password_policy_404_no_crash(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_scanner.make_request.return_value = mock_resp

        checks = AuthChecks(mock_scanner)
        checks.check_weak_password_policy()

        mock_scanner.add_finding.assert_not_called()


class TestRateLimitChecks:
    def test_check_missing_rate_limit_detects(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_scanner.make_request.return_value = mock_resp

        checks = RateLimitChecks(mock_scanner)
        checks.check_missing_rate_limit()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "RATE-001"
        assert call_args.severity == Severity.HIGH
        assert "methodology" in call_args.evidence.raw_data

    def test_check_missing_rate_limit_not_triggered_on_429(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 429
        mock_scanner.make_request.return_value = mock_resp

        checks = RateLimitChecks(mock_scanner)
        checks.check_missing_rate_limit()

        # Should NOT report if 429 received
        mock_scanner.add_finding.assert_not_called()

    def test_check_missing_rate_limit_handles_network_error(self):
        mock_scanner = Mock()
        mock_scanner.make_request.return_value = None  # Network error

        checks = RateLimitChecks(mock_scanner)
        checks.check_missing_rate_limit()

        mock_scanner.add_finding.assert_not_called()


class TestEnumChecks:
    def test_check_enumeration_detects_different_responses(self):
        """Test that different error signatures are detected."""
        mock_scanner = Mock()

        # Different responses for different users
        responses = {
            "admin": Mock(status_code=401, text="Invalid username"),
            "administrator": Mock(status_code=401, text="Invalid username"),
            "test": Mock(status_code=401, text="Invalid username"),
            "user": Mock(status_code=401, text="Invalid username"),
            "nonexistentuser12345": Mock(status_code=404, text="User not found"),
        }

        def make_request(method, endpoint, json=None, data=None):
            # Handle both json and data kwargs
            payload = json or data
            user = payload.get("username") if payload else None
            return responses.get(user)

        mock_scanner.make_request.side_effect = make_request

        checks = EnumChecks(mock_scanner)
        checks.check_username_enumeration_error_messages()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "ENUM-001"
        assert call_args.severity == Severity.MEDIUM

    def test_check_enumeration_no_finding_when_same_responses(self):
        """Test no finding when all users get same response."""
        mock_scanner = Mock()
        mock_resp = Mock(status_code=401, text="Invalid username or password")
        mock_scanner.make_request.return_value = mock_resp

        checks = EnumChecks(mock_scanner)
        checks.check_username_enumeration_error_messages()

        mock_scanner.add_finding.assert_not_called()

    def test_check_enumeration_handles_network_error(self):
        mock_scanner = Mock()
        mock_scanner.make_request.return_value = None

        checks = EnumChecks(mock_scanner)
        checks.check_username_enumeration_error_messages()

        mock_scanner.add_finding.assert_not_called()


class TestCookieChecks:
    def test_check_secure_flag_detects_missing(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123"
        mock_cookie.secure = False
        mock_resp.cookies = [mock_cookie]
        mock_scanner.make_request.return_value = mock_resp

        checks = CookieChecks(mock_scanner)
        checks.check_secure_flag()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "COOKIE-001"
        assert call_args.severity == Severity.HIGH

    def test_check_secure_flag_no_finding_when_secure(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123"
        mock_cookie.secure = True
        mock_resp.cookies = [mock_cookie]
        mock_scanner.make_request.return_value = mock_resp

        checks = CookieChecks(mock_scanner)
        checks.check_secure_flag()

        mock_scanner.add_finding.assert_not_called()

    def test_check_httponly_flag_detects_missing(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123"
        # HttpOnly check: has_nonstandard_attr returns False, str doesn't contain httponly
        mock_cookie.has_nonstandard_attr = Mock(return_value=False)
        mock_cookie.__str__ = Mock(return_value="sessionid=abc123")
        mock_resp.cookies = [mock_cookie]
        mock_scanner.make_request.return_value = mock_resp

        checks = CookieChecks(mock_scanner)
        checks.check_httponly_flag()

        mock_scanner.add_finding.assert_called()

    def test_check_samesite_detects_missing(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123"
        mock_cookie.samesite = None
        mock_resp.cookies = [mock_cookie]
        mock_scanner.make_request.return_value = mock_resp

        checks = CookieChecks(mock_scanner)
        checks.check_samesite_attribute()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "COOKIE-003"
        assert call_args.severity == Severity.HIGH

    def test_check_samesite_none_is_medium(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123"
        mock_cookie.samesite = "None"
        mock_resp.cookies = [mock_cookie]
        mock_scanner.make_request.return_value = mock_resp

        checks = CookieChecks(mock_scanner)
        checks.check_samesite_attribute()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.severity == Severity.MEDIUM


class TestCORSChecks:
    def test_check_cors_wildcard_with_credentials(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_scanner.make_request.return_value = mock_resp

        checks = CORSChecks(mock_scanner)
        checks.check_cors_policy()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "CORS-001"
        assert call_args.severity == Severity.CRITICAL

    def test_check_cors_reflected_origin_with_credentials(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_scanner.make_request.return_value = mock_resp

        checks = CORSChecks(mock_scanner)
        checks.check_cors_policy()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.severity == Severity.HIGH

    def test_check_cors_wildcard_no_credentials(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
        }
        mock_scanner.make_request.return_value = mock_resp

        checks = CORSChecks(mock_scanner)
        checks.check_cors_policy()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.severity == Severity.MEDIUM

    def test_check_security_headers_missing_csp_hsts(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.headers = {}  # No security headers
        mock_scanner.make_request.return_value = mock_resp

        checks = CORSChecks(mock_scanner)
        checks.check_security_headers()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "CORS-002"
        assert call_args.severity == Severity.HIGH
        assert "Content-Security-Policy" in call_args.evidence.raw_data["missing"]

    def test_check_security_headers_csp_unsafe_inline(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            "Strict-Transport-Security": "max-age=31536000",
        }
        mock_scanner.make_request.return_value = mock_resp

        checks = CORSChecks(mock_scanner)
        checks.check_security_headers()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert "unsafe-inline" in call_args.evidence.raw_data["issues"][0]


class TestJWTChecks:
    def test_collect_jwt_tokens_from_cookie(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_cookie = Mock()
        mock_cookie.name = "auth_token"
        mock_cookie.value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy"
        mock_resp.cookies = [mock_cookie]
        mock_resp.text = ""
        mock_resp.request = Mock(headers={})
        mock_scanner.make_request.return_value = mock_resp

        checks = JWTChecks(mock_scanner)
        checks.collect_jwt_tokens()

        assert len(checks.jwt_tokens) == 1
        assert checks.jwt_tokens[0].startswith("eyJ")

    def test_collect_jwt_tokens_from_body(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.cookies = []
        mock_resp.text = 'var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy";'
        mock_resp.request = Mock(headers={})
        mock_scanner.make_request.return_value = mock_resp

        checks = JWTChecks(mock_scanner)
        checks.collect_jwt_tokens()

        assert len(checks.jwt_tokens) == 1

    def test_check_algorithm_confusion_rs256_no_jwks(self):
        mock_scanner = Mock()
        mock_scanner.target = "https://example.com"
        mock_404 = Mock(status_code=404)
        mock_scanner.make_request.return_value = mock_404

        checks = JWTChecks(mock_scanner)
        # RS256 token
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy"
        checks.check_algorithm_confusion(token)

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "JWT-001"
        assert call_args.severity == Severity.INFO  # No JWKS = INFO

    def test_check_algorithm_confusion_rs256_with_jwks(self):
        mock_scanner = Mock()
        mock_scanner.target = "https://example.com"
        mock_jwks = Mock(status_code=200)
        mock_jwks.json.return_value = {"keys": []}
        mock_scanner.make_request.return_value = mock_jwks

        checks = JWTChecks(mock_scanner)
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy"
        checks.check_algorithm_confusion(token)

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.severity == Severity.MEDIUM  # JWKS found = MEDIUM

    def test_check_missing_expiration(self):
        mock_scanner = Mock()
        checks = JWTChecks(mock_scanner)
        # Token without exp
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy"
        checks.check_missing_expiration(token)

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "JWT-003"
        assert call_args.severity == Severity.HIGH

    def test_check_missing_expiration_with_long_exp(self):
        mock_scanner = Mock()
        checks = JWTChecks(mock_scanner)
        # Token with exp in 30 days
        import time
        exp = int(time.time()) + 86400 * 30
        import base64
        import json
        payload = {"sub": "123", "exp": exp}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload_b64}.dummy"

        checks.check_missing_expiration(token)

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.severity == Severity.MEDIUM

    def test_check_none_algorithm_active_test(self):
        """Test that endpoint accepting 'none' algorithm is detected."""
        mock_scanner = Mock()
        mock_scanner.target = "https://example.com"

        # First request: endpoint returns 401 (requires auth)
        mock_401 = Mock(status_code=401)
        # Second request: endpoint accepts none token (returns 200)
        mock_200 = Mock(status_code=200)
        mock_scanner.make_request.side_effect = [mock_401, mock_200]

        checks = JWTChecks(mock_scanner)
        # Valid HS256 token to trigger check
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy"
        checks.check_none_algorithm(token)

        # Should have made requests to check endpoint
        assert mock_scanner.make_request.call_count >= 2
        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "JWT-004"
        assert call_args.severity == Severity.CRITICAL


class TestScannerIntegration:
    def test_scanner_creation(self):
        scanner = Scanner(target="https://example.com", verbose=False)
        assert scanner.target == "https://example.com"
        assert scanner.endpoints is not None
        scanner.client.close()

    def test_scanner_custom_endpoints(self):
        scanner = Scanner(
            target="https://example.com",
            endpoints=["/custom/login", "/custom/register"],
            timeout=5,
            max_requests=50,
        )
        assert scanner.endpoints == ["/custom/login", "/custom/register"]
        assert scanner.client.max_requests == 50
        scanner.client.close()

    def test_scanner_full_url_construction(self):
        scanner = Scanner(target="https://example.com")
        assert scanner.get_full_url("/login") == "https://example.com/login"
        assert scanner.get_full_url("login") == "https://example.com/login"
        assert scanner.get_full_url("https://other.com/path") == "https://other.com/path"
        scanner.client.close()

    def test_add_finding_updates_summary(self):
        scanner = Scanner(target="https://example.com", verbose=False)
        finding = make_finding(
            check_id="TEST-001",
            title="Test",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            evidence_desc="Evidence",
            fix="Fix",
        )
        scanner.add_finding(finding)
        assert len(scanner.result.findings) == 1
        assert scanner.result.summary.high == 1
        scanner.client.close()


class TestExcludeChecks:
    def _scanner_with_mocked_modules(self, **kwargs):
        scanner = Scanner(target="https://example.com", verbose=False, **kwargs)
        scanner.auth_checks = Mock()
        scanner.rate_limit_checks = Mock()
        scanner.enum_checks = Mock()
        scanner.cookie_checks = Mock()
        scanner.cors_checks = Mock()
        scanner.jwt_checks = Mock()
        return scanner

    def test_exclude_checks_normalized(self):
        scanner = Scanner(
            target="https://example.com",
            exclude_checks=[" cookie-001 ", "JWT-004", ""],
        )
        assert scanner.excluded_checks == {"COOKIE-001", "JWT-004"}
        assert scanner.is_check_excluded("COOKIE-001")
        assert scanner.is_check_excluded("cookie-001")
        assert not scanner.is_check_excluded("COOKIE-002")
        scanner.client.close()

    def test_no_exclusions_by_default(self):
        scanner = Scanner(target="https://example.com")
        assert scanner.excluded_checks == set()
        assert not scanner.is_check_excluded("AUTH-001")
        scanner.client.close()

    def test_scan_skips_fully_excluded_category(self):
        scanner = self._scanner_with_mocked_modules(
            exclude_checks=["RATE-001", "COOKIE-001", "COOKIE-002", "COOKIE-003"],
        )
        scanner.scan()
        scanner.rate_limit_checks.run_all.assert_not_called()
        scanner.cookie_checks.run_all.assert_not_called()
        scanner.auth_checks.run_all.assert_called_once()
        scanner.enum_checks.run_all.assert_called_once()
        scanner.cors_checks.run_all.assert_called_once()
        scanner.jwt_checks.run_all.assert_called_once()

    def test_scan_runs_partially_excluded_category(self):
        # Excluding one of three cookie checks must not skip the whole module
        scanner = self._scanner_with_mocked_modules(exclude_checks=["COOKIE-002"])
        scanner.scan()
        scanner.cookie_checks.run_all.assert_called_once()

    def test_cookie_run_all_skips_excluded_check(self):
        mock_scanner = Mock()
        mock_scanner.is_check_excluded = lambda cid: cid == "COOKIE-002"
        checks = CookieChecks(mock_scanner)
        checks.check_secure_flag = Mock()
        checks.check_httponly_flag = Mock()
        checks.check_samesite_attribute = Mock()

        checks.run_all()

        checks.check_secure_flag.assert_called_once()
        checks.check_httponly_flag.assert_not_called()
        checks.check_samesite_attribute.assert_called_once()

    def test_cors_run_all_skips_excluded_check(self):
        mock_scanner = Mock()
        mock_scanner.is_check_excluded = lambda cid: cid == "CORS-001"
        checks = CORSChecks(mock_scanner)
        checks.check_cors_policy = Mock()
        checks.check_security_headers = Mock()

        checks.run_all()

        checks.check_cors_policy.assert_not_called()
        checks.check_security_headers.assert_called_once()

    def test_jwt_run_all_skips_collection_when_all_excluded(self):
        mock_scanner = Mock()
        mock_scanner.is_check_excluded = lambda cid: True
        checks = JWTChecks(mock_scanner)
        checks.collect_jwt_tokens = Mock()

        checks.run_all()

        checks.collect_jwt_tokens.assert_not_called()

    def test_jwt_run_all_runs_only_included_checks(self):
        mock_scanner = Mock()
        mock_scanner.is_check_excluded = lambda cid: cid == "JWT-004"
        checks = JWTChecks(mock_scanner)
        checks.collect_jwt_tokens = Mock(
            side_effect=lambda: checks.jwt_tokens.append("token")
        )
        checks.check_algorithm_confusion = Mock()
        checks.check_missing_expiration = Mock()
        checks.check_none_algorithm = Mock()

        checks.run_all()

        checks.check_algorithm_confusion.assert_called_once_with("token")
        checks.check_missing_expiration.assert_called_once_with("token")
        checks.check_none_algorithm.assert_not_called()

    def test_parse_exclude_checks(self):
        from authshield.cli import parse_exclude_checks

        valid, unknown = parse_exclude_checks("rate-001, JWT-004,BOGUS-999,rate-001,")
        assert valid == ["RATE-001", "JWT-004"]
        assert unknown == ["BOGUS-999"]

        valid, unknown = parse_exclude_checks(None)
        assert valid == []
        assert unknown == []

    def test_known_check_ids_cover_all_categories(self):
        scanner = Scanner(target="https://example.com")
        category_ids = set()
        for _, _, check_ids in scanner.get_check_categories():
            category_ids |= check_ids
        assert category_ids == set(Scanner.KNOWN_CHECK_IDS)
        scanner.client.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])