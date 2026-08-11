# AuthShield Tests

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from typing import TYPE_CHECKING

from authshield.core.models import (
    Severity, Category, Evidence, Finding, ScanSummary, ScanResult
)
from authshield.core.http_client import HTTPClient, make_finding, HTTPClientError
from authshield.checks.auth import AuthChecks
from authshield.checks.rate_limit import RateLimitChecks
from authshield.checks.enum import EnumChecks
from authshield.checks.cookies import CookieChecks
from authshield.checks.cors import CORSChecks
from authshield.checks.jwt import JWTChecks
from authshield.reporting.json_report import JSONReporter
from authshield.reporting.html_report import HTMLReporter

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner


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


class TestMakeFinding:
    def test_make_finding(self):
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


class TestAuthChecks:
    def test_check_weak_password_policy(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.text = "password must be at least 6 characters"
        mock_resp.status_code = 200
        mock_scanner.make_request.return_value = mock_resp

        checks = AuthChecks(mock_scanner)
        checks.check_weak_password_policy()

        mock_scanner.add_finding.assert_called()


class TestRateLimitChecks:
    def test_check_missing_rate_limit(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_scanner.make_request.return_value = mock_resp

        checks = RateLimitChecks(mock_scanner)
        checks.check_missing_rate_limit()

        mock_scanner.add_finding.assert_called()


class TestEnumChecks:
    def test_check_username_enumeration_error_messages(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 401
        mock_resp.text = "Invalid username or password"
        mock_scanner.make_request.return_value = mock_resp

        checks = EnumChecks(mock_scanner)
        checks.check_username_enumeration_error_messages()

        # Should have made multiple requests
        assert mock_scanner.make_request.call_count > 1


class TestCookieChecks:
    def test_check_secure_flag(self):
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


class TestCORSChecks:
    def test_check_cors_policy(self):
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


class TestJWTChecks:
    def test_collect_jwt_tokens(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.cookies = []
        mock_resp.text = ""
        mock_resp.request.headers = {}
        mock_scanner.make_request.return_value = mock_resp

        checks = JWTChecks(mock_scanner)
        checks.collect_jwt_tokens()

        assert mock_scanner.make_request.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])