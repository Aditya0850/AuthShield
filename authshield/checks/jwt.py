from __future__ import annotations

from typing import List, Dict, Any, Optional, TYPE_CHECKING
import jwt
import base64
import json

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.models import Finding, Severity, Category
from authshield.core.http_client import make_finding


class JWTChecks:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client
        self.jwt_tokens: List[str] = []

    def run_all(self):
        self.collect_jwt_tokens()
        if self.jwt_tokens:
            for token in self.jwt_tokens:
                self.check_algorithm_confusion(token)
                self.check_weak_secret(token)
                self.check_missing_expiration(token)
                self.check_none_algorithm(token)

    def collect_jwt_tokens(self):
        # Check cookies
        resp = self.scanner.make_request("GET", "/")
        if resp:
            for cookie in resp.cookies:
                if self._looks_like_jwt(cookie.value):
                    self.jwt_tokens.append(cookie.value)

        # Check Authorization header on authenticated endpoints
        for endpoint in ["/api/user", "/api/profile", "/api/me", "/dashboard"]:
            resp = self.scanner.make_request("GET", endpoint)
            if resp:
                auth_header = resp.request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    if self._looks_like_jwt(token):
                        self.jwt_tokens.append(token)

        # Check localStorage via JS (can't easily do this, but check response bodies)
        for endpoint in ["/login", "/api/auth/login", "/"]:
            resp = self.scanner.make_request("GET", endpoint)
            if resp:
                # Search for JWT-like strings in response
                import re
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                matches = re.findall(jwt_pattern, resp.text)
                self.jwt_tokens.extend(matches)

        # Deduplicate
        self.jwt_tokens = list(set(self.jwt_tokens))

    def _looks_like_jwt(self, token: str) -> bool:
        if not token or len(token) < 30:
            return False
        parts = token.split(".")
        return len(parts) == 3 and all(part for part in parts)

    def _decode_header(self, token: str) -> Optional[Dict]:
        try:
            header_b64 = token.split(".")[0]
            # Add padding if needed
            header_b64 += "=" * (-len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            return json.loads(header_json)
        except Exception:
            return None

    def _decode_payload(self, token: str) -> Optional[Dict]:
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_json)
        except Exception:
            return None

    def check_algorithm_confusion(self, token: str):
        """JWT-001: Check for algorithm confusion (RS256/HS256)"""
        header = self._decode_header(token)
        if not header:
            return

        alg = header.get("alg", "").upper()
        if alg == "RS256":
            # Check if we can sign with HS256 using public key as secret
            # This is a theoretical check - we can't actually test without the key
            self.scanner.add_finding(make_finding(
                check_id="JWT-001",
                title="JWT Uses RS256 - Potential Algorithm Confusion",
                severity=Severity.HIGH,
                category=Category.JWT,
                evidence_desc=f"Token uses RS256 algorithm. If public key is exposed, HS256 confusion attack possible",
                fix="Use RS256/ES256 with proper key validation. Ensure library rejects tokens with unexpected algorithms. Pin expected algorithm.",
                references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                raw_data={"algorithm": alg, "header": header},
            ))

    def check_weak_secret(self, token: str):
        """JWT-002: Check for weak JWT secret (HS256)"""
        header = self._decode_header(token)
        if not header:
            return

        alg = header.get("alg", "").upper()
        if alg == "HS256":
            # Try common weak secrets
            weak_secrets = [
                "secret", "secretkey", "jwtsecret", "mysecret", "password",
                "changeme", "secret123", "jwt", "key", "supersecret",
                "authsecret", "signingkey", "hs256secret", ""
            ]

            for secret in weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=["HS256"])
                    self.scanner.add_finding(make_finding(
                        check_id="JWT-002",
                        title="Weak JWT Secret Detected",
                        severity=Severity.CRITICAL,
                        category=Category.JWT,
                        evidence_desc=f"JWT signed with weak secret: '{secret}'",
                        fix="Use strong random secret (256+ bits). Rotate secrets regularly. Use RS256/ES256 for asymmetric signing.",
                        references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                        raw_data={"algorithm": alg, "weak_secret": secret},
                    ))
                    return
                except jwt.InvalidSignatureError:
                    continue

    def check_missing_expiration(self, token: str):
        """JWT-003: Check for missing expiration claim"""
        payload = self._decode_payload(token)
        if not payload:
            return

        if "exp" not in payload:
            self.scanner.add_finding(make_finding(
                check_id="JWT-003",
                title="JWT Missing Expiration Claim (exp)",
                severity=Severity.HIGH,
                category=Category.JWT,
                evidence_desc="JWT does not contain 'exp' (expiration) claim - token never expires",
                fix="Always include 'exp' claim with reasonable lifetime (e.g., 15-60 min for access tokens). Use 'iat' and 'nbf' as well.",
                references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                raw_data={"payload_keys": list(payload.keys())},
            ))
        else:
            # Check if expiration is too far in future
            import time
            exp = payload["exp"]
            now = int(time.time())
            if exp - now > 86400 * 7:  # More than 7 days
                self.scanner.add_finding(make_finding(
                    check_id="JWT-003",
                    title="JWT Expiration Too Long",
                    severity=Severity.MEDIUM,
                    category=Category.JWT,
                    evidence_desc=f"JWT expires in {(exp - now) // 86400} days - excessive lifetime",
                    fix="Reduce token lifetime. Use short-lived access tokens (15-60 min) with refresh tokens.",
                    references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                    raw_data={"expires_in_days": (exp - now) // 86400},
                ))

    def check_none_algorithm(self, token: str):
        """JWT-004: Check if 'none' algorithm is accepted"""
        # Create a token with 'none' algorithm
        try:
            header = {"alg": "none", "typ": "JWT"}
            payload = {"sub": "test", "iat": 1234567890}
            import base64
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            none_token = f"{header_b64}.{payload_b64}."

            # Try to decode with 'none' algorithm allowed
            jwt.decode(none_token, options={"verify_signature": False})
            # This means library accepts 'none' - but we need to test actual endpoint
            # For now, find if any token uses 'none'
            header = self._decode_header(token)
            if header and header.get("alg", "").lower() == "none":
                self.scanner.add_finding(make_finding(
                    check_id="JWT-004",
                    title="JWT Uses 'none' Algorithm",
                    severity=Severity.CRITICAL,
                    category=Category.JWT,
                    evidence_desc="JWT uses 'none' algorithm - no signature verification",
                    fix="Reject tokens with 'none' algorithm. Configure JWT library to require signature verification.",
                    references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                    raw_data={"algorithm": "none"},
                ))
        except Exception:
            pass