from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Confidence, EvidenceType, Exploitability, Severity


class JWTChecks:
    """JWT security checks.

    Performs PASSIVE analysis of discovered tokens:
    - Decodes headers/payloads (no verification)
    - Checks for missing claims, weak algorithms
    - Does NOT brute-force secrets
    - Only tests 'none' algorithm if endpoint accepts it (active, but safe)
    """

    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client
        self.jwt_tokens: list[str] = []
        self.jwks_cache: dict | None = None

    def run_all(self):
        self.collect_jwt_tokens()
        if self.jwt_tokens:
            for token in self.jwt_tokens:
                self.check_algorithm_confusion(token)
                self.check_missing_expiration(token)
                self.check_none_algorithm(token)

    def collect_jwt_tokens(self):
        """Passively collect JWTs from cookies, headers, and response bodies."""
        # Check cookies on root
        resp = self.scanner.make_request("GET", "/")
        if resp:
            for cookie in resp.cookies:
                if self._looks_like_jwt(cookie.value):
                    self.jwt_tokens.append(cookie.value)

        # Check Authorization header on authenticated endpoints (if cookies provided)
        for endpoint in ["/api/user", "/api/profile", "/api/me", "/dashboard"]:
            resp = self.scanner.make_request("GET", endpoint)
            if resp is not None and hasattr(resp, 'request') and resp.request:
                auth_header = resp.request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    if self._looks_like_jwt(token):
                        self.jwt_tokens.append(token)

        # Check response bodies for embedded tokens (login pages, etc.)
        for endpoint in ["/login", "/api/auth/login", "/"]:
            resp = self.scanner.make_request("GET", endpoint)
            if resp is not None:
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

    def _decode_header(self, token: str) -> dict[str, Any] | None:
        try:
            header_b64 = token.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            return json.loads(header_json)  # type: ignore[no-any-return]
        except (ValueError, json.JSONDecodeError):
            return None

    def _decode_payload(self, token: str) -> dict[str, Any] | None:
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_json)  # type: ignore[no-any-return]
        except (ValueError, json.JSONDecodeError):
            return None

    def _fetch_jwks(self, base_url: str) -> dict | None:
        """Fetch JWKS from standard endpoints if not cached."""
        if self.jwks_cache:
            return self.jwks_cache

        jwks_endpoints = [
            "/.well-known/jwks.json",
            "/jwks.json",
            "/keys",
            "/auth/keys",
            "/oauth2/keys",
        ]

        for endpoint in jwks_endpoints:
            resp = self.scanner.make_request("GET", endpoint)
            if resp is not None and resp.status_code == 200:
                try:
                    self.jwks_cache = resp.json()
                    return self.jwks_cache
                except (ValueError, TypeError):
                    continue
        return None

    def check_algorithm_confusion(self, token: str):
        """JWT-001: Check for RS256 algorithm confusion risk.

        Only reports HIGH if:
        - Token uses RS256/ES256 (asymmetric)
        - AND public JWKS is discoverable
        - AND no algorithm pinning evidence found

        This is a configuration risk, not an exploit.
        """
        header = self._decode_header(token)
        if not header:
            return

        alg = header.get("alg", "").upper()
        if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            return

        # Check if JWKS is publicly accessible
        jwks = self._fetch_jwks(self.scanner.target)
        if not jwks:
            # No public keys found - lower risk
            self.scanner.add_finding(make_finding(
                check_id="JWT-001",
                title="JWT Uses Asymmetric Algorithm - Verify Algorithm Pinning",
                severity=Severity.INFO,  # Downgraded: risk only if keys exposed
                category=Category.JWT,
                evidence_desc=f"Token uses {alg} algorithm. Public JWKS endpoint not discovered.",
                fix=(
                    "Ensure JWT library pins expected algorithm (reject HS256 for RS256 tokens). "
                    "Validate 'alg' header matches expected. Use library defaults that enforce this."
                ),
                references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                raw_data={"algorithm": alg, "header": header, "jwks_found": False},
                confidence=Confidence.LOW,
                evidence_type=EvidenceType.INDICATOR,
                exploitability=Exploitability.THEORETICAL,
                context={"check_type": "jwt_algorithm_analysis", "jwks_discovered": False,
                         "algorithm": alg, "risk": "algorithm_confusion_if_unpinned"},
            ))
            return

        # JWKS found - higher risk if algorithm not pinned
        self.scanner.add_finding(make_finding(
            check_id="JWT-001",
            title="JWT Algorithm Confusion Risk (RS256 with Public JWKS)",
            severity=Severity.MEDIUM,  # Medium: requires specific conditions
            category=Category.JWT,
            evidence_desc=f"Token uses {alg} algorithm AND public JWKS is accessible at known endpoint. "
                          "If library doesn't pin algorithm, HS256 confusion attack possible.",
            fix=(
                "Pin expected algorithm in JWT verification. "
                "Reject tokens with unexpected 'alg'. "
                "Use libraries that enforce algorithm validation by default."
            ),
            references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
            raw_data={"algorithm": alg, "header": header, "jwks_found": True},
            confidence=Confidence.MEDIUM,
            evidence_type=EvidenceType.INDICATOR,
            exploitability=Exploitability.THEORETICAL,
            context={"check_type": "jwt_algorithm_analysis", "jwks_discovered": True,
                     "algorithm": alg, "risk": "algorithm_confusion_if_unpinned"},
        ))

    def check_missing_expiration(self, token: str):
        """JWT-003: Check for missing or excessive expiration claims."""
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
                fix="Always include 'exp' claim with reasonable lifetime (15-60 min for access tokens). Use 'iat' and 'nbf' as well.",
                references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                raw_data={"payload_keys": list(payload.keys())},
                confidence=Confidence.HIGH,
                evidence_type=EvidenceType.PROOF,
                exploitability=Exploitability.PROVEN,
                context={"check_type": "jwt_claim_analysis", "missing_claim": "exp",
                         "risk": "indefinite_token_validity"},
            ))
        else:
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
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.PROOF,
                    exploitability=Exploitability.LIKELY,
                    context={"check_type": "jwt_claim_analysis", "claim": "exp",
                             "risk": "excessive_lifetime", "days": (exp - now) // 86400},
                ))

    def check_none_algorithm(self, token: str):
        """JWT-004: Test if endpoint accepts 'none' algorithm token.

        Sends a crafted 'none' algorithm token to a protected endpoint
        and checks if it's accepted (not rejected due to algorithm).
        """
        # First, check if any scanned token uses 'none' (passive)
        header = self._decode_header(token)
        if header and header.get("alg", "").lower() == "none":
            self.scanner.add_finding(make_finding(
                check_id="JWT-004",
                title="JWT Uses 'none' Algorithm (Passive Detection)",
                severity=Severity.CRITICAL,
                category=Category.JWT,
                evidence_desc="Discovered JWT uses 'none' algorithm - no signature verification",
                fix="Reject tokens with 'none' algorithm. Configure JWT library to require signature verification.",
                references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                raw_data={"algorithm": "none"},
                confidence=Confidence.HIGH,
                evidence_type=EvidenceType.PROOF,
                exploitability=Exploitability.PROVEN,
                context={"check_type": "jwt_algorithm_validation", "algorithm": "none",
                         "detection": "passive", "risk": "no_signature_verification"},
            ))
            return

        # Active test: send 'none' token to a protected endpoint
        # Only if we have a protected endpoint to test against
        protected_endpoints = ["/api/user", "/api/profile", "/api/me"]

        for endpoint in protected_endpoints:
            # First check if endpoint requires auth
            resp = self.scanner.make_request("GET", endpoint)
            if resp is not None and resp.status_code in (401, 403):
                # Extract username from an existing valid token if available
                test_username = self._extract_username_from_token(token)

                # If no valid token has a username, try to register a test user
                if not test_username:
                    test_username = self._register_test_user()

                if not test_username:
                    self.scanner.log(f"Could not determine test username for JWT-004 on {endpoint}")
                    continue

                # Craft a 'none' algorithm token with the test username
                try:
                    none_header = {"alg": "none", "typ": "JWT"}
                    none_payload = {"sub": test_username, "iat": 1234567890}
                    header_b64 = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip("=")
                    payload_b64 = base64.urlsafe_b64encode(json.dumps(none_payload).encode()).decode().rstrip("=")
                    none_token = f"{header_b64}.{payload_b64}."

                    # Send it
                    test_resp = self.scanner.make_request("GET", endpoint, headers={
                        "Authorization": f"Bearer {none_token}"
                    })
                    if test_resp is not None and test_resp.status_code == 200:
                        self.scanner.add_finding(make_finding(
                            check_id="JWT-004",
                            title="Endpoint Accepts 'none' Algorithm JWT",
                            severity=Severity.CRITICAL,
                            category=Category.JWT,
                            evidence_desc=f"Endpoint {endpoint} accepted a JWT with 'alg=none' (no signature)",
                            fix="Configure JWT library to reject 'none' algorithm. Require signature verification.",
                            references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "algorithm": "none"},
                            confidence=Confidence.HIGH,
                            evidence_type=EvidenceType.PROOF,
                            exploitability=Exploitability.PROVEN,
                            context={"check_type": "jwt_algorithm_validation", "algorithm": "none",
                                     "detection": "active", "endpoint": endpoint, "risk": "auth_bypass"},
                        ))
                        return
                    elif test_resp is not None and test_resp.status_code != 401:
                        # Some other response (e.g., 404 user not found) means the algorithm was accepted
                        # but authorization failed for other reasons - still a vulnerability
                        self.scanner.add_finding(make_finding(
                            check_id="JWT-004",
                            title="Endpoint Accepts 'none' Algorithm JWT (Algorithm Not Rejected)",
                            severity=Severity.HIGH,
                            category=Category.JWT,
                            evidence_desc=(
                                f"Endpoint {endpoint} did not reject 'alg=none' token (status: {test_resp.status_code}). "
                                f"The 'none' algorithm was processed by the JWT library. "
                                f"Only user validation failed afterward."
                            ),
                            fix="Configure JWT library to reject 'none' algorithm. Require signature verification.",
                            references=["https://owasp.org/www-project-json-web-token-jwt-cheat-sheet/"],
                            raw_data={"endpoint": endpoint, "algorithm": "none", "response_status": test_resp.status_code},
                            confidence=Confidence.HIGH,
                            evidence_type=EvidenceType.PROOF,
                            exploitability=Exploitability.LIKELY,
                            context={"check_type": "jwt_algorithm_validation", "algorithm": "none",
                                     "detection": "active", "endpoint": endpoint,
                                     "risk": "algorithm_not_rejected", "response_status": test_resp.status_code},
                        ))
                        return
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass

    def _extract_username_from_token(self, token: str) -> str | None:
        """Extract username/sub from a valid token if available."""
        try:
            payload = self._decode_payload(token)
            if payload and "sub" in payload:
                return str(payload["sub"])
        except (ValueError, KeyError, TypeError):
            pass
        return None

    def _register_test_user(self) -> str | None:
        """Try to register a test user and return the username."""
        import time
        test_user = f"jwt_test_{int(time.time())}"
        for endpoint in ["/register", "/signup", "/auth/register", "/api/register"]:
            resp = self.scanner.make_request("POST", endpoint, json={
                "username": test_user, "password": "TestPass123!"
            })
            if resp and resp.status_code in (200, 201):
                return test_user
            # Try form-encoded fallback
            if resp and resp.status_code == 415:
                resp = self.scanner.make_request("POST", endpoint, data={
                    "username": test_user, "password": "TestPass123!"
                })
                if resp and resp.status_code in (200, 201):
                    return test_user
        return None