#!/usr/bin/env python3
"""
Vulnerable Flask Demo Application for AuthShield Testing

⚠️  WARNING: This application contains INTENTIONAL security vulnerabilities!
     -rw-r-- DO NOT DEPLOY TO PRODUCTION --
This is for LOCAL TESTING ONLY with AuthShield.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, make_response, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['SESSION_COOKIE_SECURE'] = False  # INSECURE: No Secure flag
app.config['SESSION_COOKIE_HTTPONLY'] = False  # INSECURE: No HttpOnly flag
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # INSECURE: SameSite=None without Secure

# In-memory "database"
users_db: dict[str, dict] = {}
failed_attempts: dict[str, int] = {}

# INSECURE: Add CORS headers to all responses (reflects any origin with credentials)
@app.after_request
def add_cors_headers(response):
    """Add permissive CORS headers to all responses."""
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin  # INSECURE: reflects attacker origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    elif "Origin" not in request.headers:
        # For requests without Origin, allow all
        response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# JWT secret (weak for demo)
JWT_SECRET = "weak-secret-123"
JWT_ALGORITHM = "HS256"


def create_access_token(user_id: str, expires_delta: timedelta | None = None) -> str:
    """Create a JWT token with configurable expiration."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=30)  # INSECURE: 30-day expiration
    payload = {"sub": user_id, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_none_alg_token(user_id: str) -> str:
    """Create a JWT with 'none' algorithm (for testing JWT-004)."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": user_id, "iat": int(time.time())}
    header_b64 = jwt.utils.base64url_encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = jwt.utils.base64url_encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}."


def require_auth(f):
    """Decorator that validates JWT from Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            request.user_id = payload["sub"]
        except jwt.InvalidTokenError as e:
            # INSECURE: Accepts 'none' algorithm tokens!
            try:
                # Try without verification for demo purposes
                payload = jwt.decode(token, options={"verify_signature": False})
                request.user_id = payload.get("sub", "unknown")
            except jwt.InvalidTokenError:
                return jsonify({"error": f"Invalid token: {e}"}), 401

        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    """Home page - sets insecure cookies."""
    resp = make_response(jsonify({
        "message": "Welcome to VulnApp - AuthShield Test Target",
        "version": "1.0.0",
        "endpoints": [
            "/register", "/login", "/api/user", "/api/profile",
            "/api/me", "/dashboard", "/.well-known/jwks.json"
        ]
    }))

    # INSECURE: Sets session cookie without Secure, HttpOnly, SameSite
    resp.set_cookie("session", "insecure-session-value", httponly=False, secure=False, samesite="None")
    resp.set_cookie("tracking_id", "track-12345", httponly=False, secure=False)
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Registration endpoint with WEAK password policy.
    INSECURE: Allows passwords as short as 4 characters.
    """
    if request.method == "GET":
        return jsonify({
            "message": "Registration page",
            "requirements": "Password must be at least 4 characters"  # INSECURE: min 4 chars
        })

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if len(password) < 4:  # INSECURE: minimum 4 characters
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    if username in users_db:
        return jsonify({"error": "Username already exists"}), 409

    # Hash password (this part is secure)
    password_hash = generate_password_hash(password)
    users_db[username] = {
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    token = create_access_token(username)
    resp = make_response(jsonify({
        "message": "Registration successful",
        "token": token,
        "username": username
    }))
    # INSECURE: Sets auth cookie without Secure/HttpOnly
    resp.set_cookie("auth_token", token, httponly=False, secure=False, samesite="None")
    return resp, 201


@app.route("/login", methods=["POST"])
def login():
    """
    Login endpoint with NO rate limiting.
    INSECURE: No rate limiting on failed attempts.
    """
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = users_db.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        # INSECURE: Different error messages for user exists vs not
        if username in users_db:
            return jsonify({"error": "Invalid password for user: " + username}), 401
        else:
            return jsonify({"error": "User not found: " + username}), 401

    token = create_access_token(username)
    resp = make_response(jsonify({
        "message": "Login successful",
        "token": token,
        "username": username
    }))
    resp.set_cookie("auth_token", token, httponly=False, secure=False, samesite="None")
    return resp


@app.route("/api/user", methods=["GET"])
@require_auth
def get_user():
    """Protected endpoint - requires valid JWT."""
    user = users_db.get(request.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": request.user_id, "created_at": user["created_at"]})


@app.route("/api/profile", methods=["GET"])
@require_auth
def get_profile():
    """Another protected endpoint."""
    user = users_db.get(request.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "username": request.user_id,
        "profile": {"email": f"{request.user_id}@example.com", "role": "user"}
    })


@app.route("/api/me", methods=["GET"])
@require_auth
def get_me():
    """Yet another protected endpoint."""
    return jsonify({"user_id": request.user_id})


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Dashboard page (no auth required for demo)."""
    return jsonify({"message": "Dashboard", "data": [1, 2, 3]})


# CORS preflight handled by after_request middleware (reflects any origin with credentials)
# No explicit OPTIONS routes needed


@app.route("/api/", methods=["GET"])
@app.route("/api/auth", methods=["GET"])
def api_root():
    """API root - reflects Origin header."""
    origin = request.headers.get("Origin", "*")
    resp = jsonify({"message": "API Root", "origin_received": origin})
    resp.headers["Access-Control-Allow-Origin"] = origin  # INSECURE
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# JWKS endpoint - publicly exposes keys (for JWT-001 testing)
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """JWKS endpoint - INSECURE: Public key exposure for algorithm confusion demo."""
    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "authshield-demo-key",
            "alg": "RS256",
            "n": "demo",  # Simplified for demo
            "e": "AQAB"
        }]
    })


# Additional endpoints for testing
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    """Password reset - no rate limiting."""
    data = request.get_json() or {}
    email = data.get("email", "")
    return jsonify({"message": f"Reset link sent to {email}"}), 200


@app.route("/api/refresh", methods=["POST"])
def refresh_token():
    """Token refresh endpoint."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
        user_id = payload["sub"]
        new_token = create_access_token(user_id)
        return jsonify({"token": new_token})
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


if __name__ == "__main__":
    print("=" * 60)
    print("WARNING: VULNERABLE FLASK APP - FOR LOCAL TESTING ONLY")
    print("=" * 60)
    print("Starting on http://localhost:5000")
    print("Endpoints:")
    print("  GET  /                    - Home (sets insecure cookies)")
    print("  POST /register            - Weak password policy (min 4 chars)")
    print("  POST /login               - No rate limit, user enumeration")
    print("  GET  /api/user            - Protected (JWT required)")
    print("  GET  /api/profile         - Protected (JWT required)")
    print("  GET  /api/me              - Protected (JWT required)")
    print("  GET  /dashboard           - No auth required")
    print("  OPTIONS /api/*            - Permissive CORS (reflect origin + credentials)")
    print("  GET  /.well-known/jwks.json - Public JWKS (algorithm confusion)")
    print("=" * 60)
    print("Run AuthShield scan: authshield scan http://localhost:5000 --json report.json")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)