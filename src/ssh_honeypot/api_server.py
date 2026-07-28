"""REST API server for SSH Honeypot.

Provides a lightweight HTTP API for external integrations,
including endpoints for attack data, statistics, and health checks.
"""

import hashlib
import hmac
import json as _json
import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

from ssh_honeypot.config import config
from ssh_honeypot.database import (
    get_all_logs,
    get_latest,
    get_today_count,
    get_total_count,
    get_unique_countries,
    get_unique_ips,
)

MAX_REQUEST_SIZE = 1024 * 1024


def _generate_jwt(payload: dict, secret: str) -> str:
    """Generate a simple HMAC-SHA256 JWT-like token.

    Args:
        payload: Dictionary of claims to include in the token.
        secret: HMAC secret key.

    Returns:
        Encoded token string.
    """
    import base64

    header = _json.dumps({"alg": "HS256", "typ": "JWT"})
    b64_header = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()

    payload["iat"] = int(time.time())
    body = _json.dumps(payload)
    b64_body = base64.urlsafe_b64encode(body.encode()).rstrip(b"=").decode()

    signature = hmac.new(
        secret.encode(),
        f"{b64_header}.{b64_body}".encode(),
        hashlib.sha256,
    ).digest()
    b64_sig = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{b64_header}.{b64_body}.{b64_sig}"


def _verify_jwt(token: str, secret: str) -> dict | None:
    """Verify a JWT token and return its payload if valid.

    Args:
        token: The token string to verify.
        secret: HMAC secret key.

    Returns:
        Decoded payload dict if valid, None otherwise.
    """
    import base64

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        b64_header, b64_body, b64_sig = parts

        expected_sig = hmac.new(
            secret.encode(),
            f"{b64_header}.{b64_body}".encode(),
            hashlib.sha256,
        ).digest()
        actual_sig = base64.urlsafe_b64decode(b64_sig + "==")

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        padding = 4 - len(b64_body) % 4
        if padding != 4:
            b64_body += "=" * padding
        body = base64.urlsafe_b64decode(b64_body)
        payload = _json.loads(body)

        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""

    daemon_threads = True
    request_queue_size = 128


class HoneypotAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the honeypot REST API."""

    def _check_auth(self) -> bool:
        """Check JWT authentication if enabled.

        Returns:
            True if authentication passes or is disabled.
        """
        if not config.api.jwt_enabled or not config.api.jwt_secret:
            return True

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._respond(401, {"error": "Missing or invalid Authorization header"})
            return False

        token = auth_header[7:]
        payload = _verify_jwt(token, config.api.jwt_secret)
        if payload is None:
            self._respond(401, {"error": "Invalid or expired token"})
            return False

        return True

    def do_GET(self) -> None:
        """Handle GET requests."""
        if not self._check_auth():
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        if content_length > MAX_REQUEST_SIZE:
            self._respond(413, {"error": "Request too large"})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query_params = parse_qs(parsed.query)

        try:
            if path == "/api/attacks":
                data = get_all_logs()
                self._respond(200, data)
            elif path == "/api/attacks/latest":
                limit = int(query_params.get("limit", [50])[0])
                data = get_latest(limit=limit)
                self._respond(200, data)
            elif path == "/api/stats":
                stats = {
                    "total_attacks": get_total_count(),
                    "today_attacks": get_today_count(),
                    "unique_ips": get_unique_ips(),
                    "unique_countries": get_unique_countries(),
                }
                self._respond(200, stats)
            elif path == "/api/health":
                self._respond(200, {"status": "ok"})
            elif path == "/api/auth/token":
                self._respond(405, {"error": "Use POST to obtain a token"})
            else:
                self._respond(404, {"error": "Not found"})
        except Exception as exc:
            logger = logging.getLogger("ssh_honeypot")
            logger.error("API handler error: %s", exc)
            self._respond(500, {"error": "Internal server error"})

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/auth/token":
            self._handle_auth_token()
        else:
            self._respond(404, {"error": "Not found"})

    def _handle_auth_token(self) -> None:
        """Handle API token authentication."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_REQUEST_SIZE:
            self._respond(413, {"error": "Request too large"})
            return

        try:
            body = self.rfile.read(content_length)
            data = _json.loads(body)
        except Exception:
            self._respond(400, {"error": "Invalid JSON body"})
            return

        username = data.get("username", "")
        password = data.get("password", "")

        if username == config.dashboard.auth_username and password == config.dashboard.auth_password:
            token = _generate_jwt(
                {
                    "sub": username,
                    "exp": int(time.time()) + 3600,  # 1 hour expiry
                },
                config.api.jwt_secret or "default-secret-change-me",
            )
            self._respond(200, {"token": token, "token_type": "Bearer", "expires_in": 3600})
        else:
            self._respond(401, {"error": "Invalid credentials"})

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self._respond(200, {}, cors=True)

    def _respond(
        self,
        code: int,
        data: object,
        cors: bool = False,
    ) -> None:
        """Send a JSON response.

        Args:
            code: HTTP status code.
            data: Response data to serialize as JSON.
            cors: Whether to include CORS headers.
        """
        headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
        self.send_response(code)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(_json.dumps(data, default=str).encode("utf-8"))

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        """Log API requests to the standard logger."""
        logger = logging.getLogger("ssh_honeypot")
        logger.info("[API] %s", format % args)


def start_api_server(host: str = "0.0.0.0", port: int = 8502) -> None:
    """Start the REST API server.

    Args:
        host: Bind address.
        port: Bind port.
    """
    server = ThreadedHTTPServer((host, port), HoneypotAPIHandler)
    logger = logging.getLogger("ssh_honeypot")
    logger.info("REST API server listening on %s:%d", host, port)
    logger.info("Endpoints:")
    logger.info("  GET  /api/attacks        - All attack logs")
    logger.info("  GET  /api/attacks/latest  - Latest attack logs (?limit=N)")
    logger.info("  GET  /api/stats           - Aggregate statistics")
    logger.info("  GET  /api/health          - Health check")
    logger.info("  POST /api/auth/token      - Obtain JWT token")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        logger.info("API server stopped.")


if __name__ == "__main__":
    start_api_server()
