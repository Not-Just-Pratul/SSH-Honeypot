"""REST API server for SSH Honeypot.

Provides a lightweight HTTP API for external integrations,
including endpoints for attack data, statistics, and health checks.
"""

import json as _json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Dict
from urllib.parse import parse_qs, urlparse

from database import get_all_logs, get_latest, get_total_count, get_today_count, get_unique_countries, get_unique_ips

MAX_REQUEST_SIZE = 1024 * 1024


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""
    daemon_threads = True
    request_queue_size = 128


class HoneypotAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the honeypot REST API."""

    def do_GET(self) -> None:
        """Handle GET requests."""
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
            else:
                self._respond(404, {"error": "Not found"})
        except Exception as exc:
            logger = logging.getLogger("ssh_honeypot")
            logger.error("API handler error: %s", exc)
            self._respond(500, {"error": "Internal server error"})

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
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
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
    logger.info("  GET /api/attacks        - All attack logs")
    logger.info("  GET /api/attacks/latest  - Latest attack logs (?limit=N)")
    logger.info("  GET /api/stats           - Aggregate statistics")
    logger.info("  GET /api/health          - Health check")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        logger.info("API server stopped.")


if __name__ == "__main__":
    start_api_server()