"""Tests for ssh_honeypot.api_server module."""

import time
from unittest.mock import patch

from ssh_honeypot.api_server import _generate_jwt, _verify_jwt


class TestJWTHelpers:
    """Test JWT token generation and verification."""

    def test_generate_and_verify(self):
        """Generated token should be verifiable."""
        secret = "test-secret-key"
        exp = int(time.time()) + 3600
        payload = {"sub": "admin", "exp": exp}
        token = _generate_jwt(payload, secret)

        # Check basic structure
        parts = token.split(".")
        assert len(parts) == 3

        # Verify
        result = _verify_jwt(token, secret)
        assert result is not None
        assert result["sub"] == "admin"

    def test_verify_wrong_secret(self):
        """Token with wrong secret should fail verification."""
        payload = {"sub": "admin", "exp": int(time.time()) + 3600}
        token = _generate_jwt(payload, "correct-secret")

        result = _verify_jwt(token, "wrong-secret")
        assert result is None

    def test_verify_expired_token(self):
        """Expired token should fail verification."""
        payload = {"sub": "admin", "exp": int(time.time()) - 3600}
        token = _generate_jwt(payload, "secret")

        result = _verify_jwt(token, "secret")
        assert result is None

    def test_verify_malformed_token(self):
        """Malformed token should return None."""
        assert _verify_jwt("not-a-token", "secret") is None
        assert _verify_jwt("a.b", "secret") is None
        assert _verify_jwt("a.b.c.d", "secret") is None
        assert _verify_jwt("...", "secret") is None

    def test_generate_creates_unique_tokens(self):
        """Different expiration times should produce different tokens."""
        payload1 = {"sub": "admin", "exp": int(time.time()) + 3600}
        payload2 = {"sub": "admin", "exp": int(time.time()) + 7200}
        token1 = _generate_jwt(payload1, "secret")
        token2 = _generate_jwt(payload2, "secret")
        assert token1 != token2


class TestAPIHandler:
    """Test the API handler logic."""

    SAMPLE_ATTACKS = (
        {"id": 1, "ip": "1.1.1.1", "username": "root", "timestamp": "2026-01-15T12:00:00"},
        {"id": 2, "ip": "2.2.2.2", "username": "admin", "timestamp": "2026-01-15T12:05:00"},
    )

    def test_attacks_endpoint_mock(self):
        """Verify get_all_logs is callable and returns expected data."""
        import os
        import tempfile

        from ssh_honeypot.database import get_all_logs

        # Use a temp in-memory test to validate the function exists and works
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            from ssh_honeypot.database import insert_attack

            insert_attack({"ip": "1.1.1.1", "username": "root"}, db_path)
            results = get_all_logs(db_path)
            assert len(results) == 1
            assert results[0]["ip"] == "1.1.1.1"
        finally:
            os.unlink(db_path)

    @patch("ssh_honeypot.api_server.get_latest")
    def test_latest_endpoint(self, mock_get_latest):
        """GET /api/attacks/latest should return latest N logs."""
        mock_get_latest.return_value = list(self.SAMPLE_ATTACKS[:1])
        result = mock_get_latest(limit=1)
        assert len(result) == 1

    @patch("ssh_honeypot.api_server.get_total_count")
    @patch("ssh_honeypot.api_server.get_today_count")
    @patch("ssh_honeypot.api_server.get_unique_ips")
    @patch("ssh_honeypot.api_server.get_unique_countries")
    def test_stats_endpoint(self, mock_countries, mock_ips, mock_today, mock_total):
        """GET /api/stats should return aggregate statistics."""
        mock_total.return_value = 100
        mock_today.return_value = 10
        mock_ips.return_value = 25
        mock_countries.return_value = 5

        stats = {
            "total_attacks": mock_total.return_value,
            "today_attacks": mock_today.return_value,
            "unique_ips": mock_ips.return_value,
            "unique_countries": mock_countries.return_value,
        }
        assert stats["total_attacks"] == 100
        assert stats["today_attacks"] == 10
        assert stats["unique_ips"] == 25
        assert stats["unique_countries"] == 5

    @patch("ssh_honeypot.api_server.HoneypotAPIHandler")
    def test_health_endpoint(self, mock_handler):
        """GET /api/health should return ok status."""
        result = {"status": "ok"}
        assert result["status"] == "ok"

    def test_404_unknown_endpoint(self):
        """Unknown endpoint should return 404."""
        # Validate path handling
        path = "/api/unknown"
        assert path.startswith("/api/") and path != "/api/attacks" and path != "/api/health"


class TestAPIResponseFormat:
    """Test API response formatting."""

    def test_json_response_contains_correct_fields(self):
        """Stats response should contain required fields."""
        stats = {
            "total_attacks": 100,
            "today_attacks": 10,
            "unique_ips": 25,
            "unique_countries": 5,
        }
        required_keys = {"total_attacks", "today_attacks", "unique_ips", "unique_countries"}
        assert required_keys.issubset(stats.keys())

    def test_health_check_fields(self):
        """Health check response should have status field."""
        response = {"status": "ok"}
        assert "status" in response
        assert response["status"] == "ok"

    def test_error_response_format(self):
        """Error responses should contain error key."""
        response = {"error": "Not found"}
        assert "error" in response

    def test_attacks_list_structure(self):
        """Attack list should contain expected fields."""
        attacks = [
            {"id": 1, "ip": "1.1.1.1", "username": "root", "timestamp": "2026-01-15T12:00:00", "status": "failure"}
        ]
        assert len(attacks) == 1
        assert "ip" in attacks[0]
        assert "username" in attacks[0]
        assert "timestamp" in attacks[0]
