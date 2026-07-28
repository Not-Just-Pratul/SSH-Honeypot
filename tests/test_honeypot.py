"""Tests for ssh_honeypot.honeypot module."""

import time
from unittest.mock import MagicMock, patch

import pytest

from ssh_honeypot.honeypot import (
    BruteForceDetector,
    HoneypotServer,
    get_brute_force_detector,
)


class TestHoneypotServer:
    """Test HoneypotServer behavior."""

    def test_server_initialization(self):
        """Server should initialize with correct defaults."""
        server = HoneypotServer("1.2.3.4", 22)
        assert server.client_ip == "1.2.3.4"
        assert server.client_port == 22
        assert server.attempt_count == 0
        assert server.auth_method == "none"

    def test_check_auth_password_returns_failed(self):
        """check_auth_password should always return AUTH_FAILED."""
        server = HoneypotServer("1.2.3.4", 22)
        import paramiko

        result = server.check_auth_password("admin", "password123")
        assert result == paramiko.AUTH_FAILED
        assert server.username_attempted == "admin"
        assert server.attempt_count == 1

    def test_check_auth_publickey_returns_failed(self):
        """check_auth_publickey should always return AUTH_FAILED."""
        server = HoneypotServer("1.2.3.4", 22)
        import paramiko

        result = server.check_auth_publickey("testuser", MagicMock())
        assert result == paramiko.AUTH_FAILED
        assert server.attempt_count == 1

    def test_check_auth_none_returns_failed(self):
        """check_auth_none should always return AUTH_FAILED."""
        server = HoneypotServer("1.2.3.4", 22)
        import paramiko

        result = server.check_auth_none("anonymous")
        assert result == paramiko.AUTH_FAILED
        assert server.attempt_count == 1
        assert server.auth_method == "none"

    def test_check_channel_shell_denied(self):
        """check_channel_shell_request should return False."""
        server = HoneypotServer("1.2.3.4", 22)
        assert server.check_channel_shell_request(None) is False

    def test_check_channel_exec_denied(self):
        """check_channel_exec_request should return False."""
        server = HoneypotServer("1.2.3.4", 22)
        assert server.check_channel_exec_request(None, b"ls") is False

    def test_check_channel_pty_denied(self):
        """check_channel_pty_request should return False."""
        server = HoneypotServer("1.2.3.4", 22)
        assert server.check_channel_pty_request(None, "xterm", 80, 24, 0, 0, None) is False

    def test_check_channel_window_adjust_allowed(self):
        """check_channel_window_adjust_request should return True."""
        server = HoneypotServer("1.2.3.4", 22)
        assert server.check_channel_window_adjust_request(None, 100) is True

    def test_session_id_generation(self):
        """Session ID should be unique per instance."""
        server1 = HoneypotServer("1.2.3.4", 22)
        # Wait for time to advance enough for different session IDs
        time.sleep(1.1)
        server2 = HoneypotServer("1.2.3.4", 22)
        assert server1.session_id != server2.session_id


class TestBruteForceDetector:
    """Test brute-force detection logic."""

    def test_detector_initialization(self):
        """Detector should initialize with correct defaults."""
        detector = BruteForceDetector()
        assert detector.threshold == 5
        assert detector.window_seconds == 60

    def test_single_attempt_not_banned(self):
        """A single attempt should not trigger a ban."""
        detector = BruteForceDetector(threshold=3, window_seconds=60)
        result = detector.record_attempt("1.2.3.4")
        assert result is False

    def test_threshold_triggers_ban(self):
        """Crossing the threshold should trigger a ban."""
        detector = BruteForceDetector(threshold=3, window_seconds=60)
        for _ in range(3):
            detector.record_attempt("1.2.3.4")
        assert "1.2.3.4" in detector.get_banned_ips()

    def test_below_threshold_not_banned(self):
        """Staying below the threshold should not trigger a ban."""
        detector = BruteForceDetector(threshold=5, window_seconds=60)
        for _ in range(4):
            detector.record_attempt("1.2.3.4")
        assert "1.2.3.4" not in detector.get_banned_ips()

    def test_is_banned_returns_true(self):
        """is_banned should return True for banned IPs."""
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        for _ in range(2):
            detector.record_attempt("1.2.3.4")
        assert detector.is_banned("1.2.3.4") is True

    def test_multiple_ips_tracked_independently(self):
        """Multiple IPs should be tracked independently."""
        detector = BruteForceDetector(threshold=3, window_seconds=60)
        for _ in range(3):
            detector.record_attempt("1.2.3.4")
        for _ in range(2):
            detector.record_attempt("5.6.7.8")
        assert "1.2.3.4" in detector.get_banned_ips()
        assert "5.6.7.8" not in detector.get_banned_ips()

    def test_get_stats(self):
        """get_stats should return correct statistics."""
        detector = BruteForceDetector(threshold=5, window_seconds=60)
        for _ in range(3):
            detector.record_attempt("1.2.3.4")
        stats = detector.get_stats()
        assert stats["threshold"] == 5
        assert stats["window_seconds"] == 60
        assert stats["currently_banned"] == 0

    def test_unban_after_expiry(self):
        """Banned IP should be unbanned after ban_duration expires."""
        detector = BruteForceDetector(threshold=2, window_seconds=60, ban_duration=0)
        for _ in range(2):
            detector.record_attempt("1.2.3.4")
        # ban_duration=0 means immediate expiry
        time.sleep(0.01)
        assert detector.is_banned("1.2.3.4") is False

    def test_singleton_get_detector(self):
        """get_brute_force_detector should return the same instance."""
        d1 = get_brute_force_detector()
        d2 = get_brute_force_detector()
        assert d1 is d2

    def test_custom_threshold(self):
        """Custom threshold should be respected."""
        detector = BruteForceDetector(threshold=10, window_seconds=30)
        assert detector.threshold == 10
        assert detector.window_seconds == 30


class TestHostKeyLoading:
    """Test SSH host key loading."""

    def test_host_key_file_not_found(self):
        """Missing host key should raise FileNotFoundError."""
        # Reset the cache
        import ssh_honeypot.honeypot as h
        from ssh_honeypot.honeypot import _load_host_key

        h._cached_host_key = None

        with (
            patch("ssh_honeypot.config.config.honeypot.host_key_path", "/nonexistent/key"),
            pytest.raises(FileNotFoundError, match="Host key not found"),
        ):
            _load_host_key()
