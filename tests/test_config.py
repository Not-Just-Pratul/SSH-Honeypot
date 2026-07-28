"""Tests for ssh_honeypot.config module."""

import os
from unittest.mock import patch

import pytest

from ssh_honeypot.config import (
    _env_bool,
    _env_float,
    _env_int,
    _env_str,
    AlertConfig,
    APIConfig,
    Config,
    DashboardConfig,
    DatabaseConfig,
    GeoConfig,
    HoneypotConfig,
    ThreatIntelConfig,
    config,
)


class TestEnvHelpers:
    """Test environment variable parsing helpers."""

    def test_env_bool_true_values(self):
        """Boolean env var should be True for 'true', '1', 'yes', 'on'."""
        for val in ["true", "1", "yes", "on", "True", "YES", "ON", " true "]:
            with patch.dict(os.environ, {"TEST_BOOL": val}):
                assert _env_bool("TEST_BOOL", False) is True

    def test_env_bool_false_values(self):
        """Boolean env var should be False for 'false', '0', 'no', 'off', empty."""
        for val in ["false", "0", "no", "off", "False", "", "random"]:
            with patch.dict(os.environ, {"TEST_BOOL": val}):
                assert _env_bool("TEST_BOOL", True) is False

    def test_env_bool_default(self):
        """Missing env var should return default."""
        with patch.dict(os.environ, {}, clear=True):
            assert _env_bool("MISSING_BOOL", True) is True
            assert _env_bool("MISSING_BOOL", False) is False

    def test_env_int_valid(self):
        """Valid integer env var should parse correctly."""
        with patch.dict(os.environ, {"TEST_INT": "42"}):
            assert _env_int("TEST_INT", 0) == 42

    def test_env_int_invalid(self):
        """Invalid integer env var should return default."""
        with patch.dict(os.environ, {"TEST_INT": "not_a_number"}):
            assert _env_int("TEST_INT", 100) == 100

    def test_env_int_empty(self):
        """Empty env var should return default."""
        with patch.dict(os.environ, {"TEST_INT": ""}):
            assert _env_int("TEST_INT", 99) == 99

    def test_env_int_missing(self):
        """Missing env var should return default."""
        assert _env_int("NONEXISTENT_INT", 42) == 42

    def test_env_str_valid(self):
        """Valid string env var should return stripped value."""
        with patch.dict(os.environ, {"TEST_STR": "  hello  "}):
            assert _env_str("TEST_STR", "default") == "hello"

    def test_env_str_empty(self):
        """Empty env var should return default."""
        with patch.dict(os.environ, {"TEST_STR": ""}):
            assert _env_str("TEST_STR", "fallback") == "fallback"

    def test_env_str_missing(self):
        """Missing env var should return default."""
        assert _env_str("NONEXISTENT_STR", "default") == "default"

    def test_env_float_valid(self):
        """Valid float env var should parse correctly."""
        with patch.dict(os.environ, {"TEST_FLOAT": "3.14"}):
            assert _env_float("TEST_FLOAT", 0.0) == pytest.approx(3.14)

    def test_env_float_invalid(self):
        """Invalid float env var should return default."""
        with patch.dict(os.environ, {"TEST_FLOAT": "not_a_float"}):
            assert _env_float("TEST_FLOAT", 2.5) == 2.5


class TestConfigDataclasses:
    """Test configuration dataclass initialization."""

    def test_honeypot_config_defaults(self):
        """HoneypotConfig should have sensible defaults."""
        cfg = HoneypotConfig()
        assert cfg.port == 2222
        assert cfg.host == "0.0.0.0"
        assert cfg.max_connections == 100
        assert cfg.connection_timeout == 30
        assert cfg.reject_password is True
        assert cfg.reject_public_key is True
        assert cfg.reject_keyboard_interactive is True

    def test_database_config_defaults(self):
        """DatabaseConfig should have reasonable defaults."""
        cfg = DatabaseConfig()
        assert cfg.csv_rotation_size_mb == 10
        assert cfg.csv_max_backups == 5

    def test_geo_config_defaults(self):
        """GeoConfig should have unknown defaults."""
        cfg = GeoConfig()
        assert cfg.default_country == "Unknown"
        assert cfg.default_city == "Unknown"
        assert cfg.default_lat == 0.0
        assert cfg.default_lon == 0.0

    def test_api_config_defaults(self):
        """APIConfig should have correct defaults."""
        cfg = APIConfig()
        assert cfg.port == 8502
        assert cfg.enabled is True
        assert cfg.jwt_enabled is False
        assert cfg.jwt_secret == ""

    def test_threat_intel_config_defaults(self):
        """ThreatIntelConfig should have empty keys by default."""
        cfg = ThreatIntelConfig()
        assert cfg.abuseipdb_api_key == ""
        assert cfg.virustotal_api_key == ""
        assert cfg.greynoise_api_key == ""
        assert cfg.shodan_api_key == ""
        assert cfg.enable_threat_score is False

    def test_alert_config_defaults(self):
        """AlertConfig should have all channels disabled by default."""
        cfg = AlertConfig()
        assert cfg.email_enabled is False
        assert cfg.discord_webhook_url == ""
        assert cfg.slack_webhook_url == ""
        assert cfg.telegram_bot_token == ""
        assert cfg.telegram_chat_id == ""

    def test_dashboard_config_defaults(self):
        """DashboardConfig should have standard defaults."""
        cfg = DashboardConfig()
        assert cfg.port == 8501
        assert cfg.theme == "dark"
        assert cfg.layout == "wide"

    def test_top_level_config_composition(self):
        """Config should compose all sub-configs."""
        cfg = Config()
        assert hasattr(cfg, "honeypot")
        assert hasattr(cfg, "database")
        assert hasattr(cfg, "geo")
        assert hasattr(cfg, "threat_intel")
        assert hasattr(cfg, "alerts")
        assert hasattr(cfg, "dashboard")
        assert hasattr(cfg, "api")

    def test_global_config_singleton(self):
        """Global config should be an instance of Config."""
        assert isinstance(config, Config)
