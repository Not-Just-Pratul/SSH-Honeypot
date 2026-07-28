"""Project configuration and environment variable management.

Loads all settings from environment variables with sensible defaults
for the SSH Honeypot + Live Threat Intelligence Dashboard.
"""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    """Read a string environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


@dataclass
class HoneypotConfig:
    """SSH Honeypot server configuration."""

    host: str = field(default_factory=lambda: _env_str("HONEYPOT_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("HONEYPOT_PORT", 2222))
    banner: str = field(default_factory=lambda: _env_str("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"))
    server_version: str = field(default_factory=lambda: _env_str("HONEYPOT_SERVER_VERSION", "SSH-2.0-OpenSSH_8.9p1"))
    max_connections: int = field(default_factory=lambda: _env_int("HONEYPOT_MAX_CONNECTIONS", 100))
    connection_timeout: int = field(default_factory=lambda: _env_int("HONEYPOT_CONNECTION_TIMEOUT", 30))
    max_auth_tries: int = field(default_factory=lambda: _env_int("HONEYPOT_MAX_AUTH_TRIES", 3))
    host_key_path: str = field(
        default_factory=lambda: _env_str(
            "HONEYPOT_HOST_KEY_PATH",
            os.path.join(os.path.dirname(__file__), "..", "..", "keys", "ssh_host_rsa_key"),
        )
    )
    reject_password: bool = field(default_factory=lambda: _env_bool("HONEYPOT_REJECT_PASSWORD", True))
    reject_public_key: bool = field(default_factory=lambda: _env_bool("HONEYPOT_REJECT_PUBLIC_KEY", True))
    reject_keyboard_interactive: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_REJECT_KEYBOARD_INTERACTIVE", True)
    )


@dataclass
class DatabaseConfig:
    """Database and CSV logging configuration."""

    db_path: str = field(
        default_factory=lambda: _env_str(
            "DATABASE_PATH",
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "attack_logs.db"),
        )
    )
    csv_path: str = field(
        default_factory=lambda: _env_str(
            "CSV_PATH",
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "attack_logs.csv"),
        )
    )
    csv_rotation_size_mb: int = field(default_factory=lambda: _env_int("CSV_ROTATION_SIZE_MB", 10))
    csv_max_backups: int = field(default_factory=lambda: _env_int("CSV_MAX_BACKUPS", 5))
    init_sql: str = field(default_factory=lambda: _env_str("INIT_SQL_PATH", ""))


def _env_float(name: str, default: float) -> float:
    """Read a float environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


@dataclass
class GeoConfig:
    """GeoIP enrichment configuration."""

    geoip_city_db: str | None = field(default_factory=lambda: os.environ.get("GEOIP_CITY_DB") or None)
    geoip_asn_db: str | None = field(default_factory=lambda: os.environ.get("GEOIP_ASN_DB") or None)
    default_country: str = field(default_factory=lambda: _env_str("GEOIP_DEFAULT_COUNTRY", "Unknown"))
    default_city: str = field(default_factory=lambda: _env_str("GEOIP_DEFAULT_CITY", "Unknown"))
    default_lat: float = field(default_factory=lambda: _env_float("GEOIP_DEFAULT_LAT", 0.0))
    default_lon: float = field(default_factory=lambda: _env_float("GEOIP_DEFAULT_LON", 0.0))
    default_asn: str = field(default_factory=lambda: _env_str("GEOIP_DEFAULT_ASN", "Unknown"))
    default_org: str = field(default_factory=lambda: _env_str("GEOIP_DEFAULT_ORG", "Unknown"))
    abuseipdb_api_key: str = field(default_factory=lambda: _env_str("ABUSEIPDB_API_KEY", ""))
    abuseipdb_base_url: str = field(
        default_factory=lambda: _env_str("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2")
    )


@dataclass
class ThreatIntelConfig:
    """Threat intelligence enrichment configuration."""

    abuseipdb_api_key: str = field(default_factory=lambda: _env_str("ABUSEIPDB_API_KEY", ""))
    abuseipdb_base_url: str = field(
        default_factory=lambda: _env_str("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2")
    )
    virustotal_api_key: str = field(default_factory=lambda: _env_str("VIRUSTOTAL_API_KEY", ""))
    virustotal_base_url: str = field(
        default_factory=lambda: _env_str("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3")
    )
    greynoise_api_key: str = field(default_factory=lambda: _env_str("GREYNOISE_API_KEY", ""))
    greynoise_base_url: str = field(
        default_factory=lambda: _env_str("GREYNOISE_BASE_URL", "https://api.greynoise.io/v3")
    )
    shodan_api_key: str = field(default_factory=lambda: _env_str("SHODAN_API_KEY", ""))
    shodan_base_url: str = field(default_factory=lambda: _env_str("SHODAN_BASE_URL", "https://api.shodan.io"))
    enable_threat_score: bool = field(default_factory=lambda: _env_bool("ENABLE_THREAT_SCORE", False))
    threat_score_cache_ttl: int = field(default_factory=lambda: _env_int("THREAT_SCORE_CACHE_TTL", 3600))


@dataclass
class AlertConfig:
    """Alert notification configuration."""

    email_enabled: bool = field(default_factory=lambda: _env_bool("EMAIL_ENABLED", False))
    email_smtp_server: str = field(default_factory=lambda: _env_str("EMAIL_SMTP_SERVER", "smtp.gmail.com"))
    email_smtp_port: int = field(default_factory=lambda: _env_int("EMAIL_SMTP_PORT", 587))
    email_sender: str = field(default_factory=lambda: _env_str("EMAIL_SENDER", ""))
    email_recipients: list[str] = field(default_factory=list)
    email_username: str = field(default_factory=lambda: _env_str("EMAIL_USERNAME", ""))
    email_password: str = field(default_factory=lambda: _env_str("EMAIL_PASSWORD", ""))

    discord_webhook_url: str = field(default_factory=lambda: _env_str("DISCORD_WEBHOOK_URL", ""))
    slack_webhook_url: str = field(default_factory=lambda: _env_str("SLACK_WEBHOOK_URL", ""))
    telegram_bot_token: str = field(default_factory=lambda: _env_str("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = field(default_factory=lambda: _env_str("TELEGRAM_CHAT_ID", ""))


@dataclass
class DashboardConfig:
    """Streamlit dashboard configuration."""

    port: int = field(default_factory=lambda: _env_int("DASHBOARD_PORT", 8501))
    host: str = field(default_factory=lambda: _env_str("DASHBOARD_HOST", "0.0.0.0"))
    refresh_interval: int = field(default_factory=lambda: _env_int("DASHBOARD_REFRESH_INTERVAL", 5))
    theme: str = field(default_factory=lambda: _env_str("DASHBOARD_THEME", "dark"))
    page_title: str = field(default_factory=lambda: _env_str("DASHBOARD_PAGE_TITLE", "SSH Honeypot SOC Dashboard"))
    page_icon: str = field(default_factory=lambda: _env_str("DASHBOARD_PAGE_ICON", "🛡️"))
    layout: str = field(default_factory=lambda: _env_str("DASHBOARD_LAYOUT", "wide"))
    initial_sidebar_state: str = field(default_factory=lambda: _env_str("DASHBOARD_INITIAL_SIDEBAR_STATE", "expanded"))
    auth_enabled: bool = field(default_factory=lambda: _env_bool("DASHBOARD_AUTH_ENABLED", False))
    auth_username: str = field(default_factory=lambda: _env_str("DASHBOARD_USER", "admin"))
    auth_password: str = field(default_factory=lambda: _env_str("DASHBOARD_PASS", ""))


@dataclass
class APIConfig:
    """REST API server configuration."""

    host: str = field(default_factory=lambda: _env_str("API_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("API_PORT", 8502))
    enabled: bool = field(default_factory=lambda: _env_bool("API_ENABLED", True))
    jwt_secret: str = field(default_factory=lambda: _env_str("API_JWT_SECRET", ""))
    jwt_enabled: bool = field(default_factory=lambda: _env_bool("API_JWT_ENABLED", False))


@dataclass
class Config:
    """Top-level configuration container."""

    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    geo: GeoConfig = field(default_factory=GeoConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    api: APIConfig = field(default_factory=APIConfig)


config = Config()
