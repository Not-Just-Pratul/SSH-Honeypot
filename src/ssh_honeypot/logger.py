"""Logging module for SSH Honeypot.

Provides structured logging setup and event recording
for captured SSH authentication attempts.
"""

import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from typing import Any

from ssh_honeypot.config import config
from ssh_honeypot.database import insert_attack
from ssh_honeypot.geo import lookup_ip


def setup_logging(
    log_level: int = logging.INFO,
    log_dir: str = "logs",
    log_file: str = "honeypot.log",
) -> logging.Logger:
    """Configure and return a structured logger.

    Creates console and rotating file handlers.

    Args:
        log_level: Minimum log level to capture.
        log_dir: Directory for log files.
        log_file: Filename for the log file.

    Returns:
        Configured logger instance.
    """
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("ssh_honeypot")
    logger.setLevel(log_level)

    if not logger.handlers:
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)

        file_handler = RotatingFileHandler(
            os.path.join(log_dir, log_file),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


honeypot_logger = setup_logging()


def sanitize_string(value: str) -> str:
    """Sanitize a string for safe storage.

    Removes null bytes, carriage returns, and newlines
    to prevent log injection and data corruption.

    Args:
        value: Raw input string.

    Returns:
        Sanitized string.
    """
    if value is None:
        return ""
    sanitized = str(value).strip()
    sanitized = sanitized.replace("\x00", "")
    sanitized = sanitized.replace("\r", "")
    sanitized = sanitized.replace("\n", "")
    return sanitized


def record_attack(event: dict[str, Any]) -> None:
    """Record an attack attempt to the database and CSV.

    Enriches the IP address with geolocation data before
    persisting the record.

    Args:
        event: Dictionary containing attack event data.
               Expected keys: timestamp, ip, username, auth_method,
               status, client_version, attempts, session_id,
               connection_duration, protocol_version.
    """
    try:
        enriched = lookup_ip(event.get("ip", ""))
        record: dict[str, Any] = {
            "timestamp": event.get("timestamp", ""),
            "ip": sanitize_string(event.get("ip", "")),
            "country": enriched.get("country", "Unknown"),
            "city": enriched.get("city", "Unknown"),
            "username": sanitize_string(event.get("username", "")),
            "auth_method": sanitize_string(event.get("auth_method", "password")),
            "client_version": sanitize_string(event.get("client_version", "")),
            "attempts": int(event.get("attempts", 1)),
            "status": sanitize_string(event.get("status", "failure")),
            "latitude": enriched.get("latitude", 0.0),
            "longitude": enriched.get("longitude", 0.0),
            "asn": enriched.get("asn", "Unknown"),
            "org": enriched.get("org", "Unknown"),
            "session_id": sanitize_string(event.get("session_id", "")),
            "connection_duration": float(event.get("connection_duration", 0.0)),
            "protocol_version": sanitize_string(event.get("protocol_version", "")),
            "parsed": 1,
        }
        insert_attack(record)
        honeypot_logger.info(
            "Attack recorded: ip=%s user=%s status=%s country=%s",
            record["ip"],
            record["username"],
            record["status"],
            record["country"],
        )
        _send_alerts_async(record)
    except Exception as exc:
        honeypot_logger.error("Failed to record attack event: %s", exc)


def _send_alerts_async(record: dict[str, Any]) -> None:
    """Send alert notifications in a background thread.

    Dispatches to all configured alert channels.
    """
    thread = threading.Thread(
        target=_send_all_alerts,
        args=(record,),
        daemon=True,
    )
    thread.start()


def _send_all_alerts(record: dict[str, Any]) -> None:
    """Send alerts through all configured channels.

    Args:
        record: The attack record dict.
    """
    if config.alerts.telegram_bot_token and config.alerts.telegram_chat_id:
        _send_telegram_alert(record, config.alerts.telegram_bot_token, config.alerts.telegram_chat_id)

    if config.alerts.discord_webhook_url:
        _send_discord_alert(record, config.alerts.discord_webhook_url)

    if config.alerts.slack_webhook_url:
        _send_slack_alert(record, config.alerts.slack_webhook_url)


def _send_telegram_alert(record: dict[str, Any], token: str, chat_id: str) -> None:
    """Send a Telegram notification for a new attack record.

    Args:
        record: The attack record dict.
        token: Telegram bot token.
        chat_id: Telegram chat ID.
    """
    try:
        import requests

        message = (
            f"⚠️ *SSH Honeypot Alert*\n"
            f"IP: `{record.get('ip', 'N/A')}`\n"
            f"User: `{record.get('username', 'N/A')}`\n"
            f"Method: `{record.get('auth_method', 'N/A')}`\n"
            f"Country: {record.get('country', 'N/A')}\n"
            f"Status: {record.get('status', 'N/A')}\n"
            f"ASN: {record.get('asn', 'N/A')}\n"
            f"Time: {record.get('timestamp', 'N/A')}"
        )
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
            },
            timeout=5,
        )
    except Exception as exc:
        honeypot_logger.error("Telegram alert failed: %s", exc)


def _send_discord_alert(record: dict[str, Any], webhook_url: str) -> None:
    """Send a Discord notification for a new attack record.

    Args:
        record: The attack record dict.
        webhook_url: Discord webhook URL.
    """
    try:
        import requests

        color = 15548997  # Discord red
        embed = {
            "title": "SSH Honeypot Alert",
            "color": color,
            "fields": [
                {"name": "IP Address", "value": record.get("ip", "N/A"), "inline": True},
                {"name": "Username", "value": record.get("username", "N/A"), "inline": True},
                {"name": "Method", "value": record.get("auth_method", "N/A"), "inline": True},
                {"name": "Country", "value": record.get("country", "N/A"), "inline": True},
                {"name": "Status", "value": record.get("status", "N/A"), "inline": True},
                {"name": "ASN", "value": record.get("asn", "N/A"), "inline": True},
            ],
            "timestamp": record.get("timestamp", ""),
        }
        requests.post(
            webhook_url,
            json={"embeds": [embed]},
            timeout=5,
        )
    except Exception as exc:
        honeypot_logger.error("Discord alert failed: %s", exc)


def _send_slack_alert(record: dict[str, Any], webhook_url: str) -> None:
    """Send a Slack notification for a new attack record.

    Uses Slack's block kit formatting.

    Args:
        record: The attack record dict.
        webhook_url: Slack webhook URL.
    """
    try:
        import requests

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "⚠️ SSH Honeypot Alert"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP:*\n{record.get('ip', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Username:*\n{record.get('username', 'N/A')}"},
                ],
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Method:*\n{record.get('auth_method', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Country:*\n{record.get('country', 'N/A')}"},
                ],
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*ASN:*\n{record.get('asn', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{record.get('status', 'N/A')}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Time: {record.get('timestamp', 'N/A')}"},
                ],
            },
        ]
        requests.post(
            webhook_url,
            json={"blocks": blocks},
            timeout=5,
        )
    except Exception as exc:
        honeypot_logger.error("Slack alert failed: %s", exc)
