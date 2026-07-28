"""Database layer for SSH Honeypot.

Provides SQLite and CSV storage with reusable functions
for inserting, querying, and exporting attack log data.
"""

import csv
import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from ssh_honeypot.config import DatabaseConfig, config

logger = logging.getLogger(__name__)


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create and return a SQLite database connection.

    Args:
        db_path: Optional path to the database file.
                 Defaults to config.database.db_path.

    Returns:
        An open sqlite3.Connection.
    """
    path = db_path or config.database.db_path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the attack_logs table if it does not exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            country TEXT DEFAULT 'Unknown',
            city TEXT DEFAULT 'Unknown',
            username TEXT NOT NULL,
            auth_method TEXT DEFAULT 'password',
            client_version TEXT DEFAULT '',
            attempts INTEGER DEFAULT 1,
            status TEXT DEFAULT 'failure',
            latitude REAL DEFAULT 0.0,
            longitude REAL DEFAULT 0.0,
            asn TEXT DEFAULT 'Unknown',
            org TEXT DEFAULT 'Unknown',
            session_id TEXT DEFAULT '',
            connection_duration REAL DEFAULT 0.0,
            protocol_version TEXT DEFAULT '',
            parsed BOOLEAN DEFAULT 0
        )
    """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_attack_logs_ip
        ON attack_logs(ip)
    """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp
        ON attack_logs(timestamp)
    """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_attack_logs_username
        ON attack_logs(username)
    """
    )
    conn.commit()


def insert_attack(data: Dict[str, Any], db_path: Optional[str] = None) -> int:
    """Insert an attack record into the database and CSV file.

    Args:
        data: Dictionary with attack log fields.
        db_path: Optional database path override.

    Returns:
        The row ID of the inserted record.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO attack_logs (
                timestamp, ip, country, city, username, auth_method,
                client_version, attempts, status, latitude, longitude,
                asn, org, session_id, connection_duration, protocol_version, parsed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("timestamp", datetime.utcnow().isoformat()),
                _clean_string(data.get("ip", "")),
                _clean_string(data.get("country", "Unknown")),
                _clean_string(data.get("city", "Unknown")),
                _clean_string(data.get("username", "")),
                _clean_string(data.get("auth_method", "password")),
                _clean_string(data.get("client_version", "")),
                int(data.get("attempts", 1)),
                _clean_string(data.get("status", "failure")),
                float(data.get("latitude", 0.0)),
                float(data.get("longitude", 0.0)),
                _clean_string(data.get("asn", "Unknown")),
                _clean_string(data.get("org", "Unknown")),
                _clean_string(data.get("session_id", "")),
                float(data.get("connection_duration", 0.0)),
                _clean_string(data.get("protocol_version", "")),
                int(data.get("parsed", 0)),
            ),
        )
        conn.commit()
        row_id = cursor.lastrowid
    finally:
        conn.close()

    try:
        _append_csv(data, db_path)
    except Exception as exc:
        logger.error("Failed to append CSV: %s", exc)
    return row_id


def _append_csv(data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """Append a single record to the CSV log file.

    Creates the file with headers if it does not exist.
    """
    csv_path = (db_path and db_path.replace(".db", ".csv")) or config.database.csv_path
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    file_exists = os.path.isfile(csv_path)

    fieldnames = [
        "timestamp", "ip", "country", "city", "username", "auth_method",
        "client_version", "attempts", "status", "latitude", "longitude", "asn",
    ]

    with open(csv_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        row = {k: _clean_string(str(data.get(k, ""))) for k in fieldnames}
        writer.writerow(row)


def get_all_logs(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all attack log records from the database.

    Args:
        db_path: Optional database path override.

    Returns:
        List of dictionaries, one per log entry.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT * FROM attack_logs ORDER BY timestamp DESC"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_latest(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve the most recent attack log records.

    Args:
        limit: Maximum number of records to return.
        db_path: Optional database path override.

    Returns:
        List of the most recent log entries.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_country_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get aggregated statistics per country.

    Returns:
        List of dicts with country, count, and city.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT country, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT city) as cities,
                   SUM(attempts) as total_attempts
            FROM attack_logs
            GROUP BY country
            ORDER BY count DESC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_username_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get aggregated statistics per username.

    Returns:
        List of dicts with username, count, and first/last seen.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT username, COUNT(*) as count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   SUM(attempts) as total_attempts
            FROM attack_logs
            GROUP BY username
            ORDER BY count DESC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_ip_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get aggregated statistics per IP address.

    Returns:
        List of dicts with ip, count, country, city, total_attempts.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT ip, country, city, COUNT(*) as count,
                   SUM(attempts) as total_attempts,
                   MAX(timestamp) as last_seen,
                   MIN(timestamp) as first_seen
            FROM attack_logs
            GROUP BY ip
            ORDER BY count DESC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_hourly_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get attack counts grouped by hour.

    Returns:
        List of dicts with hour and count.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT strftime('%%Y-%%m-%%d %%H:00', timestamp) as hour,
                   COUNT(*) as count
            FROM attack_logs
            GROUP BY hour
            ORDER BY hour ASC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_daily_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get attack counts grouped by day.

    Returns:
        List of dicts with date and count.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT strftime('%%Y-%%m-%%d', timestamp) as date,
                   COUNT(*) as count
            FROM attack_logs
            GROUP BY date
            ORDER BY date ASC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_asn_stats(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get attack counts grouped by ASN.

    Returns:
        List of dicts with ASN, org, and count.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT asn, org, COUNT(*) as count
            FROM attack_logs
            WHERE asn != 'Unknown'
            GROUP BY asn, org
            ORDER BY count DESC
        """
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def search_logs(
    query: str,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search attack logs by username, country, IP, or ASN.

    Args:
        query: Search string (matched with LIKE).
        db_path: Optional database path override.

    Returns:
        List of matching log entries.
    """
    conn = get_db_connection(db_path)
    try:
        like_param = f"%{_clean_string(query)}%"
        cursor = conn.execute(
            """
            SELECT * FROM attack_logs
            WHERE username LIKE ?
               OR country LIKE ?
               OR city LIKE ?
               OR ip LIKE ?
               OR asn LIKE ?
            ORDER BY timestamp DESC
        """,
            (like_param, like_param, like_param, like_param, like_param),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def filter_logs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    country: Optional[str] = None,
    username: Optional[str] = None,
    status: Optional[str] = None,
    ip: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter attack logs by multiple criteria.

    Args:
        start_date: ISO date string (inclusive).
        end_date: ISO date string (inclusive).
        country: Country name filter.
        username: Username filter (partial match).
        status: Status filter (failure/success).
        ip: IP address filter.
        db_path: Optional database path override.

    Returns:
        List of matching log entries.
    """
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params: List[Any] = []

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date)
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date)
        if country:
            conditions.append("country = ?")
            params.append(country)
        if username:
            conditions.append("username LIKE ?")
            params.append(f"%{username}%")
        if status:
            conditions.append("status = ?")
            params.append(status)
        if ip:
            conditions.append("ip = ?")
            params.append(ip)

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

        cursor = conn.execute(
            f"SELECT * FROM attack_logs {where_clause} ORDER BY timestamp DESC",
            params,
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def export_csv(
    data: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[str] = None,
    db_path: Optional[str] = None,
) -> str:
    """Export attack logs to a CSV file.

    Args:
        data: List of log records (fetches all if None).
        output_path: Destination file path.
        db_path: Optional database path override.

    Returns:
        The path to the exported file.
    """
    path = output_path or config.database.csv_path
    if data is None:
        data = get_all_logs(db_path)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not data:
        return path

    fieldnames = list(data[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in data:
            writer.writerow(row)

    logger.info("Exported %d records to %s", len(data), path)
    return path


def export_excel(
    data: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[str] = None,
    db_path: Optional[str] = None,
) -> str:
    """Export attack logs to an Excel (.xlsx) file.

    Args:
        data: List of log records (fetches all if None).
        output_path: Destination file path.
        db_path: Optional database path override.

    Returns:
        The path to the exported file.

    Raises:
        ImportError: If pandas or openpyxl are not installed.
    """
    import pandas as pd

    path = output_path or os.path.join(
        os.path.dirname(config.database.db_path), "attack_logs_export.xlsx"
    )
    if data is None:
        data = get_all_logs(db_path)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    df = pd.DataFrame(data)
    df.to_excel(path, index=False, sheet_name="Attack Logs")
    logger.info("Exported %d records to %s", len(data), path)
    return path


def export_json(
    data: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[str] = None,
    db_path: Optional[str] = None,
) -> str:
    """Export attack logs to a JSON file.

    Args:
        data: List of log records (fetches all if None).
        output_path: Destination file path.
        db_path: Optional database path override.

    Returns:
        The path to the exported file.
    """
    path = output_path or os.path.join(
        os.path.dirname(config.database.db_path), "attack_logs_export.json"
    )
    if data is None:
        data = get_all_logs(db_path)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    logger.info("Exported %d records to %s", len(data), path)
    return path


def get_total_count(db_path: Optional[str] = None) -> int:
    """Get total number of attack log records."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT COUNT(*) FROM attack_logs")
        return cursor.fetchone()[0]
    finally:
        conn.close()


def get_today_count(db_path: Optional[str] = None) -> int:
    """Get number of attack log records from today."""
    conn = get_db_connection(db_path)
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        cursor = conn.execute(
            "SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?", (today,)
        )
        return cursor.fetchone()[0]
    finally:
        conn.close()


def get_unique_ips(db_path: Optional[str] = None) -> int:
    """Get count of unique source IP addresses."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT COUNT(DISTINCT ip) FROM attack_logs")
        return cursor.fetchone()[0]
    finally:
        conn.close()


def get_unique_countries(db_path: Optional[str] = None) -> int:
    """Get count of unique countries."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT COUNT(DISTINCT country) FROM attack_logs WHERE country != 'Unknown'"
        )
        return cursor.fetchone()[0]
    finally:
        conn.close()


def _clean_string(value: str) -> str:
    """Strip control characters from a string for safe storage.

    Removes null bytes, carriage returns, and newlines
    to prevent log injection and data corruption.
    SQL injection is prevented by parameterized queries.

    Args:
        value: Raw input string.

    Returns:
        Cleaned string safe for storage.
    """
    if value is None:
        return ""
    cleaned = str(value).strip()
    cleaned = cleaned.replace("\x00", "")
    cleaned = cleaned.replace("\r", "")
    cleaned = cleaned.replace("\n", "")
    return cleaned
