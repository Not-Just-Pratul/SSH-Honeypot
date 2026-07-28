"""Tests for ssh_honeypot.database module."""

import os

from ssh_honeypot.database import (
    _clean_string,
    filter_logs,
    get_all_logs,
    get_country_stats,
    get_db_connection,
    get_ip_stats,
    get_latest,
    get_total_count,
    get_unique_countries,
    get_unique_ips,
    get_username_stats,
    insert_attack,
    search_logs,
)


class TestCleanString:
    """Test string sanitization for safe storage."""

    def test_normal_string(self):
        assert _clean_string("hello world") == "hello world"

    def test_strips_whitespace(self):
        assert _clean_string("  hello  ") == "hello"

    def test_removes_null_bytes(self):
        assert _clean_string("hello\x00world") == "helloworld"

    def test_removes_carriage_returns(self):
        assert _clean_string("hello\rworld") == "helloworld"

    def test_removes_newlines(self):
        assert _clean_string("hello\nworld") == "helloworld"

    def test_none_input(self):
        assert _clean_string(None) == ""

    def test_empty_string(self):
        assert _clean_string("") == ""

    def test_all_control_chars(self):
        assert _clean_string("test\x00\r\nstring") == "teststring"


class TestDatabaseConnection:
    """Test database connection and schema creation."""

    def test_get_connection_creates_db(self, temp_db_path):
        """Connection should create the database file."""
        conn = get_db_connection(temp_db_path)
        assert os.path.exists(temp_db_path)
        conn.close()

    def test_schema_creates_table(self, temp_db_path):
        """Schema should create the attack_logs table."""
        conn = get_db_connection(temp_db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attack_logs'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_schema_creates_indexes(self, temp_db_path):
        """Schema should create required indexes."""
        conn = get_db_connection(temp_db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")
        indexes = [row["name"] for row in cursor.fetchall()]
        assert any("ip" in idx for idx in indexes)
        assert any("timestamp" in idx for idx in indexes)
        conn.close()


class TestInsertAttack:
    """Test inserting attack records."""

    def test_insert_single_record(self, temp_db_path, sample_attack_data):
        """Should insert a single record and return a row ID."""
        row_id = insert_attack(sample_attack_data, temp_db_path)
        assert row_id is not None
        assert row_id > 0

    def test_insert_multiple_records(self, temp_db_path, sample_attack_data_multi):
        """Should insert multiple records sequentially."""
        for i, attack in enumerate(sample_attack_data_multi):
            row_id = insert_attack(attack, temp_db_path)
            assert row_id == i + 1

    def test_inserted_data_is_retrievable(self, temp_db_path, sample_attack_data):
        """Inserted data should be retrievable."""
        insert_attack(sample_attack_data, temp_db_path)
        logs = get_all_logs(temp_db_path)
        assert len(logs) == 1
        assert logs[0]["ip"] == "192.168.1.100"
        assert logs[0]["username"] == "admin"
        assert logs[0]["status"] == "failure"

    def test_insert_uses_defaults(self, temp_db_path):
        """Insert with minimal data should use defaults."""
        attack = {"ip": "10.0.0.1", "username": "root"}
        insert_attack(attack, temp_db_path)
        logs = get_all_logs(temp_db_path)
        assert logs[0]["country"] == "Unknown"
        assert logs[0]["auth_method"] == "password"
        assert logs[0]["attempts"] == 1

    def test_insert_cleans_control_chars(self, temp_db_path):
        """Insert should sanitize control characters from input."""
        attack = {"ip": "10.0.0.1", "username": "admin\x00\r\n"}
        insert_attack(attack, temp_db_path)
        logs = get_all_logs(temp_db_path)
        # Control chars removed, should just be "admin"
        assert logs[0]["username"] == "admin"


class TestQueryFunctions:
    """Test database query functions."""

    def _insert_sample_data(self, db_path):
        """Helper to insert sample records."""
        data = [
            {"ip": "1.1.1.1", "username": "root", "country": "US", "status": "failure"},
            {"ip": "2.2.2.2", "username": "admin", "country": "CN", "status": "failure"},
            {"ip": "1.1.1.1", "username": "root", "country": "US", "status": "failure"},
            {"ip": "3.3.3.3", "username": "ubuntu", "country": "IN", "status": "failure"},
        ]
        for d in data:
            insert_attack(d, db_path)

    def test_get_all_logs(self, temp_db_path):
        """Should return all logs ordered by timestamp descending."""
        self._insert_sample_data(temp_db_path)
        logs = get_all_logs(temp_db_path)
        assert len(logs) == 4

    def test_get_latest(self, temp_db_path):
        """Should return the N most recent logs."""
        self._insert_sample_data(temp_db_path)
        logs = get_latest(2, temp_db_path)
        assert len(logs) == 2

    def test_get_latest_exceeds_total(self, temp_db_path):
        """Requesting more than total should return all records."""
        self._insert_sample_data(temp_db_path)
        logs = get_latest(100, temp_db_path)
        assert len(logs) == 4

    def test_get_total_count(self, temp_db_path):
        """Should return total number of records."""
        self._insert_sample_data(temp_db_path)
        assert get_total_count(temp_db_path) == 4

    def test_get_unique_ips(self, temp_db_path):
        """Should return count of unique IP addresses."""
        self._insert_sample_data(temp_db_path)
        assert get_unique_ips(temp_db_path) == 3

    def test_get_unique_countries(self, temp_db_path):
        """Should return count of unique countries (excluding Unknown)."""
        self._insert_sample_data(temp_db_path)
        assert get_unique_countries(temp_db_path) == 3

    def test_get_country_stats(self, temp_db_path):
        """Should return aggregated stats per country."""
        self._insert_sample_data(temp_db_path)
        stats = get_country_stats(temp_db_path)
        assert len(stats) == 3
        # US has 2 records
        us_stats = next(s for s in stats if s["country"] == "US")
        assert us_stats["count"] == 2

    def test_get_username_stats(self, temp_db_path):
        """Should return aggregated stats per username."""
        self._insert_sample_data(temp_db_path)
        stats = get_username_stats(temp_db_path)
        assert len(stats) == 3
        # root has 2 records
        root_stats = next(s for s in stats if s["username"] == "root")
        assert root_stats["count"] == 2

    def test_get_ip_stats(self, temp_db_path):
        """Should return aggregated stats per IP address."""
        self._insert_sample_data(temp_db_path)
        stats = get_ip_stats(temp_db_path)
        assert len(stats) == 3

    def test_search_logs(self, temp_db_path):
        """Should find matching records across multiple fields."""
        self._insert_sample_data(temp_db_path)
        results = search_logs("root", temp_db_path)
        assert len(results) == 2
        results = search_logs("US", temp_db_path)
        assert len(results) == 2

    def test_search_logs_no_match(self, temp_db_path):
        """Should return empty list for no matches."""
        self._insert_sample_data(temp_db_path)
        results = search_logs("nonexistent", temp_db_path)
        assert len(results) == 0

    def test_filter_logs_by_ip(self, temp_db_path):
        """Should filter by IP address."""
        self._insert_sample_data(temp_db_path)
        results = filter_logs(ip="1.1.1.1", db_path=temp_db_path)
        assert len(results) == 2

    def test_filter_logs_by_country(self, temp_db_path):
        """Should filter by country."""
        self._insert_sample_data(temp_db_path)
        results = filter_logs(country="CN", db_path=temp_db_path)
        assert len(results) == 1

    def test_filter_logs_by_username(self, temp_db_path):
        """Should filter by username (partial match)."""
        self._insert_sample_data(temp_db_path)
        results = filter_logs(username="root", db_path=temp_db_path)
        assert len(results) == 2

    def test_filter_logs_combined(self, temp_db_path):
        """Should combine multiple filters with AND logic."""
        self._insert_sample_data(temp_db_path)
        results = filter_logs(ip="1.1.1.1", username="root", db_path=temp_db_path)
        assert len(results) == 2

    def test_empty_database_queries(self, temp_db_path):
        """Query functions should handle empty database gracefully."""
        assert get_all_logs(temp_db_path) == []
        assert get_latest(10, temp_db_path) == []
        assert get_total_count(temp_db_path) == 0
        assert get_unique_ips(temp_db_path) == 0
        assert get_unique_countries(temp_db_path) == 0
        assert search_logs("test", temp_db_path) == []
