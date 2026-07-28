"""Shared test fixtures for SSH Honeypot test suite."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture
def temp_db_dir():
    """Create a temporary directory for test database files."""
    tmpdir = tempfile.mkdtemp(prefix="honeypot_test_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def temp_db_path(temp_db_dir):
    """Return a temporary database path."""
    return os.path.join(temp_db_dir, "test_attack_logs.db")


@pytest.fixture
def temp_csv_path(temp_db_dir):
    """Return a temporary CSV path."""
    return os.path.join(temp_db_dir, "test_attack_logs.csv")


@pytest.fixture
def sample_attack_data():
    """Return a sample attack event for testing."""
    return {
        "timestamp": "2026-01-15T12:34:56.789012+00:00",
        "ip": "192.168.1.100",
        "port": 22,
        "username": "admin",
        "auth_method": "password",
        "client_version": "SSH-2.0-libssh2_1.11.1",
        "protocol_version": "SSH-2.0-OpenSSH_8.9p1",
        "attempts": 3,
        "status": "failure",
        "session_id": "test-session-1",
        "connection_duration": 12.5,
    }


@pytest.fixture
def sample_attack_data_multi():
    """Return multiple sample attack events for batch testing."""
    base = {
        "timestamp": "2026-01-15T12:34:56.789012+00:00",
        "port": 22,
        "auth_method": "password",
        "client_version": "SSH-2.0-libssh2_1.11.1",
        "protocol_version": "SSH-2.0-OpenSSH_8.9p1",
        "attempts": 1,
        "status": "failure",
        "connection_duration": 5.0,
    }
    return [
        {**base, "ip": "10.0.0.1", "username": "root", "session_id": "s1", "timestamp": "2026-01-15T12:00:00"},
        {**base, "ip": "10.0.0.2", "username": "admin", "session_id": "s2", "timestamp": "2026-01-15T12:05:00"},
        {**base, "ip": "10.0.0.1", "username": "root", "session_id": "s3", "timestamp": "2026-01-15T12:10:00"},
        {**base, "ip": "10.0.0.3", "username": "ubuntu", "session_id": "s4", "timestamp": "2026-01-15T12:15:00"},
        {**base, "ip": "10.0.0.2", "username": "admin", "session_id": "s5", "timestamp": "2026-01-15T12:20:00"},
    ]
