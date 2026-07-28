"""Tests for ssh_honeypot.logger module."""

from ssh_honeypot.logger import sanitize_string


class TestSanitizeString:
    """Test string sanitization for logging."""

    def test_normal_string(self):
        """Normal strings should pass through unchanged."""
        assert sanitize_string("hello world") == "hello world"

    def test_strips_whitespace(self):
        """Strings should be stripped of leading/trailing whitespace."""
        assert sanitize_string("  hello  ") == "hello"

    def test_removes_null_bytes(self):
        """Null bytes should be removed."""
        assert sanitize_string("hello\x00world") == "helloworld"

    def test_removes_carriage_returns(self):
        """Carriage returns should be removed."""
        assert sanitize_string("hello\rworld") == "helloworld"

    def test_removes_newlines(self):
        """Newlines should be removed."""
        assert sanitize_string("hello\nworld") == "helloworld"

    def test_none_input(self):
        """None input should return empty string."""
        assert sanitize_string(None) == ""

    def test_empty_string(self):
        """Empty string should stay empty."""
        assert sanitize_string("") == ""

    def test_special_characters(self):
        """Special characters (not control chars) should be preserved."""
        result = sanitize_string("test@#$%^&*()")
        assert result == "test@#$%^&*()"

    def test_unicode_characters(self):
        """Unicode characters should be preserved."""
        result = sanitize_string("héllo wörld 中文")
        assert result == "héllo wörld 中文"

    def test_mixed_control_chars(self):
        """Mixed control characters should all be removed."""
        result = sanitize_string("\x00\r\nhello\x00\r\n")
        assert result == "hello"

    def test_only_whitespace(self):
        """Only whitespace should become empty string."""
        assert sanitize_string("   ") == ""
