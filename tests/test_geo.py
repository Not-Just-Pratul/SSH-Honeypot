"""Tests for ssh_honeypot.geo module."""

from unittest.mock import MagicMock, patch

import pytest

from ssh_honeypot.geo import GeoEnricher, bulk_lookup, get_enricher, lookup_ip


class TestGeoEnricher:
    """Test GeoIP enricher initialization and default behavior."""

    def test_default_result_structure(self):
        """Default result should have all required keys."""
        enricher = GeoEnricher()
        result = enricher._default_result()
        assert result["country"] == "Unknown"
        assert result["city"] == "Unknown"
        assert result["latitude"] == 0.0
        assert result["longitude"] == 0.0
        assert result["asn"] == "Unknown"
        assert result["org"] == "Unknown"

    def test_enrich_empty_ip(self):
        """Empty IP should return default result."""
        enricher = GeoEnricher()
        result = enricher.enrich("")
        assert result["country"] == "Unknown"

    def test_enrich_none_ip(self):
        """None-like IP should return default result."""
        enricher = GeoEnricher()
        result = enricher.enrich("")
        assert result["country"] == "Unknown"

    def test_enrich_without_geoip_db(self):
        """Without GeoIP database, enrich should return defaults."""
        enricher = GeoEnricher()
        result = enricher.enrich("8.8.8.8")
        assert result is not None
        assert result["country"] == "Unknown"
        assert result["city"] == "Unknown"

    def test_lookup_reputation_no_api_key(self):
        """Without API key, lookup_reputation should return empty dict."""
        enricher = GeoEnricher()
        result = enricher.lookup_reputation("8.8.8.8")
        assert result == {}

    def test_singleton_get_enricher(self):
        """get_enricher should return the same instance."""
        e1 = get_enricher()
        e2 = get_enricher()
        assert e1 is e2

    def test_lookup_ip_convenience(self):
        """lookup_ip should work as a convenience function."""
        result = lookup_ip("8.8.8.8")
        assert result["country"] == "Unknown"


class TestGeoWithMocks:
    """Test GeoIP enrichment with mocked database responses."""

    @patch("geoip2.database.Reader")
    def test_enrich_with_city_db(self, mock_reader):
        """With city database, enrich should return geo data."""
        mock_response = MagicMock()
        mock_response.country.name = "United States"
        mock_response.city.name = "Mountain View"
        mock_response.location.latitude = 37.386
        mock_response.location.longitude = -122.0838

        mock_reader_instance = MagicMock()
        mock_reader_instance.city.return_value = mock_response
        mock_reader.return_value = mock_reader_instance

        # Mock the _init_geoip to set our mock
        enricher = GeoEnricher()
        enricher._geoip_db = mock_reader_instance

        result = enricher.enrich("8.8.8.8")
        assert result["country"] == "United States"
        assert result["city"] == "Mountain View"
        assert result["latitude"] == 37.386
        assert result["longitude"] == pytest.approx(-122.0838)

    @patch("geoip2.database.Reader")
    def test_enrich_with_asn_db(self, mock_reader):
        """With ASN database, enrich should return ASN/org data."""
        mock_response = MagicMock()
        mock_response.autonomous_system_number = 15169
        mock_response.autonomous_system_organization = "Google LLC"

        mock_reader_instance = MagicMock()
        mock_reader_instance.asn.return_value = mock_response
        mock_reader.return_value = mock_reader_instance

        enricher = GeoEnricher()
        enricher._asn_db = mock_reader_instance

        result = enricher.enrich("8.8.8.8")
        assert result["asn"] == "15169"
        assert result["org"] == "Google LLC"

    def test_enrich_with_partial_data(self):
        """Enrich should handle partial data gracefully."""
        enricher = GeoEnricher()
        result = enricher.enrich("10.0.0.1")
        assert isinstance(result["country"], str)
        assert isinstance(result["latitude"], float)
        assert isinstance(result["longitude"], float)


class TestBulkLookup:
    """Test bulk IP lookup functionality."""

    def test_bulk_lookup_empty_list(self):
        """Bulk lookup with empty list should return empty dict."""
        result = bulk_lookup([])
        assert result == {}

    def test_bulk_lookup_single_ip(self):
        """Bulk lookup with single IP should return dict with one entry."""
        result = bulk_lookup(["8.8.8.8"])
        assert "8.8.8.8" in result
        assert result["8.8.8.8"]["country"] == "Unknown"

    def test_bulk_lookup_multiple_ips(self):
        """Bulk lookup with multiple IPs should return all results."""
        result = bulk_lookup(["8.8.8.8", "1.1.1.1"])
        assert len(result) == 2
        assert "8.8.8.8" in result
        assert "1.1.1.1" in result
