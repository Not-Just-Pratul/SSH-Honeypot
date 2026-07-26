"""GeoIP enrichment module.

Provides functions to enrich IP addresses with geolocation,
ASN, and organization data using MaxMind GeoLite2 and optional
threat intelligence APIs.
"""

import logging
import os
from typing import Dict, Optional

from config import GeoConfig, config

logger = logging.getLogger(__name__)


class GeoEnricher:
    """IP geolocation and ASN enrichment engine."""

    def __init__(self, geo_config: Optional[GeoConfig] = None) -> None:
        self._cfg = geo_config or config.geo
        self._geoip_db = None
        self._asn_db = None
        self._init_geoip()

    def _init_geoip(self) -> None:
        """Initialize GeoIP database connections."""
        try:
            import geoip2.database
            if self._cfg.geoip_city_db and os.path.isfile(self._cfg.geoip_city_db):
                self._geoip_db = geoip2.database.Reader(self._cfg.geoip_city_db)
                logger.info("GeoLite2 city database loaded from %s", self._cfg.geoip_city_db)
            if self._cfg.geoip_asn_db and os.path.isfile(self._cfg.geoip_asn_db):
                self._asn_db = geoip2.database.Reader(self._cfg.geoip_asn_db)
                logger.info("GeoLite2 ASN database loaded from %s", self._cfg.geoip_asn_db)
        except ImportError:
            logger.warning("geoip2 package not installed. GeoIP enrichment disabled.")
        except Exception as exc:
            logger.error("Failed to load GeoIP database: %s", exc)

    def enrich(self, ip: str) -> Dict[str, object]:
        """Enrich a single IP address with geolocation and ASN data.

        Returns a dict with keys: country, city, latitude, longitude, asn, org.
        """
        if not ip:
            return self._default_result()

        return self._lookup_geoip(ip)

    def _lookup_geoip(self, ip: str) -> Dict[str, object]:
        """Perform GeoIP lookup using loaded databases."""
        data: Dict[str, object] = self._default_result()

        if self._geoip_db is not None:
            try:
                response = self._geoip_db.city(ip)
                data["country"] = response.country.name or self._cfg.default_country
                data["city"] = response.city.name or self._cfg.default_city
                data["latitude"] = response.location.latitude or self._cfg.default_lat
                data["longitude"] = response.location.longitude or self._cfg.default_lon
            except Exception as exc:
                logger.debug("GeoIP city lookup failed for %s: %s", ip, exc)

        if self._asn_db is not None:
            try:
                response = self._asn_db.asn(ip)
                data["asn"] = str(response.autonomous_system_number) if response.autonomous_system_number else self._cfg.default_asn
                data["org"] = response.autonomous_system_organization or self._cfg.default_org
            except Exception as exc:
                logger.debug("GeoIP ASN lookup failed for %s: %s", ip, exc)

        return data

    def lookup_reputation(self, ip: str) -> Dict[str, object]:
        """Look up IP reputation from AbuseIPDB if API key is configured.

        Returns a dict with risk_score, confidence, and is_whitelisted.
        Returns empty dict if no API key or lookup fails.
        """
        api_key = self._cfg.abuseipdb_api_key
        if not api_key:
            return {}

        try:
            import requests
            resp = requests.get(
                f"{self._cfg.abuseipdb_base_url}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                    "verbose": "true",
                },
                headers={"Key": api_key},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "risk_score": data.get("abuseConfidenceScore", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "num_reports": data.get("numOccurrences", 0),
                "country_code": data.get("countryCode", ""),
            }
        except Exception as exc:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return {}

    def _default_result(self) -> Dict[str, object]:
        """Return a default (unknown) enrichment result."""
        return {
            "country": self._cfg.default_country,
            "city": self._cfg.default_city,
            "latitude": self._cfg.default_lat,
            "longitude": self._cfg.default_lon,
            "asn": self._cfg.default_asn,
            "org": self._cfg.default_org,
        }

    def close(self) -> None:
        """Close GeoIP database connections."""
        if self._geoip_db is not None:
            try:
                self._geoip_db.close()
            except Exception:
                pass
        if self._asn_db is not None:
            try:
                self._asn_db.close()
            except Exception:
                pass

    def __del__(self) -> None:
        self.close()


_enricher_instance: Optional[GeoEnricher] = None


def get_enricher() -> GeoEnricher:
    """Return a singleton GeoEnricher instance."""
    global _enricher_instance
    if _enricher_instance is None:
        _enricher_instance = GeoEnricher()
    return _enricher_instance


def lookup_ip(ip: str) -> Dict[str, object]:
    """Convenience function: enrich a single IP address.

    Args:
        ip: The IP address to look up.

    Returns:
        Dict with country, city, latitude, longitude, asn, org.
    """
    enricher = get_enricher()
    return enricher.enrich(ip)


def bulk_lookup(ips: list[str]) -> Dict[str, Dict[str, object]]:
    """Enrich multiple IP addresses in a single call.

    Args:
        ips: List of IP address strings.

    Returns:
        Dict mapping IP to enrichment result. Failed lookups return defaults.
    """
    enricher = get_enricher()
    results: Dict[str, Dict[str, object]] = {}
    for ip in ips:
        try:
            results[ip] = enricher.enrich(ip)
        except Exception as exc:
            logger.debug("bulk_lookup failed for %s: %s", ip, exc)
            results[ip] = enricher._default_result()
    return results