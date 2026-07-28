# GeoIP Databases

Place MaxMind GeoLite2 database files here to enable geolocation on
the interactive map:

1. Sign up for a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Create a license key in your account dashboard
3. Download both databases:
   - GeoLite2-City.mmdb (city-level geolocation)
   - GeoLite2-ASN.mmdb (autonomous system numbers)
4. Extract and place the .mmdb files in this directory

Or use the setup script:
```bash
MAXMIND_LICENSE_KEY=your_key_here bash scripts/setup.sh
```

Once configured, set in .env:
```
GEOIP_CITY_DB=data/GeoLite2-City.mmdb
GEOIP_ASN_DB=data/GeoLite2-ASN.mmdb
```

The map will then show attacker locations, ASN info, and organizations.
