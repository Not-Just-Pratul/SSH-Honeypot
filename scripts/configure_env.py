"""Configure .env with GeoIP database paths and API keys.

Usage:
    # Set paths and any API keys via environment:
    ABUSEIPDB_API_KEY=xxx python scripts/configure_env.py

    # Or run and manually edit .env after:
    python scripts/configure_env.py
"""
import os
import re

EXAMPLE_PATH = ".env.example"
ENV_PATH = ".env"

# Read from example template
with open(EXAMPLE_PATH, encoding="utf-8") as f:
    content = f.read()

# Set GeoIP database paths
city_path = os.path.abspath("data/GeoLite2-City.mmdb").replace("\\", "/")
asn_path = os.path.abspath("data/GeoLite2-ASN.mmdb").replace("\\", "/")

content = re.sub(r"^GEOIP_CITY_DB=.*", f"GEOIP_CITY_DB={city_path}", content, flags=re.MULTILINE)
content = re.sub(r"^GEOIP_ASN_DB=.*", f"GEOIP_ASN_DB={asn_path}", content, flags=re.MULTILINE)

# Set API keys from environment variables (fall back to empty)
api_keys = {
    "ABUSEIPDB_API_KEY": "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY": "VIRUSTOTAL_API_KEY",
    "GREYNOISE_API_KEY": "GREYNOISE_API_KEY",
    "SHODAN_API_KEY": "SHODAN_API_KEY",
}
for env_var, config_key in api_keys.items():
    val = os.environ.get(env_var, "")
    content = re.sub(rf"^{config_key}=.*", f"{config_key}={val}", content, flags=re.MULTILINE)

content = re.sub(r"^ENABLE_THREAT_SCORE=.*", "ENABLE_THREAT_SCORE=true", content, flags=re.MULTILINE)

with open(ENV_PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("Updated .env:")
print(f"  GEOIP_CITY_DB={city_path}")
print(f"  GEOIP_ASN_DB={asn_path}")
for env_var in api_keys:
    val = os.environ.get(env_var, "")
    print(f"  {env_var}={'SET' if val else 'empty'}")
print(f"  ENABLE_THREAT_SCORE=true")
