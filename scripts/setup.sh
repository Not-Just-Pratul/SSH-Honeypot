#!/usr/bin/env bash
# =============================================================================
# SSH Honeypot - Setup Script
# =============================================================================
# Generates host keys, downloads GeoIP databases, and creates .env file.
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh                    # interactive setup
#   MAXMIND_LICENSE_KEY=abc ./scripts/setup.sh  # auto-download GeoIP
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "========================================"
echo "  SSH Honeypot - Setup"
echo "========================================"

# --- Step 1: SSH Host Key ---
echo ""
echo "[1/4] SSH Host Key"
if [ -f keys/ssh_host_rsa_key ]; then
    echo "  ✅ Host key already exists at keys/ssh_host_rsa_key"
    openssl rsa -in keys/ssh_host_rsa_key -check -noout 2>/dev/null && echo "  ✅ Key is valid" || echo "  ⚠️  Key is invalid, regenerating..."
else
    echo "  Generating new RSA 2048-bit host key..."
    mkdir -p keys
    openssl genrsa -out keys/ssh_host_rsa_key 2048
    chmod 600 keys/ssh_host_rsa_key
    echo "  ✅ Generated keys/ssh_host_rsa_key"
fi

# --- Step 2: GeoIP Databases ---
echo ""
echo "[2/4] GeoIP Databases"
GEOIP_DIR="data"
mkdir -p "$GEOIP_DIR"

download_geoip() {
    local db_name="$1"
    local license_key="${MAXMIND_LICENSE_KEY:-}"

    if [ -f "$GEOIP_DIR/$db_name" ]; then
        echo "  ✅ $db_name already exists"
        return 0
    fi

    if [ -z "$license_key" ]; then
        echo "  ⏭️  Skipping $db_name — set MAXMIND_LICENSE_KEY to auto-download"
        echo "      Get a free key at: https://www.maxmind.com/en/geolite2/signup"
        return 1
    fi

    echo "  Downloading $db_name..."
    local edition
    case "$db_name" in
        GeoLite2-City.mmdb) edition="GeoLite2-City" ;;
        GeoLite2-ASN.mmdb)  edition="GeoLite2-ASN" ;;
        *) echo "  Unknown database: $db_name"; return 1 ;;
    esac

    curl -sSL "https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${license_key}&suffix=tar.gz" \
        -o "/tmp/${edition}.tar.gz"
    tar -xzf "/tmp/${edition}.tar.gz" -C "/tmp/"
    cp "/tmp/${edition}"*/"${edition}.mmdb" "$GEOIP_DIR/$db_name"
    rm -rf "/tmp/${edition}.tar.gz" "/tmp/${edition}"*/
    echo "  ✅ Downloaded $db_name"
}

download_geoip "GeoLite2-City.mmdb" || true
download_geoip "GeoLite2-ASN.mmdb" || true

# --- Step 3: .env File ---
echo ""
echo "[3/4] Environment Configuration"
if [ -f .env ]; then
    echo "  ✅ .env already exists"
    echo "     Edit it to add API keys: nano .env"
else
    echo "  Creating .env from .env.example..."
    cp .env.example .env

    # Set GeoIP paths if databases were downloaded
    if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]; then
        # Get absolute path for GeoIP databases
        GEOIP_ABS=$(cd "$GEOIP_DIR" && pwd)
        if [[ "$OSTYPE" == "darwin"* || "$OSTYPE" == "linux-gnu"* ]]; then
            sed -i "s|^GEOIP_CITY_DB=$|GEOIP_CITY_DB=${GEOIP_ABS}/GeoLite2-City.mmdb|" .env
            sed -i "s|^GEOIP_ASN_DB=$|GEOIP_ASN_DB=${GEOIP_ABS}/GeoLite2-ASN.mmdb|" .env
        fi
        echo "  ✅ GeoIP paths configured in .env"
    fi

    echo "  ✅ Created .env"
    echo "     Edit it to add API keys: nano .env"
fi

# --- Step 4: Logs Directory ---
echo ""
echo "[4/4] Logs Directory"
mkdir -p logs
echo "  ✅ Logs directory ready at logs/"

# --- Summary ---
echo ""
echo "========================================"
echo "  Setup Complete"
echo "========================================"
echo ""
echo "  To start:"
echo "    python -m ssh_honeypot all"
echo "    # or:  docker compose up -d"
echo ""
echo "  Dashboard: http://localhost:8501"
echo "  API:       http://localhost:8502/api/health"
echo ""
echo "  Next steps:"
if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "    1. Get a free MaxMind license key:"
    echo "       https://www.maxmind.com/en/geolite2/signup"
    echo "    2. Re-run: MAXMIND_LICENSE_KEY=xxx ./scripts/setup.sh"
fi
echo "    3. Add threat intel API keys to .env:"
echo "       - ABUSEIPDB_API_KEY (free tier available)"
echo "       - VIRUSTOTAL_API_KEY (free tier available)"
echo ""
echo "========================================"
