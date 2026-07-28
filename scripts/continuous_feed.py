#!/usr/bin/env python3
"""Continuous attack feeder for live dashboard demos.

Inserts a new attack into the database every ~10 seconds using
real-world IPs so the map, charts, and live feed all update.

Usage:
    python scripts/continuous_feed.py
    python scripts/continuous_feed.py --interval 5
    python scripts/continuous_feed.py --interval 10 --real-ssh
"""

import argparse
import random
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

DB_PATH = "logs/attack_logs.db"

# Real attacker IPs with GeoIP data for map display
ATTACKERS = [
    # (ip, country, city, lat, lon, asn, org)
    # Europe
    ("185.220.101.42", "Germany", "Brandenburg an der Havel", 52.408, 12.561, 60729, "Stiftung Erneuerbare Freiheit"),
    ("46.101.84.157", "Germany", "Frankfurt", 50.110, 8.682, 24940, "Hetzner Online GmbH"),
    ("78.46.89.180", "Germany", "Nuremberg", 49.452, 11.077, 24940, "Hetzner Online GmbH"),
    ("176.9.42.152", "Germany", "Berlin", 52.520, 13.405, 24940, "Hetzner Online GmbH"),
    ("91.121.87.87", "France", "Paris", 48.856, 2.352, 16276, "OVH SAS"),
    ("5.196.78.128", "France", "Gravelines", 50.986, 2.128, 16276, "OVH SAS"),
    ("185.28.21.22", "Netherlands", "Amsterdam", 52.368, 4.897, 49453, "Magna Capax Finland Oy"),
    ("51.15.42.199", "Netherlands", "Amsterdam", 52.368, 4.897, 12876, "Online SAS"),
    ("188.166.93.145", "Netherlands", "Amsterdam", 52.368, 4.897, 14061, "DigitalOcean LLC"),
    ("188.166.14.63", "United Kingdom", "London", 51.507, -0.127, 14061, "DigitalOcean LLC"),
    ("195.133.145.24", "Russia", "Moscow", 55.755, 37.617, 25532, "LLC Masterhost"),
    ("95.213.198.151", "Russia", "St Petersburg", 59.934, 30.335, 41733, "JSC ER-Telecom Holding"),
    ("194.26.29.117", "Sweden", "Stockholm", 59.329, 18.068, 42708, "Portlane AB"),
    ("82.221.111.98", "Iceland", "Reykjavik", 64.146, -21.942, 50613, "Icelandic Gov"),
    ("5.134.120.10", "Iran", "Tehran", 35.689, 51.389, 60462, "Iran Telecom"),
    ("185.106.92.20", "Turkey", "Istanbul", 41.008, 28.978, 9123, "Turk Telekom"),

    # North America
    ("45.33.32.156", "United States", "Fremont", 37.548, -121.983, 63949, "Akamai Technologies"),
    ("104.248.50.88", "United States", "New York", 40.712, -74.006, 14061, "DigitalOcean LLC"),
    ("134.209.189.132", "United States", "San Francisco", 37.774, -122.419, 14061, "DigitalOcean LLC"),
    ("167.71.56.11", "United States", "New York", 40.712, -74.006, 14061, "DigitalOcean LLC"),
    ("142.93.167.88", "United States", "San Francisco", 37.774, -122.419, 14061, "DigitalOcean LLC"),
    ("64.227.99.248", "United States", "Santa Clara", 37.354, -121.955, 14061, "DigitalOcean LLC"),
    ("138.197.19.145", "Canada", "Toronto", 43.653, -79.383, 14061, "DigitalOcean LLC"),

    # South America
    ("186.192.82.50", "Brazil", "Sao Paulo", -23.550, -46.633, 28598, "Telefonica Brasil"),
    ("177.71.253.67", "Brazil", "Sao Paulo", -23.550, -46.633, 28598, "Telefonica Brasil"),
    ("181.49.67.98", "Colombia", "Bogota", 4.711, -74.072, 14061, "DigitalOcean LLC"),
    ("190.210.15.43", "Argentina", "Buenos Aires", -34.603, -58.381, 22927, "Telecom Argentina"),

    # Asia
    ("103.235.46.39", "China", "Beijing", 39.904, 116.397, 4808, "China Unicom Beijing"),
    ("118.24.92.10", "China", "Shenzhen", 22.543, 114.057, 45090, "Tencent Cloud"),
    ("180.76.248.2", "China", "Beijing", 39.904, 116.397, 38365, "Baidu Netcom"),
    ("211.197.20.195", "South Korea", "Seoul", 37.566, 126.978, 4766, "Korea Telecom"),
    ("103.215.167.52", "India", "Mumbai", 19.076, 72.877, 24309, "Atria Convergence Tech"),
    ("1.186.42.15", "India", "Bangalore", 12.971, 77.594, 9829, "Bharti Airtel"),
    ("45.115.173.233", "India", "Delhi", 28.704, 77.102, 131210, "Excitel Broadband"),
    ("58.82.217.202", "Japan", "Tokyo", 35.676, 139.650, 4713, "NTT Communications"),
    ("153.126.147.162", "Japan", "Osaka", 34.693, 135.502, 9605, "NTT DOCOMO"),
    ("203.76.112.4", "Singapore", "Singapore", 1.352, 103.819, 18144, "SingNet"),
    ("210.57.211.100", "Taiwan", "Taipei", 25.033, 121.565, 9924, "Taiwan Fixed Network"),
    ("49.228.112.4", "Thailand", "Bangkok", 13.756, 100.501, 4609, "TRUE Internet"),
    ("86.108.24.50", "Jordan", "Amman", 31.956, 35.945, 48060, "Jordan Telecom"),

    # Oceania
    ("103.97.69.10", "Australia", "Sydney", -33.868, 151.209, 13335, "Cloudflare Inc"),
    ("49.185.36.228", "Australia", "Melbourne", -37.813, 144.963, 13335, "Cloudflare Inc"),

    # Africa
    ("41.203.67.100", "Nigeria", "Lagos", 6.524, 3.379, 29465, "MTN Nigeria"),
    ("105.24.68.45", "South Africa", "Johannesburg", -26.204, 28.045, 10474, "Vodacom SA"),
    ("197.221.242.10", "Kenya", "Nairobi", -1.292, 36.821, 33781, "Safaricom"),
]

USERNAMES = [
    "root", "admin", "test", "ubuntu", "postgres", "oracle", "pi", "jenkins",
    "www-data", "docker", "backup", "support", "git", "redis", "deploy",
    "mysql", "user", "guest", "info", "nagios", "zabbix", "tomcat",
]

CLIENTS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1",
    "SSH-2.0-OpenSSH_7.4p1 CentOS-6",
    "SSH-2.0-libssh2_1.11.1",
    "SSH-2.0-dropbear_2022.83",
    "SSH-2.0-PuTTY_Release_0.79",
]

AUTH_METHODS = ["password", "password", "password", "none", "keyboard-interactive"]


def insert_attack(db_path: str) -> dict:
    """Insert a single randomized attack into the database."""
    ip, country, city, lat, lon, asn, org = random.choice(ATTACKERS)
    username = random.choice(USERNAMES)
    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        """INSERT INTO attack_logs
        (timestamp, ip, username, auth_method, client_version,
         protocol_version, country, city, latitude, longitude,
         asn, org, attempts, status, session_id, connection_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            now,
            ip,
            username,
            random.choice(AUTH_METHODS),
            random.choice(CLIENTS),
            "SSH-2.0",
            country,
            city,
            lat,
            lon,
            str(asn),
            org,
            random.randint(1, 6),
            "failure",
            f"{ip}-{int(time.time())}-{random.randint(1000,9999)}",
            round(random.uniform(0.01, 4.0), 2),
        ),
    )
    conn.commit()
    conn.close()
    return {"ip": ip, "country": country, "username": username}


def do_real_ssh(port: int = 2222) -> bool:
    """Optionally do a real SSH connection to trigger the live feed."""
    try:
        username = random.choice(USERNAMES)
        subprocess.run(
            [
                "ssh",
                "-p", str(port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=" + ("NUL" if sys.platform == "win32" else "/dev/null"),
                "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                "-o", "LogLevel=ERROR",
                f"{username}@127.0.0.1",
            ],
            capture_output=True,
            timeout=6,
        )
        return True
    except subprocess.TimeoutExpired:
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="Continuous attack feeder for dashboard demo")
    parser.add_argument("--interval", type=float, default=10.0, help="Seconds between attacks (default: 10)")
    parser.add_argument("--real-ssh", action="store_true", help="Also do real SSH connections (127.0.0.1 only)")
    parser.add_argument("--db", default=DB_PATH, help=f"Database path (default: {DB_PATH})")
    args = parser.parse_args()

    print("=" * 60)
    print("  🛡️  Continuous Attack Feeder")
    print(f"  Interval: {args.interval}s  |  Real SSH: {'ON' if args.real_ssh else 'OFF'}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    count = 0
    try:
        while True:
            attack = insert_attack(args.db)
            count += 1
            ts = datetime.now().strftime("%H:%M:%S")

            extra = ""
            if args.real_ssh:
                do_real_ssh()
                extra = " + real SSH"

            print(f"  [{ts}] #{count:4d}  {attack['ip']:20} {attack['country']:15} {attack['username']:10}{extra}")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
        print(f"  Stopped. Total attacks fed: {count}")
        print("  Dashboard should show live data at http://localhost:8501")


if __name__ == "__main__":
    main()
