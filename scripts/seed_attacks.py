"""Seed database with sample attacker IPs for GeoIP dashboard."""
import random
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = "logs/attack_logs.db"

ATTACKERS = [
    ("185.220.101.42", "Germany", "Brandenburg an der Havel", 52.408, 12.561, 60729,
     "Stiftung Erneuerbare Freiheit", "root"),
    ("103.235.46.39", "China", "Beijing", 39.904, 116.397, 4808,
     "China Unicom Beijing", "admin"),
    ("91.121.87.87", "France", "Paris", 48.856, 2.352, 16276,
     "OVH SAS", "test"),
    ("185.28.21.22", "Netherlands", "Amsterdam", 52.368, 4.897, 49453,
     "Magna Capax Finland Oy", "ubuntu"),
    ("45.33.32.156", "United States", "Fremont", 37.548, -121.983, 63949,
     "Akamai Technologies", "postgres"),
    ("46.101.84.157", "Germany", "Frankfurt", 50.110, 8.682, 24940,
     "Hetzner Online GmbH", "oracle"),
    ("195.133.145.24", "Russia", "Moscow", 55.755, 37.617, 25532,
     "LLC Masterhost", "pi"),
    ("103.215.167.52", "India", "Mumbai", 19.076, 72.877, 24309,
     "Atria Convergence Tech", "jenkins"),
    ("5.196.78.128", "France", "Gravelines", 50.986, 2.128, 16276,
     "OVH SAS", "www-data"),
    ("104.248.50.88", "United States", "New York", 40.712, -74.006, 14061,
     "DigitalOcean LLC", "docker"),
    ("186.192.82.50", "Brazil", "Sao Paulo", -23.550, -46.633, 28598,
     "Telefonica Brasil", "backup"),
    ("211.197.20.195", "South Korea", "Seoul", 37.566, 126.978, 4766,
     "Korea Telecom", "admin"),
    ("78.46.89.180", "Germany", "Nuremberg", 49.452, 11.077, 24940,
     "Hetzner Online GmbH", "support"),
    ("51.15.42.199", "Netherlands", "Amsterdam", 52.368, 4.897, 12876,
     "Online SAS", "git"),
    ("176.9.42.152", "Germany", "Berlin", 52.520, 13.405, 24940,
     "Hetzner Online GmbH", "redis"),
]

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
now = datetime.now(timezone.utc)

for i, (ip, country, city, lat, lon, asn, org, username) in enumerate(ATTACKERS):
    ts = (now - timedelta(minutes=i * 3 + random.randint(0, 2))).isoformat()
    c.execute(
        """INSERT INTO attack_logs
        (timestamp, ip, username, auth_method,
         client_version, protocol_version, country, city,
         latitude, longitude, asn, org, attempts, status, session_id,
         connection_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ts,
            ip,
            username,
            random.choice(["password", "none", "keyboard-interactive"]),
            random.choice([
                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                "SSH-2.0-libssh2_1.11.1",
                "SSH-2.0-dropbear_2022.83",
            ]),
            "SSH-2.0",
            country,
            city,
            lat,
            lon,
            str(asn),
            org,
            random.randint(1, 8),
            "failure",
            f"{ip}-{int(datetime.now().timestamp())}",
            round(random.uniform(0.01, 5.0), 2),
        ),
    )
    print(f"  {ip:20} {country:15} {username:10}")

conn.commit()
conn.close()
print(f"\nInserted {len(ATTACKERS)} enriched attacks")
