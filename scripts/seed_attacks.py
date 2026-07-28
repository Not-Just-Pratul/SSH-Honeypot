"""Seed database with sample attacker IPs for GeoIP dashboard.

Usage:
    python scripts/seed_attacks.py              # seed 50 attacks
    python scripts/seed_attacks.py 200          # seed 200 attacks
"""

import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DB_PATH = "logs/attack_logs.db"

ATTACKERS = [
    # (ip, country, city, lat, lon, asn, org, username)
    # --- Europe ---
    ("185.220.101.42", "Germany", "Brandenburg an der Havel", 52.408, 12.561, 60729,
     "Stiftung Erneuerbare Freiheit", "root"),
    ("46.101.84.157", "Germany", "Frankfurt", 50.110, 8.682, 24940,
     "Hetzner Online GmbH", "oracle"),
    ("78.46.89.180", "Germany", "Nuremberg", 49.452, 11.077, 24940,
     "Hetzner Online GmbH", "support"),
    ("176.9.42.152", "Germany", "Berlin", 52.520, 13.405, 24940,
     "Hetzner Online GmbH", "redis"),
    ("5.196.78.128", "France", "Gravelines", 50.986, 2.128, 16276,
     "OVH SAS", "www-data"),
    ("91.121.87.87", "France", "Paris", 48.856, 2.352, 16276,
     "OVH SAS", "test"),
    ("185.28.21.22", "Netherlands", "Amsterdam", 52.368, 4.897, 49453,
     "Magna Capax Finland Oy", "ubuntu"),
    ("51.15.42.199", "Netherlands", "Amsterdam", 52.368, 4.897, 12876,
     "Online SAS", "git"),
    ("195.133.145.24", "Russia", "Moscow", 55.755, 37.617, 25532,
     "LLC Masterhost", "pi"),
    ("95.213.198.151", "Russia", "St Petersburg", 59.934, 30.335, 41733,
     "JSC ER-Telecom Holding", "mysql"),
    ("188.166.93.145", "Netherlands", "Amsterdam", 52.368, 4.897, 14061,
     "DigitalOcean LLC", "postgres"),
    ("159.203.42.127", "Netherlands", "Amsterdam", 52.368, 4.897, 14061,
     "DigitalOcean LLC", "jenkins"),
    ("194.26.29.117", "Sweden", "Stockholm", 59.329, 18.068, 42708,
     "Portlane AB", "backup"),
    ("82.221.111.98", "Iceland", "Reykjavik", 64.146, -21.942, 50613,
     "Icelandic Gov", "admin"),
    ("188.166.14.63", "United Kingdom", "London", 51.507, -0.127, 14061,
     "DigitalOcean LLC", "deploy"),

    # --- North America ---
    ("45.33.32.156", "United States", "Fremont", 37.548, -121.983, 63949,
     "Akamai Technologies", "postgres"),
    ("104.248.50.88", "United States", "New York", 40.712, -74.006, 14061,
     "DigitalOcean LLC", "docker"),
    ("134.209.189.132", "United States", "San Francisco", 37.774, -122.419, 14061,
     "DigitalOcean LLC", "ubuntu"),
    ("167.71.56.11", "United States", "New York", 40.712, -74.006, 14061,
     "DigitalOcean LLC", "root"),
    ("138.197.19.145", "Canada", "Toronto", 43.653, -79.383, 14061,
     "DigitalOcean LLC", "test"),
    ("142.93.167.88", "United States", "San Francisco", 37.774, -122.419, 14061,
     "DigitalOcean LLC", "admin"),
    ("64.227.99.248", "United States", "Santa Clara", 37.354, -121.955, 14061,
     "DigitalOcean LLC", "oracle"),
    ("143.110.236.198", "United States", "New York", 40.712, -74.006, 14061,
     "DigitalOcean LLC", "www-data"),
    ("159.89.225.184", "United States", "New York", 40.712, -74.006, 14061,
     "DigitalOcean LLC", "support"),

    # --- South America ---
    ("186.192.82.50", "Brazil", "Sao Paulo", -23.550, -46.633, 28598,
     "Telefonica Brasil", "backup"),
    ("177.71.253.67", "Brazil", "Sao Paulo", -23.550, -46.633, 28598,
     "Telefonica Brasil", "admin"),
    ("181.49.67.98", "Colombia", "Bogota", 4.711, -74.072, 14061,
     "DigitalOcean LLC", "test"),
    ("190.210.15.43", "Argentina", "Buenos Aires", -34.603, -58.381, 22927,
     "Telecom Argentina", "root"),

    # --- Asia ---
    ("103.235.46.39", "China", "Beijing", 39.904, 116.397, 4808,
     "China Unicom Beijing", "admin"),
    ("211.197.20.195", "South Korea", "Seoul", 37.566, 126.978, 4766,
     "Korea Telecom", "admin"),
    ("103.215.167.52", "India", "Mumbai", 19.076, 72.877, 24309,
     "Atria Convergence Tech", "jenkins"),
    ("1.186.42.15", "India", "Bangalore", 12.971, 77.594, 9829,
     "Bharti Airtel", "root"),
    ("45.115.173.233", "India", "Delhi", 28.704, 77.102, 131210,
     "Excitel Broadband", "test"),
    ("58.82.217.202", "Japan", "Tokyo", 35.676, 139.650, 4713,
     "NTT Communications", "oracle"),
    ("153.126.147.162", "Japan", "Osaka", 34.693, 135.502, 9605,
     "NTT DOCOMO", "git"),
    ("203.76.112.4", "Singapore", "Singapore", 1.352, 103.819, 18144,
     "SingNet", "admin"),
    ("210.57.211.100", "Taiwan", "Taipei", 25.033, 121.565, 9924,
     "Taiwan Fixed Network", "backup"),
    ("49.228.112.4", "Thailand", "Bangkok", 13.756, 100.501, 4609,
     "TRUE Internet", "pi"),
    ("180.76.248.2", "China", "Beijing", 39.904, 116.397, 38365,
     "Baidu Netcom", "root"),
    ("118.24.92.10", "China", "Shenzhen", 22.543, 114.057, 45090,
     "Tencent Cloud", "docker"),

    # --- Middle East ---
    ("5.134.120.10", "Iran", "Tehran", 35.689, 51.389, 60462,
     "Iran Telecom", "admin"),
    ("86.108.24.50", "Jordan", "Amman", 31.956, 35.945, 48060,
     "Jordan Telecom", "test"),
    ("185.106.92.20", "Turkey", "Istanbul", 41.008, 28.978, 9123,
     "Turk Telekom", "root"),

    # --- Oceania ---
    ("103.97.69.10", "Australia", "Sydney", -33.868, 151.209, 13335,
     "Cloudflare Inc", "ubuntu"),
    ("49.185.36.228", "Australia", "Melbourne", -37.813, 144.963, 13335,
     "Cloudflare Inc", "www-data"),

    # --- Africa ---
    ("41.203.67.100", "Nigeria", "Lagos", 6.524, 3.379, 29465,
     "MTN Nigeria", "admin"),
    ("105.24.68.45", "South Africa", "Johannesburg", -26.204, 28.045, 10474,
     "Vodacom SA", "test"),
    ("197.221.242.10", "Kenya", "Nairobi", -1.292, 36.821, 33781,
     "Safaricom", "root"),
]

USERNAMES = [
    "root", "admin", "test", "ubuntu", "postgres", "oracle", "pi", "jenkins",
    "www-data", "docker", "backup", "support", "git", "redis", "deploy",
    "mysql", "user", "guest", "info", "admin2", "nagios", "zabbix",
    "tomcat", "kafka", "elastic", "hadoop", "spark", "mongodb",
]

def seed(rounds: int = 3):
    """Seed database with `rounds` passes over the attacker list."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now(timezone.utc)

    total = 0
    for r in range(rounds):
        for i, (ip, country, city, lat, lon, asn, org, _) in enumerate(ATTACKERS):
            ts = (now - timedelta(
                hours=r * 2,
                minutes=i * 2 + random.randint(0, 1),
            )).isoformat()

            username = random.choice(USERNAMES)
            auth = random.choice(["password", "none", "keyboard-interactive"])
            client = random.choice([
                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1",
                "SSH-2.0-OpenSSH_7.4p1 CentOS-6",
                "SSH-2.0-libssh2_1.11.1",
                "SSH-2.0-dropbear_2022.83",
                "SSH-2.0-PuTTY_Release_0.79",
            ])
            attempts = random.randint(1, 12)
            duration = round(random.uniform(0.01, 8.0), 2)

            c.execute(
                """INSERT INTO attack_logs
                (timestamp, ip, username, auth_method,
                 client_version, protocol_version, country, city,
                 latitude, longitude, asn, org, attempts, status,
                 session_id, connection_duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts, ip, username, auth, client, "SSH-2.0",
                    country, city, lat, lon, str(asn), org,
                    attempts, "failure",
                    f"{ip}-{int(datetime.now().timestamp())}-{r}-{i}",
                    duration,
                ),
            )
            total += 1

        print(f"  Round {r + 1}/{rounds} done ({total} total)")

    # Sometimes include some "success" status entries (brute force wins)
    for _ in range(int(total * 0.05)):  # ~5% success rate
        idx = random.randrange(len(ATTACKERS))
        ip, country, city, lat, lon, asn, org, _ = ATTACKERS[idx]
        ts = (now - timedelta(hours=random.randint(0, 5))).isoformat()
        c.execute(
            """INSERT INTO attack_logs
            (timestamp, ip, username, auth_method, client_version,
             protocol_version, country, city, latitude, longitude,
             asn, org, attempts, status, session_id, connection_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts, ip, random.choice(USERNAMES), "password",
                "SSH-2.0-libssh2_1.11.1", "SSH-2.0",
                country, city, lat, lon, str(asn), org,
                random.randint(10, 50), "success",
                f"{ip}-{int(datetime.now().timestamp())}-success",
                round(random.uniform(0.1, 3.0), 2),
            ),
        )
        total += 1

    conn.commit()
    conn.close()
    print(f"\n  Total: {total} attacks seeded")
    return total


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    rounds = max(1, n // len(ATTACKERS))
    print(f"Seeding ~{rounds * len(ATTACKERS)} attacks ({rounds} rounds, {len(ATTACKERS)} IPs)...")
    seed(rounds=rounds)
    print("Done!")
