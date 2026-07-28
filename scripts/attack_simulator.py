#!/usr/bin/env python3
"""Attack simulator for SSH Honeypot.

Generates realistic-looking attack traffic against the honeypot
for testing and demonstration purposes.

Usage:
    python scripts/attack_simulator.py [count] [--delay N]

Examples:
    python scripts/attack_simulator.py 50          # 50 attacks fast
    python scripts/attack_simulator.py 10 --delay 1 # 10 attacks, 1s apart
"""

import subprocess
import sys
import time
import random

# Common usernames attackers try
USERNAMES = [
    "root", "admin", "test", "ubuntu", "oracle", "postgres",
    "pi", "git", "deploy", "jenkins", "www-data", "backup",
    "user", "nagios", "guest", "info", "support", "webmaster",
    "mysql", "tomcat", "hadoop", "zabbix", "amavis", "nobody",
    "ansible", "redis", "mongodb", "elastic", "docker",
]


def simulate_ssh_attack(host: str = "127.0.0.1", port: int = 2222) -> bool:
    """Simulate an SSH connection using the system SSH client.

    Uses the OpenSSH client with BatchMode=yes. The honeypot will:
    1. Accept the TCP connection
    2. Complete the SSH transport negotiation
    3. Receive the 'none' authentication attempt
    4. Log and reject it
    """
    username = random.choice(USERNAMES)
    try:
        subprocess.run(
            [
                "ssh",
                "-p", str(port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=" + ("NUL" if sys.platform == "win32" else "/dev/null"),
                "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                "-o", "LogLevel=ERROR",
                f"{username}@{host}",
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
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 0.2

    host = "127.0.0.1"
    port = 2222

    print("=== Attack Simulator ===")
    print(f"   Target: {host}:{port}")
    print(f"   Attacks: {count}")
    print(f"   Delay: {delay}s")
    print()

    successful = 0
    start = time.time()

    for i in range(count):
        username = random.choice(USERNAMES)
        try:
            if simulate_ssh_attack(host, port):
                successful += 1
        except Exception:
            pass

        # Progress indicator
        if (i + 1) % 5 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"   [{i+1}/{count}] {successful} connected | {rate:.1f} attacks/s")

        time.sleep(delay)

    elapsed = time.time() - start
    print(f"\nDone: {successful}/{count} attacks sent in {elapsed:.1f}s")
    print(f"   Rate: {count/elapsed:.1f} attacks/s")


if __name__ == "__main__":
    main()
