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

import socket
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

# Common SSH client banners
BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "SSH-2.0-OpenSSH_9.0p1 Debian-1",
    "SSH-2.0-OpenSSH_8.0",
    "SSH-2.0-OpenSSH_7.9",
    "SSH-2.0-libssh2_1.11.1",
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-PuTTY_Release_0.79",
    "SSH-2.0-Paramiko_3.4.0",
    "SSH-2.0-dropbear_2022.83",
    "SSH-2.0-mobileSSH",
]


def simulate_ssh_attack(host: str = "127.0.0.1", port: int = 2222) -> bool:
    """Simulate a single SSH connection attempt using the system ssh client.

    Returns True if the connection was attempted.
    """
    username = random.choice(USERNAMES)
    try:
        result = subprocess.run(
            [
                "ssh",
                "-p", str(port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=NUL",
                "-o", "ConnectTimeout=3",
                "-o", "BatchMode=yes",
                f"{username}@{host}",
            ],
            capture_output=True,
            timeout=5,
        )
        return True
    except subprocess.TimeoutExpired:
        return True
    except Exception:
        return simulate_raw_ssh_attempt(host, port, username)


def simulate_raw_ssh_attempt(host: str, port: int, username: str) -> bool:
    """Simulate an SSH connection at the raw socket level."""
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((host, port))
        # Send client banner
        banner = random.choice(BANNERS)
        sock.send(f"{banner}\r\n".encode())
        # Read server banner
        sock.recv(1024)
        sock.close()
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
