"""SSH Honeypot + Live Threat Intelligence Dashboard.

This is the backward-compatible entry point. Prefer using the package
installation: `pip install -e .` and then `ssh-honeypot` CLI command.

Usage:
    python app.py [mode] [options]
    ssh-honeypot [mode] [options]
    python -m ssh_honeypot [mode] [options]
"""

from ssh_honeypot.app import main

if __name__ == "__main__":
    main()
