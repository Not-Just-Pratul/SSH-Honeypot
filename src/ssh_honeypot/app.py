"""Main entry point for SSH Honeypot + Live Threat Intelligence Dashboard.

Launches the honeypot server, the Streamlit dashboard, and/or the REST API
depending on command-line arguments. Designed for defensive
security research and educational purposes only.

Usage:
    python -m ssh_honeypot honeypot     Start only the SSH honeypot server
    python -m ssh_honeypot dashboard    Start only the Streamlit dashboard
    python -m ssh_honeypot api          Start only the REST API
    python -m ssh_honeypot all          Start all components (default)
"""

import argparse
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone

from ssh_honeypot.config import config


def start_honeypot_server() -> None:
    """Start the SSH honeypot server in the current thread."""
    from ssh_honeypot.honeypot import start_honeypot

    logger = logging.getLogger("ssh_honeypot")
    logger.info("Starting SSH Honeypot server...")
    logger.info(
        "Listening on %s:%d (simulated SSH service)",
        config.honeypot.host,
        config.honeypot.port,
    )
    logger.info("WARNING: This honeypot is for defensive security research only.")
    start_honeypot(host=config.honeypot.host, port=config.honeypot.port)


def start_api_server() -> None:
    """Start the REST API server in the current thread."""
    from ssh_honeypot.api_server import start_api_server as _start_api_server

    logger = logging.getLogger("ssh_honeypot")
    logger.info("Starting REST API server on %s:%d", config.api.host, config.api.port)
    _start_api_server(host=config.api.host, port=config.api.port)


def start_dashboard() -> subprocess.Popen:
    """Start the Streamlit dashboard as a subprocess.

    Returns:
        The Popen process handle so the caller can monitor or terminate it.
    """
    dashboard_port = config.dashboard.port
    dashboard_host = config.dashboard.host
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(app_dir, "..", ".."))
    runner_path = os.path.join(project_root, "dashboard_runner.py")

    if not os.path.isfile(runner_path):
        # Fallback: Docker container layout
        docker_path = "/app/dashboard_runner.py"
        if os.path.isfile(docker_path):
            runner_path = docker_path
        else:
            # Fallback: running as installed package — find the module file
            import ssh_honeypot.dashboard as dash_mod

            runner_path = os.path.abspath(dash_mod.__file__)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        runner_path,
        "--server.port",
        str(dashboard_port),
        "--server.address",
        dashboard_host,
    ]

    logger = logging.getLogger("ssh_honeypot")
    logger.info("Starting Streamlit dashboard on %s:%d", dashboard_host, dashboard_port)

    process = subprocess.Popen(
        cmd,
        cwd=app_dir,
        env={
            **os.environ,
            "DATABASE_PATH": os.path.join(project_root, "logs", "attack_logs.db"),
            "HONEYPOT_HOST_KEY_PATH": os.path.join(project_root, "keys", "ssh_host_rsa_key"),
        },
    )
    return process


def main() -> None:
    """Parse arguments and launch the selected components."""
    parser = argparse.ArgumentParser(
        description="SSH Honeypot + Live Threat Intelligence Dashboard",
        epilog="⚠️  This tool is for defensive security research and education only.",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="all",
        choices=["honeypot", "dashboard", "all", "api"],
        help="Component to start: honeypot, dashboard, api, or all (default: all)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override honeypot bind host (default: from config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override honeypot bind port (default: 2222)",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Override dashboard port (default: 8501)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging verbosity level",
    )

    args = parser.parse_args()

    # Set absolute paths for database and host key so all processes use the same files.
    # Config is loaded at import time so we must update the config object directly too.
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(app_dir, "..", ".."))

    abs_db = os.path.join(project_root, "logs", "attack_logs.db")
    abs_key = os.path.join(project_root, "keys", "ssh_host_rsa_key")
    os.environ.setdefault("DATABASE_PATH", abs_db)
    os.environ.setdefault("HONEYPOT_HOST_KEY_PATH", abs_key)
    config.database.db_path = abs_db
    config.honeypot.host_key_path = abs_key

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logger = logging.getLogger("ssh_honeypot")
    logger.setLevel(log_level)

    if not logger.handlers:
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logger.addHandler(logging.StreamHandler())
        logger.addHandler(
            logging.handlers.RotatingFileHandler(
                os.path.join(os.path.dirname(__file__), "..", "..", "logs", "app.log"),
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
        )
        for h in logger.handlers:
            h.setFormatter(fmt)
            h.setLevel(log_level)

    logger.propagate = False

    logger.info("=" * 60)
    logger.info("SSH Honeypot + Live Threat Intelligence Dashboard")
    logger.info(f"Started at {datetime.now(timezone.utc).isoformat()}")
    logger.info("=" * 60)

    if args.host is not None:
        config.honeypot.host = args.host
    if args.port is not None:
        config.honeypot.port = args.port
    if args.dashboard_port is not None:
        config.dashboard.port = args.dashboard_port

    if args.mode == "honeypot":
        start_honeypot_server()
    elif args.mode == "dashboard":
        dashboard_proc = start_dashboard()
        try:
            dashboard_proc.wait()
        except KeyboardInterrupt:
            logger.info("Shutting down dashboard...")
            dashboard_proc.terminate()
            dashboard_proc.wait()
    elif args.mode == "api":
        start_api_server()
    else:
        honeypot_thread = threading.Thread(
            target=start_honeypot_server,
            daemon=True,
        )
        honeypot_thread.start()

        if config.api.enabled:
            api_thread = threading.Thread(
                target=start_api_server,
                daemon=True,
            )
            api_thread.start()

        dashboard_proc = start_dashboard()
        try:
            dashboard_proc.wait()
        except KeyboardInterrupt:
            logger.info("Shutting down components...")
            dashboard_proc.terminate()
            dashboard_proc.wait()
            logger.info("All components stopped.")


def _handle_signal(signum: int, frame: object) -> None:
    """Handle termination signals gracefully."""
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    main()
