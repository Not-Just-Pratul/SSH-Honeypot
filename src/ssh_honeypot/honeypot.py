"""SSH Honeypot server implementation.

Simulates an SSH server using Paramiko's SocketServer to accept
incoming connections, log authentication attempts, and immediately
terminate sessions without providing any shell access.

Includes brute-force detection and optional fail2Ban integration
for automated attacker blocking.
"""

import contextlib
import logging
import os
import socket
import subprocess
import threading
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from threading import RLock

import paramiko
from paramiko.server import ServerInterface
from paramiko.transport import Transport

from ssh_honeypot.config import config
from ssh_honeypot.logger import record_attack, sanitize_string

logger = logging.getLogger("ssh_honeypot")


_cached_host_key: paramiko.RSAKey | None = None


def _load_host_key() -> paramiko.RSAKey:
    """Load and cache the RSA host key from the configured path."""
    global _cached_host_key
    if _cached_host_key is not None:
        return _cached_host_key

    key_path = config.honeypot.host_key_path
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Host key not found at {key_path}. "
            "Generate one with: openssl genrsa -out keys/ssh_host_rsa_key 2048"
        )
    _cached_host_key = paramiko.RSAKey(filename=key_path)
    return _cached_host_key


class HoneypotServer(ServerInterface):
    """Paramiko server implementation that rejects all authentication."""

    def __init__(self, client_ip: str, client_port: int) -> None:
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
        self.session_id = sanitize_string(
            f"{client_ip}-{int(time.time())}"
        )
        self.start_time = time.time()
        self.username_attempted = ""
        self.auth_method = "none"
        self.client_version = ""
        self.protocol_version = ""
        self.attempt_count = 0

    def check_channel_request(
        self, kind: str, chanid: int
    ) -> int:
        """Allow session channel requests."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username: str) -> int:
        """Reject password-less authentication attempts."""
        self.username_attempted = sanitize_string(username)
        self.auth_method = "none"
        self.attempt_count += 1
        logger.info(
            "Auth attempt (none) from %s:%d user=%s",
            self.client_ip,
            self.client_port,
            username,
        )
        return paramiko.AUTH_FAILED

    def check_auth_password(
        self, username: str, password: str
    ) -> int:
        """Reject password authentication attempts."""
        self.username_attempted = sanitize_string(username)
        self.auth_method = "password"
        self.attempt_count += 1
        logger.info(
            "Auth attempt (password) from %s:%d user=%s",
            self.client_ip,
            self.client_port,
            username,
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(
        self, username: str, key: paramiko.pkey.PKey
    ) -> int:
        """Reject public key authentication attempts."""
        self.username_attempted = sanitize_string(username)
        self.auth_method = "publickey"
        self.attempt_count += 1
        logger.info(
            "Auth attempt (publickey) from %s:%d user=%s",
            self.client_ip,
            self.client_port,
            username,
        )
        return paramiko.AUTH_FAILED

    def check_auth_keyboard_interactive(
        self, username: str, submethods: str
    ) -> int:
        """Reject keyboard-interactive authentication attempts."""
        self.username_attempted = sanitize_string(username)
        self.auth_method = "keyboard-interactive"
        self.attempt_count += 1
        logger.info(
            "Auth attempt (keyboard-interactive) from %s:%d user=%s",
            self.client_ip,
            self.client_port,
            username,
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """Return empty string to advertise no allowed auth methods."""
        return ""

    def check_channel_shell_request(self, channel) -> bool:
        """Deny shell access regardless of request."""
        return False

    def check_channel_exec_request(
        self, channel, command: bytes
    ) -> bool:
        """Deny command execution requests."""
        return False

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        """Deny PTY allocation requests."""
        return False

    def check_channel_window_adjust_request(
        self, channel, bytes_to_add
    ) -> bool:
        """Accept window adjustment requests."""
        return True

    def finalize_session(self) -> None:
        """Log and record the finalized attack session."""
        duration = time.time() - self.start_time
        event: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": self.client_ip,
            "port": self.client_port,
            "username": self.username_attempted or "unknown",
            "auth_method": self.auth_method,
            "client_version": sanitize_string(self.client_version),
            "protocol_version": sanitize_string(self.protocol_version),
            "attempts": self.attempt_count,
            "status": "failure",
            "session_id": self.session_id,
            "connection_duration": round(duration, 2),
        }
        record_attack(event)


class BruteForceDetector:
    """Tracks failed authentication attempts per IP and triggers
    fail2Ban blocking when thresholds are exceeded."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        ban_duration: int = 3600,
        fail2ban_enabled: bool = False,
        fail2ban_action: str = "ban",
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ban_duration = ban_duration
        self.fail2ban_enabled = fail2ban_enabled
        self.fail2ban_action = fail2ban_action
        self._attempts: dict[str, list] = defaultdict(list)
        self._banned: dict[str, float] = {}
        self._lock = RLock()

    def record_attempt(self, ip: str) -> bool:
        """Record a failed attempt for an IP.

        Returns True if the IP should be banned (threshold exceeded).
        """
        now = time.time()
        with self._lock:
            self._attempts[ip].append(now)
            cutoff = now - self.window_seconds
            self._attempts[ip] = [
                t for t in self._attempts[ip] if t > cutoff
            ]
            count = len(self._attempts[ip])

            if count >= self.threshold and ip not in self._banned:
                self._banned[ip] = now + self.ban_duration
                logger.warning(
                    "Brute-force detected from %s (%d attempts in %ds). "
                    "Triggering %s.",
                    ip,
                    count,
                    self.window_seconds,
                    self.fail2ban_action,
                )
                if self.fail2ban_enabled:
                    self._invoke_fail2ban(ip)
                return True
        return False

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned."""
        now = time.time()
        with self._lock:
            ban_until = self._banned.get(ip, 0)
            if ban_until > now:
                return True
            if ban_until > 0:
                del self._banned[ip]
                del self._attempts[ip]
        return False

    def _invoke_fail2ban(self, ip: str) -> None:
        """Invoke fail2Ban-client to ban an IP address.

        Only runs if fail2ban-client is available on the system.
        """
        try:
            subprocess.run(
                [
                    "fail2ban-client",
                    "set",
                    "sshd",
                    "banip",
                    ip,
                ],
                capture_output=True,
                timeout=5,
            )
            logger.info("fail2Ban issued ban for %s", ip)
        except FileNotFoundError:
            logger.info(
                "fail2Ban-client not found. Install fail2Ban for "
                "automated blocking of %s",
                ip,
            )
        except subprocess.TimeoutExpired:
            logger.error("fail2Ban-client timed out banning %s", ip)
        except Exception as exc:
            logger.error("fail2Ban ban failed for %s: %s", ip, exc)

    def get_banned_ips(self) -> list:
        """Return list of currently banned IPs."""
        now = time.time()
        with self._lock:
            return [
                ip
                for ip, until in self._banned.items()
                if until > now
            ]

    def get_stats(self) -> dict:
        """Return brute-force detection statistics."""
        with self._lock:
            return {
                "total_tracked_ips": len(self._attempts),
                "currently_banned": len(self.get_banned_ips()),
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
            }


_brute_force_detector: BruteForceDetector | None = None


def get_brute_force_detector() -> BruteForceDetector:
    """Return a singleton BruteForceDetector instance."""
    global _brute_force_detector
    if _brute_force_detector is None:
        _brute_force_detector = BruteForceDetector(
            threshold=5,
            window_seconds=60,
            ban_duration=3600,
            fail2ban_enabled=False,
        )
    return _brute_force_detector


def handle_client_connection(
    client_sock: socket.socket,
    client_addr: tuple,
    server_sock: socket.socket,
) -> None:
    """Handle a single incoming SSH connection.

    Performs the SSH handshake, processes authentication attempts,
    terminates the session after logging, and triggers brute-force
    detection for repeated offenders.

    Args:
        client_sock: The connected client socket.
        client_addr: Client address tuple (ip, port).
        server_sock: The listening server socket (for reference).
    """
    client_ip, client_port = client_addr
    logger.info(
        "New connection from %s:%d", client_ip, client_port
    )

    detector = get_brute_force_detector()

    if detector.is_banned(client_ip):
        logger.warning(
            "Blocked banned IP %s:%d", client_ip, client_port
        )
        client_sock.close()
        return

    try:
        transport = Transport(client_sock)
        host_key = _load_host_key()
        transport.add_server_key(host_key)

        server = HoneypotServer(client_ip, client_port)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            logger.warning(
                "SSH handshake failed with %s:%d", client_ip, client_port
            )
            detector.record_attempt(client_ip)
            transport.close()
            return

        if hasattr(transport, "session"):
            server.client_version = getattr(transport, "remote_version", "")
            server.protocol_version = getattr(transport, "local_version", "")

        channel = transport.accept(timeout=config.honeypot.connection_timeout)
        if channel is None:
            logger.info(
                "No channel opened by %s:%d, terminating", client_ip, client_port
            )
            detector.record_attempt(client_ip)
            server.finalize_session()
            transport.close()
            return

        logger.info(
            "Session established with %s:%d, denying access", client_ip, client_port
        )

        detector.record_attempt(client_ip)

        channel.close()
        server.finalize_session()
        transport.close()

    except TimeoutError:
        logger.info(
            "Connection timed out with %s:%d", client_ip, client_port
        )
    except Exception as exc:
        tb = traceback.format_exc()
        logger.error(
            "Error handling connection from %s:%d: %s | Traceback:\n%s",
            client_ip,
            client_port,
            repr(exc),
            tb,
        )
    finally:
        with contextlib.suppress(Exception):
            client_sock.close()


def start_honeypot(
    host: str | None = None,
    port: str | None = None,
) -> None:
    """Start the SSH honeypot server and listen for connections.

    Args:
        host: Bind address (defaults to config.honeypot.host).
        port: Bind port (defaults to config.honeypot.port).
    """
    bind_host = host or config.honeypot.host
    bind_port = port or config.honeypot.port

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(60)

    try:
        server_sock.bind((bind_host, bind_port))
        server_sock.listen(config.honeypot.max_connections)
        logger.info(
            "SSH Honeypot listening on %s:%d", bind_host, bind_port
        )
        logger.info(
            "Banner: %s", config.honeypot.banner
        )
        logger.info(
            "Server version: %s", config.honeypot.server_version
        )
        logger.warning(
            "This honeypot is for defensive security research only."
        )

        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                client_sock.settimeout(
                    config.honeypot.connection_timeout
                )

                client_thread = threading.Thread(
                    target=handle_client_connection,
                    args=(client_sock, client_addr, server_sock),
                    daemon=True,
                )
                client_thread.start()

            except TimeoutError:
                continue
            except KeyboardInterrupt:
                logger.info("Shutting down honeypot...")
                break
            except OSError:
                break

    except OSError as exc:
        logger.error(
            "Failed to bind to %s:%d: %s", bind_host, bind_port, exc
        )
        raise
    finally:
        server_sock.close()
        logger.info("Honeypot server stopped.")


if __name__ == "__main__":
    start_honeypot()
