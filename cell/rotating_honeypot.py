#!/usr/bin/env python3
"""
WRAITH v5.0 — Rotating Honeypot System
========================================
Deploys fake services that rotate ports every 5-10 seconds to
high ports (40000-65535). Logs all attacker interactions and
extracts IOCs from behavior.

Services: SSH (22), FTP (21), MySQL (3306), HTTP (80), RDP (3389)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import secrets
import socket
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

CELL_HOME = Path(os.path.expanduser("~")) / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
HONEYPOT_LOG = CELL_HOME / "honeypot_attacks.json"
HONEYPOT_IOC = CELL_HOME / "honeypot_iocs.json"

log = logging.getLogger("wraith-honeypot")

# ═══════════════════════════════════════════════════════════════
# SERVICE BANNERS — Realistic service identification strings
# ═══════════════════════════════════════════════════════════════

SERVICE_BANNERS: Dict[str, str] = {
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "ftp": "220 (vsFTPd 3.0.5)",
    "mysql": "5.7.42-0ubuntu0.04.14-log\\x00\\x00\\x00",
    "http": (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
    ),
    "http_nginx": (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
    ),
    "rdp": "RDP_NEGotiation_Request|Standard RDP",
}

# Fake credentials that rotate periodically
FAKE_CREDENTIALS = {
    "ssh": [
        ("root", "toor"),
        ("admin", "admin123"),
        ("ubuntu", "ubuntu2024"),
        ("deploy", "deploy2024"),
        ("vagrant", "vagrant"),
    ],
    "ftp": [
        ("ftpuser", "ftp2024"),
        ("anonymous", ""),
        ("admin", "ftp_admin"),
        ("backup", "backup123"),
    ],
    "mysql": [
        ("root", "mysql_root_2024"),
        ("admin", "db_admin_pass"),
        ("wp_user", "wordpress_db_2024"),
        ("app_user", "app_secret_db"),
    ],
    "http": [
        ("admin", "admin_portal_2024"),
        ("webmaster", "web_portal_pass"),
    ],
    "rdp": [
        ("Administrator", "WinServer2024!"),
        ("user01", "UserPass123!"),
    ],
}


# ═══════════════════════════════════════════════════════════════
# IOC EXTRACTOR — Extract attacker intelligence from interactions
# ═══════════════════════════════════════════════════════════════

class IOCExtractor:
    """Extract Indicators of Compromise from attacker behavior."""

    def __init__(self, storage_path: Path = HONEYPOT_IOC):
        self.storage_path = storage_path
        self._iocs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.storage_path.exists():
            try:
                self._iocs = json.loads(self.storage_path.read_text())
            except (json.JSONDecodeError, IOError):
                self._iocs = []

    def extract(self, service: str, client_ip: str, client_port: int,
                data: bytes, timestamp: str) -> Dict[str, Any]:
        """Extract IOCs from an interaction."""
        ioc = {
            "timestamp": timestamp,
            "service": service,
            "attacker_ip": client_ip,
            "attacker_port": client_port,
            "data_length": len(data),
            "data_hash": hashlib.sha256(data).hexdigest()[:16],
            "indicators": [],
        }

        # Extract usernames from login attempts
        decoded = data.decode("utf-8", errors="ignore").lower()
        for proto_key, creds in FAKE_CREDENTIALS.items():
            for user, passwd in creds:
                if user.lower() in decoded:
                    ioc["indicators"].append({
                        "type": "credential_use",
                        "value": user,
                        "protocol": proto_key,
                    })
                if passwd and passwd.lower() in decoded:
                    ioc["indicators"].append({
                        "type": "password_use",
                        "value": passwd[:4] + "***",
                        "protocol": proto_key,
                    })

        # Detect scanning patterns
        if len(data) > 1000:
            ioc["indicators"].append({
                "type": "large_payload",
                "size": len(data),
            })

        # Detect SQL injection attempts
        sql_patterns = ["select ", "union ", "drop ", "insert ", "or 1=1", "'--"]
        for pat in sql_patterns:
            if pat in decoded:
                ioc["indicators"].append({
                    "type": "sqli_attempt",
                    "pattern": pat.strip(),
                })
                break

        # Detect command injection
        cmd_patterns = ["; ls", "| cat", "&& whoami", "; cat /etc/passwd", "$(curl"]
        for pat in cmd_patterns:
            if pat in decoded:
                ioc["indicators"].append({
                    "type": "cmd_injection",
                    "pattern": pat.strip(),
                })
                break

        with self._lock:
            self._iocs.append(ioc)
            # Keep last 10000 IOCs
            if len(self._iocs) > 10000:
                self._iocs = self._iocs[-10000:]
            self._save()

        return ioc

    def _save(self):
        try:
            self.storage_path.write_text(json.dumps(self._iocs, indent=2, default=str))
        except IOError:
            pass

    def get_iocs(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            return self._iocs[-limit:]

    def get_attacker_ips(self) -> Set[str]:
        with self._lock:
            return {ioc["attacker_ip"] for ioc in self._iocs}


# ═══════════════════════════════════════════════════════════════
# SERVICE EMULATOR — One per fake service
# ═══════════════════════════════════════════════════════════════

class ServiceEmulator:
    """Emulates a single fake service on a given port."""

    def __init__(self, service_name: str, port: int, ioc_extractor: IOCExtractor):
        self.service_name = service_name
        self.port = port
        self.ioc = ioc_extractor
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._interactions: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._banner = self._pick_banner()
        self._creds = random.choice(FAKE_CREDENTIALS.get(service_name, [("user", "pass")]))

    def _pick_banner(self) -> str:
        if self.service_name == "http":
            return random.choice([SERVICE_BANNERS["http"], SERVICE_BANNERS["http_nginx"]])
        return SERVICE_BANNERS.get(self.service_name, "220 Service Ready")

    def start(self):
        self._running = True
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.settimeout(2.0)
            self._socket.bind(("0.0.0.0", self.port))
            self._socket.listen(5)
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            log.debug(f"Honeypot {self.service_name} listening on :{self.port}")
        except OSError as exc:
            log.warning(f"Cannot bind honeypot {self.service_name} on :{self.port}: {exc}")
            self._running = False

    def stop(self):
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass

    def _serve(self):
        """Main accept loop."""
        while self._running:
            try:
                conn, addr = self._socket.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Handle a single attacker connection."""
        client_ip, client_port = addr
        timestamp = datetime.now(timezone.utc).isoformat()
        data_received = b""

        try:
            conn.settimeout(10.0)

            # Send banner
            if self.service_name in ("ssh", "ftp", "mysql"):
                conn.sendall((self._banner + "\r\n").encode())
            elif self.service_name == "http":
                # Wait for HTTP request first
                try:
                    data_received = conn.recv(8192)
                    conn.sendall((
                        self._banner +
                        "\r\n\r\n<html><head><title>404 Not Found</title></head>"
                        "<body><h1>Not Found</h1><p>The requested URL was not found.</p>"
                        "</body></html>"
                    ).encode())
                except socket.timeout:
                    pass
            elif self.service_name == "rdp":
                conn.sendall(
                    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00"
                )

            # Try to receive more data
            if not data_received:
                try:
                    data_received = conn.recv(8192)
                except socket.timeout:
                    data_received = b""

            # Log interaction
            interaction = {
                "timestamp": timestamp,
                "service": self.service_name,
                "client_ip": client_ip,
                "client_port": client_port,
                "data_length": len(data_received),
                "data_preview": data_received[:200].decode("utf-8", errors="replace"),
            }

            with self._lock:
                self._interactions.append(interaction)
                # Keep last 500 interactions per service
                if len(self._interactions) > 500:
                    self._interactions = self._interactions[-500:]

            # Extract IOCs
            if data_received:
                self.ioc.extract(
                    self.service_name, client_ip, client_port,
                    data_received, timestamp,
                )

            log.info(
                f"Honeypot [{self.service_name}] hit from {client_ip}:{client_port} "
                f"({len(data_received)} bytes)"
            )

        except Exception as exc:
            log.debug(f"Honeypot handler error: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def rotate_banner(self):
        """Pick a new random banner."""
        self._banner = self._pick_banner()
        self._creds = random.choice(
            FAKE_CREDENTIALS.get(self.service_name, [("user", "pass")])
        )

    @property
    def interaction_count(self) -> int:
        with self._lock:
            return len(self._interactions)

    def get_interactions(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            return self._interactions[-limit:]


# ═══════════════════════════════════════════════════════════════
# ROTATING HONEYPOT — Main orchestrator
# ═══════════════════════════════════════════════════════════════

class RotatingHoneypot:
    """
    Rotating honeypot system that:
    - Deploys 5 fake services (SSH, FTP, MySQL, HTTP, RDP)
    - Rotates ports every 5-10 seconds to random high ports (40000-65535)
    - Logs all attacker interactions
    - Extracts IOCs from attacker behavior
    - Thread-safe, non-blocking
    """

    SERVICES = ["ssh", "ftp", "mysql", "http", "rdp"]
    PORT_RANGE = (40000, 65535)
    ROTATION_MIN = 5   # seconds
    ROTATION_MAX = 10  # seconds

    def __init__(self, log_path: Optional[Path] = None,
                 ioc_path: Optional[Path] = None):
        self.log_path = log_path or HONEYPOT_LOG
        self.ioc_extractor = IOCExtractor(ioc_path or HONEYPOT_IOC)
        self._services: Dict[str, ServiceEmulator] = {}
        self._used_ports: Set[int] = set()
        self._running = False
        self._rotation_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._total_interactions = 0

    def _random_port(self) -> int:
        """Generate a random unused high port."""
        for _ in range(100):
            port = random.randint(*self.PORT_RANGE)
            if port not in self._used_ports:
                # Quick check if port is actually free
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.bind(("0.0.0.0", port))
                    s.close()
                    self._used_ports.add(port)
                    return port
                except OSError:
                    self._used_ports.add(port)
                    continue
        # Fallback: just pick random
        return random.randint(*self.PORT_RANGE)

    def _release_port(self, port: int):
        self._used_ports.discard(port)

    def start(self):
        """Start the honeypot system."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        # Start all services
        for svc_name in self.SERVICES:
            self._spawn_service(svc_name)

        # Start rotation thread
        self._rotation_thread = threading.Thread(
            target=self._rotation_loop, daemon=True
        )
        self._rotation_thread.start()
        log.info(
            f"RotatingHoneypot started — {len(self.SERVICES)} services, "
            f"rotation every {self.ROTATION_MIN}-{self.ROTATION_MAX}s"
        )

    def _spawn_service(self, svc_name: str):
        """Start a single service on a new random port."""
        port = self._random_port()
        emulator = ServiceEmulator(svc_name, port, self.ioc_extractor)
        emulator.start()
        old = self._services.get(svc_name)
        self._services[svc_name] = emulator
        if old:
            old._stop_event if hasattr(old, '_stop_event') else None
            try:
                old.stop()
            except Exception:
                pass
            self._release_port(old.port)
        log.info(f"Honeypot service [{svc_name}] on :{port}")

    def _rotation_loop(self):
        """Periodically rotate service ports."""
        while not self._stop_event.is_set():
            wait = random.uniform(self.ROTATION_MIN, self.ROTATION_MAX)
            self._stop_event.wait(wait)
            if self._stop_event.is_set():
                break

            # Pick a random service to rotate
            svc_name = random.choice(self.SERVICES)
            self._spawn_service(svc_name)

            # Rotate banners for all services
            for svc in self._services.values():
                svc.rotate_banner()

    def stop(self):
        """Stop all services and rotation."""
        self._running = False
        self._stop_event.set()
        for svc in self._services.values():
            svc.stop()
        self._services.clear()
        self._used_ports.clear()
        log.info("RotatingHoneypot stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get current honeypot status."""
        services = {}
        for name, svc in self._services.items():
            services[name] = {
                "port": svc.port,
                "interactions": svc.interaction_count,
                "banner": svc._banner[:50],
            }
        return {
            "running": self._running,
            "services": services,
            "total_interactions": sum(
                s.interaction_count for s in self._services.values()
            ),
            "iocs_collected": len(self.ioc_extractor.get_iocs(999999)),
            "attacker_ips": list(self.ioc_extractor.get_attacker_ips()),
        }

    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        """Get recent attack interactions."""
        all_interactions = []
        for svc in self._services.values():
            all_interactions.extend(svc.get_interactions(limit))
        all_interactions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return all_interactions[:limit]

    def get_iocs(self, limit: int = 100) -> List[Dict]:
        """Get extracted IOCs."""
        return self.ioc_extractor.get_iocs(limit)

    @property
    def is_healthy(self) -> bool:
        return self._running and len(self._services) == len(self.SERVICES)
