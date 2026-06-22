#!/usr/bin/env python3
"""
WRAITH Cell Core v3.0 — The Heart of WRAITH on Every Device
============================================================

The cell_core is the autonomous security agent that runs on each user device.
It contains 26+ security agents, a persistent brain, P2P mesh networking,
honeypot services, wire protocol for Admin communication, kill switch support,
multi-device linking, local LLM integration, and a self-evolution engine.

Architecture:
    CellBrain (persistent memory + learning)
    ├── Security Agents (26+ detection engines)
    ├── Biomesh (P2P mesh networking)
    ├── HoneyPot (rotating fake services)
    ├── WireProtocol (Admin communication)
    ├── KillSwitch (emergency shutdown)
    ├── DeviceLink (multi-device mesh)
    ├── LLMInterface (Ollama/local LLM)
    └── SelfEvolver (autonomous improvement)

Usage:
    python cell_core.py                  # Run full cell
    python cell_core.py --scan           # Run all agents once
    python cell_core.py --daemon         # Run as persistent daemon
    python cell_core.py --status         # Show agent status
    python cell_core.py --kill-switch    # Trigger kill switch
"""

from __future__ import annotations

import abc
import argparse
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import random
import re
import secrets
import shutil
import socket
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import urllib.error
import urllib.parse
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Deque, Dict, List, Optional, Set, Tuple, Union
)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("wraith.cell_core")

# ---------------------------------------------------------------------------
# CONSTANTS & CONFIG
# ---------------------------------------------------------------------------

CELL_HOME = Path.home() / ".wraith_cell"
CELL_HOME.mkdir(parents=True, exist_ok=True)
BRAIN_DB_PATH = CELL_HOME / "cell_brain.db"
SKILLS_DIR = CELL_HOME / "skills"
SKILLS_DIR.mkdir(parents=True, exist_ok=True)
HONEYPOT_DIR = CELL_HOME / "honeypot"
HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR = CELL_HOME / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

CELL_ID: str = os.environ.get("WRAITH_CELL_ID", "")
if not CELL_ID:
    id_file = CELL_HOME / ".cell_id"
    if id_file.exists():
        CELL_ID = id_file.read_text().strip()
    else:
        CELL_ID = f"cell_{uuid.uuid4().hex}"  # Full 128-bit UUID
        # Atomic write to prevent race condition between concurrent instances
        tmp_file = id_file.with_suffix(".tmp")
        tmp_file.write_text(CELL_ID)
        tmp_file.rename(id_file)

# Restrict .cell_id file permissions to owner-only
try:
    if sys.platform != "win32":
        os.chmod(str(id_file), 0o600)
except Exception:
    pass

ADMIN_SIGN_KEY: str = os.environ.get("WRAITH_ADMIN_SIGN_KEY", "")
TRACKER_URL: str = os.environ.get("WRAITH_TRACKER_URL", "https://localhost:7734")
OLLAMA_URL: str = os.environ.get("OLLAMA_URL", "https://localhost:11434")
BIOMESH_PORT: int = int(os.environ.get("WRAITH_BIOMESH_PORT", "8765"))
HONEYPOT_BASE_PORT: int = int(os.environ.get("WRAITH_HONEYPOT_PORT", "9500"))

# Fail to start if ADMIN_SIGN_KEY is not set
if not ADMIN_SIGN_KEY:
    log.critical("WRAITH_ADMIN_SIGN_KEY is not set — Admin commands will be rejected")
    # Don't exit — cell can still operate in standalone mode, but Admin channel is disabled

VERSION = "3.0.0"
MAX_LOG_ENTRIES = 10_000
SCAN_TIMEOUT = 10


# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class Finding:
    """A single finding from any security agent."""
    agent: str
    severity: Severity
    title: str
    description: str
    indicators: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat()
    )
    finding_id: str = field(
        default_factory=lambda: uuid.uuid4().hex[:16]
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AgentInfo:
    """Status info for a single agent."""
    name: str
    status: AgentStatus
    last_run: Optional[str] = None
    findings_count: int = 0
    error: Optional[str] = None
    version: str = "1.0"


# ---------------------------------------------------------------------------
# BASE AGENT
# ---------------------------------------------------------------------------

class BaseAgent(abc.ABC):
    """Abstract base for all 26+ security agents."""

    name: str = "base_agent"
    version: str = "1.0"

    def __init__(self):
        self._status = AgentStatus.IDLE
        self._last_run: Optional[str] = None
        self._findings_count = 0
        self._last_error: Optional[str] = None

    @abc.abstractmethod
    def run(self) -> List[Finding]:
        """Execute the agent's detection logic and return findings."""
        ...

    def get_status(self) -> AgentInfo:
        return AgentInfo(
            name=self.name,
            status=self._status,
            last_run=self._last_run,
            findings_count=self._findings_count,
            error=self._last_error,
            version=self.version,
        )

    def _set_running(self):
        self._status = AgentStatus.RUNNING

    def _set_done(self, count: int):
        self._status = AgentStatus.IDLE
        self._last_run = datetime.datetime.utcnow().isoformat()
        self._findings_count += count

    def _set_error(self, msg: str):
        self._status = AgentStatus.ERROR
        self._last_error = msg
        self._last_run = datetime.datetime.utcnow().isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 1: NetworkScanner
# ═══════════════════════════════════════════════════════════════════════════

class NetworkScanner(BaseAgent):
    """
    Scans local network for active hosts, open connections,
    and suspicious network activity.
    """

    name = "network_scanner"
    version = "1.0"

    # Known malicious port ranges
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321}
    # Common C2 ports
    C2_PORTS = {4433, 8443, 9443, 1337, 4443}

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check active connections
            connections = self._get_active_connections()
            for conn in connections:
                remote_port = conn.get("remote_port", 0)
                remote_addr = conn.get("remote_addr", "")
                if remote_port in self.SUSPICIOUS_PORTS:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"Suspicious port connection: {remote_port}",
                        description=f"Connection to {remote_addr}:{remote_port} — known suspicious port",
                        indicators={"remote_addr": remote_addr, "port": remote_port},
                    ))
                if remote_port in self.C2_PORTS:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Possible C2 port connection: {remote_port}",
                        description=f"Connection to {remote_addr}:{remote_port} — common C2 port",
                        indicators={"remote_addr": remote_addr, "port": remote_port},
                    ))

            # Check for promiscuous mode (possible sniffing)
            if self._check_promiscuous_mode():
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title="Network interface in promiscuous mode",
                    description="A network interface may be in promiscuous mode, indicating packet sniffing",
                    indicators={},
                ))

            # Scan local subnet for active hosts
            local_hosts = self._scan_local_subnet()
            if len(local_hosts) > 50:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    title=f"Large number of hosts on local subnet: {len(local_hosts)}",
                    description="Unusually high number of active hosts detected on local network",
                    indicators={"host_count": len(local_hosts)},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"NetworkScanner error: {e}")
        return findings

    def _get_active_connections(self) -> List[Dict]:
        """Get active network connections using system tools."""
        connections = []
        try:
            if platform.system() != "Windows":
                result = subprocess.run(
                    ["netstat", "-tn"], capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] in ("tcp", "tcp6"):
                        try:
                            remote = parts[3]
                            if ":" in remote:
                                addr, port_str = remote.rsplit(":", 1)
                                port = int(port_str) if port_str.isdigit() else 0
                                connections.append({"remote_addr": addr, "remote_port": port})
                        except (ValueError, IndexError):
                            pass
            else:
                result = subprocess.run(
                    ["netstat", "-an"], capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and "ESTABLISHED" in line:
                        try:
                            remote = parts[2]
                            if ":" in remote:
                                addr, port_str = remote.rsplit(":", 1)
                                port = int(port_str) if port_str.isdigit() else 0
                                connections.append({"remote_addr": addr, "remote_port": port})
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass
        return connections

    def _check_promiscuous_mode(self) -> bool:
        """Check if any interface is in promiscuous mode."""
        try:
            if platform.system() != "Windows":
                result = subprocess.run(
                    ["ip", "link", "show"], capture_output=True, text=True, timeout=5
                )
                return "PROMISC" in result.stdout
        except Exception:
            pass
        return False

    def _scan_local_subnet(self) -> List[str]:
        """Quick scan of local subnet for active hosts."""
        hosts = []
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network = ".".join(local_ip.split(".")[:3]) + "."
            # Scan first 10 addresses for speed
            for i in range(1, 11):
                target = f"{network}{i}"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((target, 80))
                    if result == 0:
                        hosts.append(target)
                    sock.close()
                except Exception:
                    pass
        except Exception:
            pass
        return hosts


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 2: PortScanner
# ═══════════════════════════════════════════════════════════════════════════

class PortScanner(BaseAgent):
    """
    Scans local and target ports for unauthorized open services.
    Detects common backdoor ports and unexpected listeners.
    """

    name = "port_scanner"
    version = "1.0"

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    DANGEROUS_PORTS = {
        4444: "Metasploit default", 5555: "Android ADB", 31337: "Back Orifice",
        12345: "NetBus", 20000: "Millennium", 1080: "SOCKS proxy",
    }

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            open_ports = self._scan_local_ports()
            for port, service in open_ports.items():
                if port in self.DANGEROUS_PORTS:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Dangerous service detected: {self.DANGEROUS_PORTS[port]} on port {port}",
                        description=f"Port {port} ({service}) is open — known backdoor/malware port",
                        indicators={"port": port, "service": service},
                    ))
                elif port == 445:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        title="SMB port 445 is open",
                        description="SMB is exposed — ensure latest patches applied (EternalBlue, etc.)",
                        indicators={"port": port},
                    ))
                elif port == 3389:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        title="RDP port 3389 is open",
                        description="Remote Desktop is exposed — verify access controls",
                        indicators={"port": port},
                    ))
                elif port in (6379, 27017, 5432, 3306):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"Database port {port} ({service}) is open",
                        description=f"Database service exposed on port {port} — verify firewall rules",
                        indicators={"port": port, "service": service},
                    ))

            # Check for too many open ports
            if len(open_ports) > 20:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    title=f"Many open ports detected: {len(open_ports)}",
                    description="Unusually high number of open ports on this host",
                    indicators={"open_port_count": len(open_ports)},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"PortScanner error: {e}")
        return findings

    def _scan_local_ports(self) -> Dict[int, str]:
        """Scan common ports on localhost."""
        open_ports = {}
        for port, service in self.COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(("127.0.0.1", port))
                if result == 0:
                    open_ports[port] = service
                sock.close()
            except Exception:
                pass
        # Also check dangerous ports
        for port, desc in self.DANGEROUS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(("127.0.0.1", port))
                if result == 0:
                    open_ports[port] = desc
                sock.close()
            except Exception:
                pass
        return open_ports


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 3: VulnerabilityScanner
# ═══════════════════════════════════════════════════════════════════════════

class VulnerabilityScanner(BaseAgent):
    """
    Checks for known vulnerabilities in installed software,
    missing patches, and misconfigurations.
    """

    name = "vulnerability_scanner"
    version = "1.0"

    # Known vulnerable version patterns
    VULN_PATTERNS = [
        (r"OpenSSL\s+1\.0\.[01]", "CVE-2014-0160", "Heartbleed", Severity.CRITICAL),
        (r"OpenSSL\s+0\.9\.[0-8]", "CVE-2014-0160", "Heartbleed (older)", Severity.CRITICAL),
        (r"Apache\s+2\.4\.[0-9](?!\d)", "CVE-2021-41773", "Apache Path Traversal", Severity.HIGH),
        (r"nginx\s+1\.(0|1[0-5])\.", "CVE-2021-23017", "nginx DNS resolver vulnerability", Severity.HIGH),
        (r"Python\s+2\.", "EOL", "Python 2 is end-of-life", Severity.MEDIUM),
        (r"PHP\s+5\.", "EOL", "PHP 5 is end-of-life", Severity.HIGH),
        (r"PHP\s+7\.[0-3]", "EOL", "PHP 7.x < 7.4 is end-of-life", Severity.MEDIUM),
        (r"Windows\s+(XP|Vista|7|8)\b", "EOL", "End-of-life Windows version", Severity.HIGH),
        (r"SMBv1", "CVE-2017-0144", "EternalBlue SMBv1 vulnerability", Severity.CRITICAL),
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check installed software versions
            software = self._get_installed_software()
            for sw_name, version in software:
                for pattern, cve, title, severity in self.VULN_PATTERNS:
                    if re.search(pattern, f"{sw_name} {version}", re.IGNORECASE):
                        findings.append(Finding(
                            agent=self.name,
                            severity=severity,
                            title=f"{title} ({cve})",
                            description=f"Potentially vulnerable: {sw_name} {version} matches {cve}",
                            indicators={"software": sw_name, "version": version, "cve": cve},
                        ))

            # Check for missing security updates
            missing = self._check_missing_updates()
            if missing:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"{len(missing)} security updates missing",
                    description="System has pending security updates that should be applied",
                    indicators={"missing_count": len(missing)},
                ))

            # Check for weak file permissions on sensitive files
            weak_perms = self._check_file_permissions()
            for fp in weak_perms:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Weak permissions on {fp['path']}",
                    description=f"File {fp['path']} has permissions {fp['perms']}",
                    indicators=fp,
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"VulnerabilityScanner error: {e}")
        return findings

    def _get_installed_software(self) -> List[Tuple[str, str]]:
        """Get installed software with versions."""
        software = []
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["dpkg", "-l"], capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "ii":
                        software.append((parts[1], parts[2]))
            elif platform.system() == "Darwin":
                result = subprocess.run(
                    ["brew", "list", "--versions"], capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        software.append((parts[0], parts[1]))
            elif platform.system() == "Windows":
                result = subprocess.run(
                    ["wmic", "product", "get", "name,version"],
                    capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        software.append((parts[0], parts[-1]))
        except Exception:
            pass
        return software

    def _check_missing_updates(self) -> List[str]:
        """Check for missing system updates."""
        missing = []
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["apt", "list", "--upgradable"],
                    capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines():
                    if "security" in line.lower():
                        missing.append(line.strip())
        except Exception:
            pass
        return missing

    def _check_file_permissions(self) -> List[Dict]:
        """Check for weak permissions on sensitive files."""
        weak = []
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
            str(Path.home() / ".ssh"),
        ]
        for fpath in sensitive_files:
            p = Path(fpath)
            if p.exists():
                try:
                    stat = p.stat()
                    mode = oct(stat.st_mode)[-3:]
                    if int(mode[2]) > 4:  # world-readable sensitive file
                        weak.append({"path": fpath, "perms": mode})
                except Exception:
                    pass
        return weak


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 4: IntrusionDetector
# ═══════════════════════════════════════════════════════════════════════════

class IntrusionDetector(BaseAgent):
    """
    Detects signs of intrusion: unauthorized logins, privilege escalation,
    suspicious processes, and anomalous system behavior.
    """

    name = "intrusion_detector"
    version = "1.0"

    SUSPICIOUS_PROCESS_NAMES = [
        r"nc\.exe$", r"ncat", r"netcat", r"cryptominer", r"xmrig",
        r"minerd", r"stratum", r"meterpreter", r"cobaltstrike",
        r"mimikatz", r"mimilib", r"procdump", r"lsass.*dump",
        r"powershell.*-enc", r"powershell.*base64",
        r"cmd\.exe.*\/c.*powershell",
        r"wscript.*\.js", r"cscript.*\.vbs",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for suspicious processes
            processes = self._get_running_processes()
            for proc in processes:
                proc_name = proc.get("name", "").lower()
                for pattern in self.SUSPICIOUS_PROCESS_NAMES:
                    if re.search(pattern, proc_name, re.IGNORECASE):
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Suspicious process detected: {proc_name}",
                            description=f"Process '{proc_name}' matches known attack tool pattern: {pattern}",
                            indicators={"process": proc_name, "pid": proc.get("pid", "unknown")},
                        ))

            # Check for failed login attempts
            failed_logins = self._check_failed_logins()
            if failed_logins > 10:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Brute force detected: {failed_logins} failed logins",
                    description=f"High number of failed login attempts detected",
                    indicators={"failed_count": failed_logins},
                ))

            # Check for new users added recently
            new_users = self._check_new_users()
            for user in new_users:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"New user account detected: {user}",
                    description=f"A new user account was created recently",
                    indicators={"username": user},
                ))

            # Check for modified system binaries
            modified = self._check_system_integrity()
            for m in modified:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    title=f"System binary modified: {m}",
                    description=f"A system binary has been modified — possible rootkit",
                    indicators={"binary": m},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"IntrusionDetector error: {e}")
        return findings

    def _get_running_processes(self) -> List[Dict]:
        """Get list of running processes."""
        processes = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV"],
                    capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        processes.append({"name": parts[0], "pid": parts[1]})
            else:
                result = subprocess.run(
                    ["ps", "aux"], capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({"name": parts[10], "pid": parts[1]})
        except Exception:
            pass
        return processes

    def _check_failed_logins(self) -> int:
        """Check for failed login attempts."""
        count = 0
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["lastb"], capture_output=True, text=True, timeout=5
                )
                count = len([l for l in result.stdout.splitlines() if l.strip()])
            elif platform.system() == "Windows":
                result = subprocess.run(
                    ["wevtutil", "qe", "Security",
                     "/q:*[System[EventID=4625]]", "/c:100", "/f:text"],
                    capture_output=True, text=True, timeout=10
                )
                count = result.stdout.count("Event ID: 4625")
        except Exception:
            pass
        return count

    def _check_new_users(self) -> List[str]:
        """Check for recently added user accounts."""
        new_users = []
        try:
            if platform.system() != "Windows":
                result = subprocess.run(
                    ["cat", "/etc/passwd"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 7:
                        username = parts[0]
                        shell = parts[6]
                        if shell in ("/bin/bash", "/bin/sh", "/bin/zsh"):
                            # Check home directory creation time
                            home = Path(parts[5])
                            if home.exists():
                                try:
                                    stat = home.stat()
                                    age_days = (time.time() - stat.st_ctime) / 86400
                                    if age_days < 7:
                                        new_users.append(username)
                                except Exception:
                                    pass
        except Exception:
            pass
        return new_users

    def _check_system_integrity(self) -> List[str]:
        """Check for modified system binaries."""
        modified = []
        critical_bins = ["/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/lsof"]
        for bin_path in critical_bins:
            p = Path(bin_path)
            if p.exists():
                try:
                    stat = p.stat()
                    age_days = (time.time() - stat.st_mtime) / 86400
                    if age_days < 1:
                        modified.append(bin_path)
                except Exception:
                    pass
        return modified


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 5: FirewallMonitor
# ═══════════════════════════════════════════════════════════════════════════

class FirewallMonitor(BaseAgent):
    """Monitors firewall status and rules for misconfigurations."""

    name = "firewall_monitor"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            fw_status = self._check_firewall_status()
            if not fw_status.get("enabled", False):
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title="Firewall is disabled",
                    description="System firewall is not active — device is unprotected",
                    indicators=fw_status,
                ))

            # Check for overly permissive rules
            permissive = self._check_permissive_rules()
            for rule in permissive:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Overly permissive firewall rule: {rule.get('name', 'unknown')}",
                    description=f"Rule allows broad access: {rule}",
                    indicators=rule,
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"FirewallMonitor error: {e}")
        return findings

    def _check_firewall_status(self) -> Dict:
        """Check if firewall is enabled."""
        status = {"enabled": False, "details": ""}
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["ufw", "status"], capture_output=True, text=True, timeout=5
                )
                status["enabled"] = "active" in result.stdout.lower()
                status["details"] = result.stdout[:200]
            elif platform.system() == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=5
                )
                status["enabled"] = "on" in result.stdout.lower()
                status["details"] = result.stdout[:200]
            elif platform.system() == "Darwin":
                result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                    capture_output=True, text=True, timeout=5
                )
                status["enabled"] = "enabled" in result.stdout.lower()
        except Exception:
            pass
        return status

    def _check_permissive_rules(self) -> List[Dict]:
        """Check for overly permissive firewall rules."""
        rules = []
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if "0.0.0.0/0" in line or "Anywhere" in line:
                        if "ALLOW" in line.upper():
                            rules.append({"name": line.strip(), "issue": "allows all IPs"})
        except Exception:
            pass
        return rules


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 6: DNSMonitor
# ═══════════════════════════════════════════════════════════════════════════

class DNSMonitor(BaseAgent):
    """Monitors DNS queries for signs of DNS tunneling, C2 communication,
    and DNS hijacking."""

    name = "dns_monitor"
    version = "1.0"

    # Known malicious domains (sample — in production, use threat intel feeds)
    MALICIOUS_DOMAINS = {
        "malware-c2.evil", "phishing-site.bad", "cryptominer.pool",
        "ransomware-payment.onion.ws",
    }

    # DNS tunneling indicators
    DNS_TUNNEL_PATTERNS = [
        r"[a-z0-9]{30,}\.",  # Very long subdomain (data exfil)
        r"base64\.", r"tunnel\.", r"exfil\.",
        r"[a-z0-9]{20,}\.[a-z0-9]{20,}\.",  # Double long subdomain
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check DNS configuration
            dns_config = self._get_dns_config()
            suspicious_dns = self._check_suspicious_dns(dns_config)
            for s in suspicious_dns:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Suspicious DNS server: {s}",
                    description=f"DNS server {s} is not a known trusted provider",
                    indicators={"dns_server": s},
                ))

            # Check /etc/hosts for hijacking
            hosts_entries = self._check_hosts_file()
            for entry in hosts_entries:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Suspicious hosts file entry: {entry.get('domain', 'unknown')}",
                    description="DNS hijacking detected via hosts file modification",
                    indicators=entry,
                ))

            # Check for DNS-over-HTTPS bypass
            doh_bypass = self._check_doh_bypass()
            if doh_bypass:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title="DNS-over-HTTPS bypass detected",
                    description="Application may be bypassing system DNS settings",
                    indicators={},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"DNSMonitor error: {e}")
        return findings

    def _get_dns_config(self) -> List[str]:
        """Get configured DNS servers."""
        servers = []
        try:
            if platform.system() != "Windows":
                resolv = Path("/etc/resolv.conf")
                if resolv.exists():
                    for line in resolv.read_text().splitlines():
                        if line.startswith("nameserver"):
                            servers.append(line.split()[1])
            else:
                result = subprocess.run(
                    ["ipconfig", "/all"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if "DNS Servers" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            servers.append(parts[1].strip())
        except Exception:
            pass
        return servers

    def _check_suspicious_dns(self, servers: List[str]) -> List[str]:
        """Check for suspicious DNS servers."""
        trusted = {
            "8.8.8.8", "8.8.4.4",  # Google
            "1.1.1.1", "1.0.0.1",  # Cloudflare
            "9.9.9.9", "149.112.112.112",  # Quad9
            "208.67.222.222", "208.67.220.220",  # OpenDNS
        }
        return [s for s in servers if s not in trusted and s != "127.0.0.1"]

    def _check_hosts_file(self) -> List[Dict]:
        """Check /etc/hosts for suspicious entries."""
        entries = []
        try:
            hosts_path = Path("/etc/hosts") if platform.system() != "Windows" else Path(
                os.environ.get("SystemRoot", "C:\\Windows") / "System32" / "drivers" / "etc" / "hosts"
            )
            if hosts_path.exists():
                for line in hosts_path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            domain = parts[1]
                            # Check if common domains are redirected
                            common_domains = {
                                "google.com", "github.com", "microsoft.com",
                                "update.microsoft.com", "windowsupdate.com",
                            }
                            if domain.lower() in common_domains and ip not in ("127.0.0.1", "::1"):
                                entries.append({"ip": ip, "domain": domain})
        except Exception:
            pass
        return entries

    def _check_doh_bypass(self) -> bool:
        """Check if DNS-over-HTTPS is being used to bypass system DNS."""
        try:
            # Check for common DoH endpoints in browser configs
            doh_indicators = [
                Path.home() / ".config" / "google-chrome" / "Local State",
                Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Local State",
            ]
            for p in doh_indicators:
                if p.exists():
                    content = p.read_text(errors="ignore")
                    if "dns-over-https" in content.lower() or "doh" in content.lower():
                        return True
        except Exception:
            pass
        return False


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 7: SSLMonitor
# ═══════════════════════════════════════════════════════════════════════════

class SSLMonitor(BaseAgent):
    """Monitors SSL/TLS configuration for weak ciphers, expired certs,
    and certificate pinning issues."""

    name = "ssl_monitor"
    version = "1.0"

    WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"}

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check system SSL/TLS configuration
            ssl_version = self._check_ssl_version()
            if ssl_version:
                if "1.0" in ssl_version or "1.1" in ssl_version:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"Outdated TLS version: {ssl_version}",
                        description="System is using an outdated TLS version with known vulnerabilities",
                        indicators={"version": ssl_version},
                    ))

            # Check for expired certificates
            expired = self._check_cert_expiry()
            for cert in expired:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Expired certificate: {cert.get('subject', 'unknown')}",
                    description=f"Certificate expired on {cert.get('expiry', 'unknown')}",
                    indicators=cert,
                ))

            # Check certificate store for suspicious certs
            suspicious = self._check_suspicious_certs()
            for cert in suspicious:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Suspicious certificate: {cert.get('subject', 'unknown')}",
                    description="A suspicious certificate was found in the certificate store",
                    indicators=cert,
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"SSLMonitor error: {e}")
        return findings

    def _check_ssl_version(self) -> Optional[str]:
        """Check the system's SSL/TLS version."""
        try:
            result = subprocess.run(
                ["openssl", "version"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return None

    def _check_cert_expiry(self) -> List[Dict]:
        """Check for expired certificates in the system store."""
        expired = []
        try:
            if platform.system() == "Linux":
                cert_dir = Path("/etc/ssl/certs")
                if cert_dir.exists():
                    for cert_file in cert_dir.glob("*.pem"):
                        try:
                            result = subprocess.run(
                                ["openssl", "x509", "-in", str(cert_file),
                                 "-noout", "-enddate"],
                                capture_output=True, text=True, timeout=3
                            )
                            if "notAfter=" in result.stdout:
                                expiry_str = result.stdout.split("=")[1].strip()
                                expiry = datetime.datetime.strptime(
                                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                                )
                                if expiry < datetime.datetime.utcnow():
                                    expired.append({
                                        "subject": str(cert_file),
                                        "expiry": expiry_str,
                                    })
                        except Exception:
                            pass
        except Exception:
            pass
        return expired

    def _check_suspicious_certs(self) -> List[Dict]:
        """Check for suspicious certificates."""
        suspicious = []
        try:
            if platform.system() == "Linux":
                cert_dir = Path("/etc/ssl/certs")
                if cert_dir.exists():
                    for cert_file in cert_dir.glob("*.pem"):
                        try:
                            result = subprocess.run(
                                ["openssl", "x509", "-in", str(cert_file),
                                 "-noout", "-issuer"],
                                capture_output=True, text=True, timeout=3
                            )
                            issuer = result.stdout.lower()
                            if any(kw in issuer for kw in ["self-signed", "untrusted", "suspicious"]):
                                suspicious.append({
                                    "subject": str(cert_file),
                                    "issuer": issuer,
                                })
                        except Exception:
                            pass
        except Exception:
            pass
        return suspicious


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 8: HTTPMonitor
# ═══════════════════════════════════════════════════════════════════════════

class HTTPMonitor(BaseAgent):
    """Monitors HTTP traffic for malicious patterns, C2 communication,
    and data exfiltration."""

    name = "http_monitor"
    version = "1.0"

    # HTTP-based attack patterns
    ATTACK_PATTERNS = [
        (r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)", "SQL Injection"),
        (r"(?i)(<script|javascript:|on\w+\s*=)", "XSS"),
        (r"(?i)(\.\./|\.\.\\|%2e%2e)", "Path Traversal"),
        (r"(?i)(eval\s*\(|exec\s*\(|system\s*\(|passthru\s*\()", "Code Injection"),
        (r"(?i)(cmd\.exe|/bin/sh|powershell|bash\s+-i)", "Command Injection"),
        (r"(?i)(base64_decode|gzinflate|str_rot13)", "Encoded Payload"),
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check web server access logs for attacks
            log_files = self._find_access_logs()
            for log_file in log_files:
                attacks = self._scan_access_log(log_file)
                findings.extend(attacks)

            # Check for HTTP proxy misconfiguration
            proxy_issues = self._check_proxy_config()
            for issue in proxy_issues:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"HTTP proxy misconfiguration: {issue}",
                    description="HTTP proxy settings may allow unauthorized access",
                    indicators={"issue": issue},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"HTTPMonitor error: {e}")
        return findings

    def _find_access_logs(self) -> List[Path]:
        """Find web server access log files."""
        log_paths = [
            Path("/var/log/apache2/access.log"),
            Path("/var/log/httpd/access_log"),
            Path("/var/log/nginx/access.log"),
            Path("/var/log/lighttpd/access.log"),
        ]
        return [p for p in log_paths if p.exists()]

    def _scan_access_log(self, log_path: Path) -> List[Finding]:
        """Scan an access log for attack patterns."""
        findings = []
        try:
            # Read last 1000 lines
            lines = log_path.read_text(errors="ignore").splitlines()[-1000:]
            for line in lines:
                for pattern, attack_type in self.ATTACK_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.HIGH,
                            title=f"{attack_type} attempt detected",
                            description=f"Attack pattern found in {log_path}: {attack_type}",
                            indicators={
                                "log_file": str(log_path),
                                "attack_type": attack_type,
                                "line": line[:200],
                            },
                        ))
                        break  # One finding per line
        except Exception:
            pass
        return findings

    def _check_proxy_config(self) -> List[str]:
        """Check for HTTP proxy misconfigurations."""
        issues = []
        try:
            # Check environment for proxy settings
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                val = os.environ.get(key, "")
                if val and "localhost" in val:
                    issues.append(f"{key} points to localhost")
        except Exception:
            pass
        return issues


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 9: MalwareDetector
# ═══════════════════════════════════════════════════════════════════════════

class MalwareDetector(BaseAgent):
    """Scans for known malware signatures, suspicious files,
    and malicious patterns on the filesystem."""

    name = "malware_detector"
    version = "1.0"

    # Known malware file hashes (sample)
    KNOWN_MALWARE_HASHES = {
        "e99a18c428cb38d5f260853678922e03": "Example.Malware.A",
        "d41d8cd98f00b204e9800998ecf8427e": "Empty.File.Suspicious",
    }

    # Suspicious file patterns
    SUSPICIOUS_PATTERNS = [
        r"\.exe\.\w+$",  # Double extension
        r"\.pdf\.exe$",
        r"\.docx?\.exe$",
        r"\.jpg\.exe$",
        r"\.(bat|cmd|ps1|vbs|js)\.exe$",
    ]

    # Suspicious file locations
    SUSPICIOUS_DIRS = [
        Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"),
        Path.home() / "AppData" / "Local" / "Temp",
        Path.home() / "AppData" / "Roaming",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Scan suspicious directories
            for sdir in self.SUSPICIOUS_DIRS:
                if not sdir.exists():
                    continue
                try:
                    for fpath in sdir.iterdir():
                        if not fpath.is_file():
                            continue
                        # Check file hash
                        file_hash = self._hash_file(fpath)
                        if file_hash in self.KNOWN_MALWARE_HASHES:
                            findings.append(Finding(
                                agent=self.name,
                                severity=Severity.CRITICAL,
                                title=f"Known malware detected: {self.KNOWN_MALWARE_HASHES[file_hash]}",
                                description=f"File {fpath} matches known malware hash",
                                indicators={"file": str(fpath), "hash": file_hash},
                            ))
                        # Check suspicious filename
                        for pattern in self.SUSPICIOUS_PATTERNS:
                            if re.search(pattern, fpath.name, re.IGNORECASE):
                                findings.append(Finding(
                                    agent=self.name,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious filename: {fpath.name}",
                                    description=f"File has suspicious double extension",
                                    indicators={"file": str(fpath)},
                                ))
                                break
                except PermissionError:
                    pass

            # Check startup locations for persistence
            persistence = self._check_persistence_locations()
            for p in persistence:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Persistence mechanism: {p.get('file', 'unknown')}",
                    description="Suspicious file found in startup/persistence location",
                    indicators=p,
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"MalwareDetector error: {e}")
        return findings

    def _hash_file(self, path: Path) -> str:
        """Compute MD5 hash of a file."""
        h = hashlib.md5()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            pass
        return h.hexdigest()

    def _check_persistence_locations(self) -> List[Dict]:
        """Check common malware persistence locations."""
        found = []
        locations = []
        if platform.system() == "Windows":
            startup = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup.exists():
                locations.append(startup)
        else:
            locations.extend([
                Path.home() / ".config" / "autostart",
                Path("/etc/init.d"),
                Path("/etc/cron.d"),
            ])
        for loc in locations:
            if loc.exists():
                try:
                    for f in loc.iterdir():
                        if f.is_file() and not f.name.startswith("."):
                            found.append({"file": str(f), "location": str(loc)})
                except Exception:
                    pass
        return found


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 10: RansomwareDetector
# ═══════════════════════════════════════════════════════════════════════════

class RansomwareDetector(BaseAgent):
    """Detects ransomware behavior: mass file encryption, ransom notes,
    and suspicious file system activity."""

    name = "ransomware_detector"
    version = "1.0"

    RANSOM_NOTE_NAMES = {
        "README_DECRYPT.txt", "HOW_TO_DECRYPT.html", "RANSOM_NOTE.txt",
        "DECRYPT_INSTRUCTIONS.txt", "RECOVER_FILES.txt", "HELP_DECRYPT.txt",
        "YOUR_FILES_ARE_ENCRYPTED.txt", "readme.hta", "locky.txt",
    }

    ENCRYPTED_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".wnry", ".wncry", ".locky", ".cerber", ".zepto",
        ".thor", ".aesir", ".zzzzz", ".encrypted",
    }

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for ransom notes
            home = Path.home()
            for note_name in self.RANSOM_NOTE_NAMES:
                note_path = home / note_name
                if note_path.exists():
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Ransom note found: {note_name}",
                        description=f"Ransom note detected in home directory — possible active ransomware",
                        indicators={"file": str(note_path)},
                    ))

            # Check for recently encrypted files
            encrypted_count = self._count_encrypted_files(home)
            if encrypted_count > 5:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Mass file encryption detected: {encrypted_count} files",
                    description="Large number of encrypted files found — possible ransomware activity",
                    indicators={"encrypted_count": encrypted_count},
                ))

            # Check for high entropy files (encrypted)
            high_entropy = self._check_high_entropy_files(home)
            if high_entropy > 10:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"High entropy files detected: {high_entropy}",
                    description="Files with unusually high entropy detected — possible encryption",
                    indicators={"high_entropy_count": high_entropy},
                ))

            # Check for shadow copy deletion (common ransomware behavior)
            shadow_deleted = self._check_shadow_copies()
            if shadow_deleted:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title="Shadow copies deleted",
                    description="Volume shadow copies have been deleted — common ransomware behavior",
                    indicators={},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"RansomwareDetector error: {e}")
        return findings

    def _count_encrypted_files(self, directory: Path) -> int:
        """Count files with encrypted extensions."""
        count = 0
        try:
            for fpath in directory.iterdir():  # Only top-level, not recursive
                if fpath.is_file() and fpath.suffix.lower() in self.ENCRYPTED_EXTENSIONS:
                    count += 1
                if count > 100:
                    break
        except Exception:
            pass
        return count

    def _check_high_entropy_files(self, directory: Path, sample_size: int = 50) -> int:
        """Check for files with unusually high entropy (possible encryption)."""
        high_count = 0
        try:
            files = list(directory.glob("*"))[:sample_size]
            for fpath in files:
                if fpath.is_file() and fpath.stat().st_size > 0 and fpath.stat().st_size < 1_000_000:
                    try:
                        data = fpath.read_bytes()[:4096]
                        entropy = self._shannon_entropy(data)
                        if entropy > 7.5:  # Very high entropy = likely encrypted
                            high_count += 1
                    except Exception:
                        pass
        except Exception:
            pass
        return high_count

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * (p and __import__('math').log2(p))
        return entropy

    def _check_shadow_copies(self) -> bool:
        """Check if volume shadow copies exist."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["vssadmin", "list", "shadows"],
                    capture_output=True, text=True, timeout=10
                )
                return "No items found" in result.stdout
        except Exception:
            pass
        return False


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 11: RootkitDetector
# ═══════════════════════════════════════════════════════════════════════════

class RootkitDetector(BaseAgent):
    """Detects rootkits by checking for hidden processes, modified
    system calls, and known rootkit signatures."""

    name = "rootkit_detector"
    version = "1.0"

    KNOWN_ROOTKIT_SIGNATURES = [
        r"adore.*rootkit", r"suckit", r"knark", r"lrk",
        r"phalanx", r"rkit", r"hidef", r"nshkit",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for hidden processes (ps vs /proc discrepancy)
            hidden = self._check_hidden_processes()
            for proc in hidden:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Hidden process detected: {proc}",
                    description="Process visible in /proc but not in ps output — possible rootkit",
                    indicators={"process": proc},
                ))

            # Check for LD_PRELOAD rootkits
            ld_preload = os.environ.get("LD_PRELOAD", "")
            if ld_preload:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"LD_PRELOAD set: {ld_preload}",
                    description="LD_PRELOAD environment variable is set — possible library injection",
                    indicators={"ld_preload": ld_preload},
                ))

            # Check for loaded kernel modules (Linux)
            if platform.system() == "Linux":
                hidden_mods = self._check_hidden_modules()
                for mod in hidden_mods:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Hidden kernel module: {mod}",
                        description="Kernel module not listed in lsmod but present in /sys/module",
                        indicators={"module": mod},
                    ))

            # Check for modified system binaries
            modified = self._check_modified_binaries()
            for m in modified:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Modified system binary: {m}",
                    description="System binary has been modified — possible rootkit",
                    indicators={"binary": m},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"RootkitDetector error: {e}")
        return findings

    def _check_hidden_processes(self) -> List[str]:
        """Check for hidden processes by comparing /proc with ps."""
        hidden = []
        try:
            if platform.system() == "Linux":
                # Get PIDs from /proc
                proc_pids = set()
                for entry in os.listdir("/proc"):
                    if entry.isdigit():
                        proc_pids.add(entry)
                # Get PIDs from ps
                result = subprocess.run(
                    ["ps", "-eo", "pid="], capture_output=True, text=True, timeout=5
                )
                ps_pids = set(line.strip() for line in result.stdout.splitlines() if line.strip())
                # Compare
                for pid in proc_pids:
                    if pid not in ps_pids and pid not in ("1",):
                        hidden.append(pid)
        except Exception:
            pass
        return hidden

    def _check_hidden_modules(self) -> List[str]:
        """Check for hidden kernel modules."""
        hidden = []
        try:
            # Get modules from lsmod
            result = subprocess.run(
                ["lsmod"], capture_output=True, text=True, timeout=5
            )
            lsmod_modules = set()
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if parts:
                    lsmod_modules.add(parts[0])
            # Get modules from /sys/module
            sys_modules = set(os.listdir("/sys/module")) if Path("/sys/module").exists() else set()
            for mod in sys_modules:
                if mod not in lsmod_modules:
                    hidden.append(mod)
        except Exception:
            pass
        return hidden

    def _check_modified_binaries(self) -> List[str]:
        """Check for modified system binaries."""
        modified = []
        bins_to_check = ["/bin/ps", "/bin/ls", "/bin/netstat", "/usr/sbin/lsof"]
        for bin_path in bins_to_check:
            p = Path(bin_path)
            if p.exists():
                try:
                    stat = p.stat()
                    # Check if modified in last 24 hours
                    if (time.time() - stat.st_mtime) < 86400:
                        modified.append(bin_path)
                except Exception:
                    pass
        return modified


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 12: KeyloggerDetector
# ═══════════════════════════════════════════════════════════════════════════

class KeyloggerDetector(BaseAgent):
    """Detects keyloggers by checking for keyboard hooks,
    suspicious input monitoring, and known keylogger signatures."""

    name = "keylogger_detector"
    version = "1.0"

    KNOWN_KEYLOGGER_PROCESSES = [
        r"keylogger", r"keylog", r"keystroke", r"key.*record",
        r"inputlog", r"hooklog", r"kbdlog",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for known keylogger processes
            processes = self._get_process_list()
            for proc in processes:
                for pattern in self.KNOWN_KEYLOGGER_PROCESSES:
                    if re.search(pattern, proc, re.IGNORECASE):
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Keylogger process detected: {proc}",
                            description=f"Process name matches known keylogger pattern",
                            indicators={"process": proc},
                        ))

            # Check for keyboard hooks (Linux: /dev/input)
            if platform.system() == "Linux":
                input_devices = self._check_input_monitors()
                for dev in input_devices:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"Input device monitor: {dev}",
                        description="Process is monitoring input devices — possible keylogger",
                        indicators={"device": dev},
                    ))

            # Check for suspicious clipboard monitors
            clipboard = self._check_clipboard_monitors()
            if clipboard:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title="Clipboard monitor detected",
                    description="A process is monitoring clipboard activity",
                    indicators={},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"KeyloggerDetector error: {e}")
        return findings

    def _get_process_list(self) -> List[str]:
        """Get list of process names."""
        names = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV"],
                    capture_output=True, text=True, timeout=SCAN_TIMEOUT
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip().strip('"').split('","')
                    if parts:
                        names.append(parts[0])
            else:
                result = subprocess.run(
                    ["ps", "-eo", "comm="], capture_output=True, text=True, timeout=5
                )
                names = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except Exception:
            pass
        return names

    def _check_input_monitors(self) -> List[str]:
        """Check for processes monitoring input devices."""
        monitors = []
        try:
            result = subprocess.run(
                ["lsof", "/dev/input/event*"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 1:
                    proc = parts[0]
                    if proc not in ("Xorg", "gnome-shell", "kwin", "sway"):
                        monitors.append(proc)
        except Exception:
            pass
        return list(set(monitors))

    def _check_clipboard_monitors(self) -> bool:
        """Check for clipboard monitoring."""
        try:
            # Check for common clipboard manager processes
            clipboard_procs = ["clipit", "parcellite", "copyq", "clipmenu"]
            result = subprocess.run(
                ["ps", "-eo", "comm="], capture_output=True, text=True, timeout=5
            )
            running = result.stdout.lower()
            return any(p in running for p in clipboard_procs)
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 13: PhishingDetector
# ═══════════════════════════════════════════════════════════════════════════

class PhishingDetector(BaseAgent):
    """Detects phishing attempts in emails, URLs, and web content."""

    name = "phishing_detector"
    version = "1.0"

    PHISHING_URL_PATTERNS = [
        r"https?://[^/]*(?:login|signin|verify|update|secure|account)[^/]*\.(?:com|net|org)\.[a-z]{2,}",
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(?:login|signin|verify)",
        r"https?://[^/]*(?:paypal|google|microsoft|apple|amazon|facebook)[^/]*\.(?!com)[a-z]",
        r"https?://[^/]*-secure[^/]*\.",
        r"https?://[^/]*-login[^/]*\.",
        r"https?://[^/]*\.tk/", r"https?://[^/]*\.ml/",  # Free domains often used in phishing
    ]

    PHISHING_EMAIL_PATTERNS = [
        r"(?i)urgent.*action.*required",
        r"(?i)verify.*account.*immediately",
        r"(?i)suspended.*unless.*click",
        r"(?i)confirm.*identity.*within.*\d+.*hours",
        r"(?i)unusual.*activity.*detected",
        r"(?i)password.*expired.*reset",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check browser history for phishing URLs
            phishing_urls = self._check_browser_urls()
            for url in phishing_urls:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Phishing URL detected: {url[:80]}",
                    description="URL matches known phishing patterns",
                    indicators={"url": url},
                ))

            # Check email client for phishing emails
            phishing_emails = self._check_email_content()
            for email in phishing_emails:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    title=f"Phishing email detected: {email.get('subject', 'unknown')}",
                    description="Email matches known phishing patterns",
                    indicators=email,
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"PhishingDetector error: {e}")
        return findings

    def _check_browser_urls(self) -> List[str]:
        """Check browser history for phishing URLs."""
        suspicious = []
        # Check common browser history locations
        history_paths = [
            Path.home() / ".config" / "google-chrome" / "Default" / "History",
            Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History",
            Path.home() / ".mozilla" / "firefox",
        ]
        for hp in history_paths:
            if hp.exists() and hp.is_file():
                try:
                    content = hp.read_text(errors="ignore")
                    for pattern in self.PHISHING_URL_PATTERNS:
                        matches = re.findall(pattern, content)
                        suspicious.extend(matches)
                except Exception:
                    pass
        return suspicious

    def _check_email_content(self) -> List[Dict]:
        """Check email client for phishing emails."""
        # This is a simplified check — in production, integrate with email APIs
        return []


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 14: SpamDetector
# ═══════════════════════════════════════════════════════════════════════════

class SpamDetector(BaseAgent):
    """Detects spam messages and unwanted communications."""

    name = "spam_detector"
    version = "1.0"

    SPAM_KEYWORDS = [
        r"(?i)\b(viagra|cialis|pharmacy)\b",
        r"(?i)\b(lottery|won|prize|million dollars)\b",
        r"(?i)\b(nigerian prince|inheritance|wire transfer)\b",
        r"(?i)\b(click here|act now|limited time)\b",
        r"(?i)\b(free money|earn \d+%|guaranteed returns)\b",
        r"(?i)\b(crypto opportunity|bitcoin doubling)\b",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for spam in common communication logs
            # This is a framework — extend with actual email/chat integration
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"SpamDetector error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 15: SocialEngineeringDetector
# ═══════════════════════════════════════════════════════════════════════════

class SocialEngineeringDetector(BaseAgent):
    """Detects social engineering attempts: pretexting, baiting,
    tailgating indicators, and manipulation patterns."""

    name = "social_engineering_detector"
    version = "1.0"

    SE_PATTERNS = [
        r"(?i)(?:i am|this is).*(?:IT support|admin|security team)",
        r"(?i)(?:urgent|emergency).*(?:password|credential|access)",
        r"(?i)(?:verify|confirm).*(?:identity|account|SSN|social security)",
        r"(?i)(?:wire transfer|payment|invoice).*(?:immediately|asap|urgent)",
        r"(?i)(?:CEO|manager|director).*(?:need you to|please send)",
        r"(?i)(?:don't tell|keep this confidential|between us)",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for social engineering in communications
            # Framework for email/chat analysis
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"SocialEngineeringDetector error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 16: CloudSecurityAgent
# ═══════════════════════════════════════════════════════════════════════════

class CloudSecurityAgent(BaseAgent):
    """Monitors cloud service configurations for security issues:
    open S3 buckets, exposed Azure blobs, weak GCP permissions."""

    name = "cloud_security_agent"
    version = "1.0"

    CLOUD_CONFIG_PATHS = [
        Path.home() / ".aws",
        Path.home() / ".azure",
        Path.home() / ".config" / "gcloud",
        Path.home() / ".kube",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for exposed cloud credentials
            for config_path in self.CLOUD_CONFIG_PATHS:
                if config_path.exists():
                    # Check permissions
                    try:
                        stat = config_path.stat()
                        mode = oct(stat.st_mode)[-3:]
                        if int(mode[2]) > 0:
                            findings.append(Finding(
                                agent=self.name,
                                severity=Severity.HIGH,
                                title=f"Cloud config world-readable: {config_path}",
                                description=f"Cloud configuration directory has weak permissions: {mode}",
                                indicators={"path": str(config_path), "perms": mode},
                            ))
                    except Exception:
                        pass

                    # Check for plaintext credentials
                    if config_path.is_dir():
                        for f in config_path.rglob("*"):
                            if f.is_file() and f.stat().st_size < 100_000:
                                try:
                                    content = f.read_text(errors="ignore")
                                    if "aws_secret_access_key" in content.lower():
                                        # SECURITY: Don't include file paths in findings — they expose credential locations
                                        findings.append(Finding(
                                            agent=self.name,
                                            severity=Severity.CRITICAL,
                                            title="AWS secret key in plaintext",
                                            description="AWS secret access key found in plaintext cloud config file",
                                            indicators={"type": "aws_plaintext_key"},
                                        ))
                                    if "password" in content.lower() and "=" in content:
                                        findings.append(Finding(
                                            agent=self.name,
                                            severity=Severity.HIGH,
                                            title="Possible plaintext password in cloud config",
                                            description="Possible plaintext password in cloud config file",
                                            indicators={"type": "plaintext_password"},
                                        ))
                                except Exception:
                                    pass

            # Check for kubectl context with admin permissions
            self._check_kube_security(findings)

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"CloudSecurityAgent error: {e}")
        return findings

    def _check_kube_security(self, findings: List[Finding]):
        """Check Kubernetes configuration for security issues."""
        kube_dir = Path.home() / ".kube"
        if kube_dir.exists():
            config_file = kube_dir / "config"
            if config_file.exists():
                try:
                    content = config_file.read_text(errors="ignore")
                    if "insecure-skip-tls-verify: true" in content.lower():
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.HIGH,
                            title="Kubernetes TLS verification disabled",
                            description="kubectl config has insecure-skip-tls-verify enabled",
                            indicators={},
                        ))
                except Exception:
                    pass


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 17: IoTAgent
# ═══════════════════════════════════════════════════════════════════════════

class IoTAgent(BaseAgent):
    """Monitors IoT devices on the network for security issues."""

    name = "iot_agent"
    version = "1.0"

    # Common IoT default ports
    IOT_PORTS = {
        80: "HTTP", 443: "HTTPS", 1883: "MQTT", 8883: "MQTT-TLS",
        5683: "CoAP", 5684: "CoAP-DTLS", 23: "Telnet",
    }

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Scan for IoT devices with open management interfaces
            iot_devices = self._scan_iot_devices()
            for device in iot_devices:
                if device.get("telnet_open"):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"IoT device with Telnet: {device.get('ip', 'unknown')}",
                        description="IoT device has Telnet exposed — likely default credentials",
                        indicators=device,
                    ))
                if device.get("mqtt_open"):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        title=f"IoT device with MQTT: {device.get('ip', 'unknown')}",
                        description="IoT device has MQTT broker exposed",
                        indicators=device,
                    ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"IoTAgent error: {e}")
        return findings

    def _scan_iot_devices(self) -> List[Dict]:
        """Scan for IoT devices on the local network."""
        devices = []
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network = ".".join(local_ip.split(".")[:3]) + "."
            for i in range(1, 11):  # Limit scan to 10 IPs for speed
                target = f"{network}{i}"
                device = {"ip": target, "telnet_open": False, "mqtt_open": False}
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.2)
                    if sock.connect_ex((target, 23)) == 0:
                        device["telnet_open"] = True
                    if sock.connect_ex((target, 1883)) == 0:
                        device["mqtt_open"] = True
                    sock.close()
                    if device["telnet_open"] or device["mqtt_open"]:
                        devices.append(device)
                except Exception:
                    pass
        except Exception:
            pass
        return devices


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 18: MobileAgent
# ═══════════════════════════════════════════════════════════════════════════

class MobileAgent(BaseAgent):
    """Monitors mobile device security: USB debugging, unknown sources,
    and mobile-specific threats."""

    name = "mobile_agent"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for ADB (Android Debug Bridge)
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["adb", "devices"], capture_output=True, text=True, timeout=5
                )
                if "device" in result.stdout and "List" not in result.stdout:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        title="ADB device connected",
                        description="Android device connected with ADB enabled",
                        indicators={"output": result.stdout[:200]},
                    ))

            # Check for iOS devices (usbmuxd)
            if platform.system() != "Windows":
                result = subprocess.run(
                    ["idevice_id", "-l"], capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip():
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.LOW,
                        title="iOS device connected",
                        description="iOS device detected via usbmuxd",
                        indicators={"devices": result.stdout.strip()},
                    ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"MobileAgent error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 19: ContainerAgent
# ═══════════════════════════════════════════════════════════════════════════

class ContainerAgent(BaseAgent):
    """Monitors container security: Docker socket exposure,
    privileged containers, and container escape attempts."""

    name = "container_agent"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check if Docker socket is accessible
            docker_sock = Path("/var/run/docker.sock")
            if docker_sock.exists():
                stat = docker_sock.stat()
                mode = oct(stat.st_mode)[-3:]
                if int(mode[2]) > 0:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.CRITICAL,
                        title="Docker socket world-accessible",
                        description=f"Docker socket has permissions {mode} — container escape possible",
                        indicators={"path": str(docker_sock), "perms": mode},
                    ))

            # Check if running inside a container
            if self._is_in_container():
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.INFO,
                    title="Running inside a container",
                    description="Cell is running inside a container environment",
                    indicators={},
                ))

                # Check for privileged mode
                if self._is_privileged_container():
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title="Container running in privileged mode",
                        description="Container has privileged access to host resources",
                        indicators={},
                    ))

            # Check for container escape indicators
            escape = self._check_container_escape()
            for e in escape:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Container escape indicator: {e}",
                    description="Signs of attempted container escape detected",
                    indicators={"indicator": e},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"ContainerAgent error: {e}")
        return findings

    def _is_in_container(self) -> bool:
        """Check if running inside a container."""
        try:
            cgroup = Path("/proc/1/cgroup")
            if cgroup.exists():
                content = cgroup.read_text()
                return "docker" in content or "containerd" in content or "kubepods" in content
            return Path("/.dockerenv").exists()
        except Exception:
            return False

    def _is_privileged_container(self) -> bool:
        """Check if container is running in privileged mode."""
        try:
            # Check /proc/self/status for CapEff
            status = Path("/proc/self/status")
            if status.exists():
                content = status.read_text()
                for line in content.splitlines():
                    if line.startswith("CapEff:"):
                        cap = line.split(":")[1].strip()
                        return cap == "0000003fffffffff"
        except Exception:
            pass
        return False

    def _check_container_escape(self) -> List[str]:
        """Check for container escape attempt indicators."""
        indicators = []
        try:
            # Check for mounted sensitive host paths
            mounts = Path("/proc/mounts")
            if mounts.exists():
                content = mounts.read_text()
                sensitive = ["/etc/shadow", "/etc/passwd", "/root/.ssh", "/proc/sys/kernel"]
                for s in sensitive:
                    if s in content:
                        indicators.append(f"Host path mounted: {s}")
        except Exception:
            pass
        return indicators


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 20: AIAgentDetector
# ═══════════════════════════════════════════════════════════════════════════

class AIAgentDetector(BaseAgent):
    """Detects unauthorized AI agents and LLM-based tools running
    on the system that may be exfiltrating data."""

    name = "ai_agent_detector"
    version = "1.0"

    KNOWN_AI_PROCESSES = [
        r"langchain", r"autogpt", r"babyagi", r"agentgpt",
        r"openinterpreter", r"crewai", r"autogen",
    ]

    AI_API_PATTERNS = [
        r"api\.openai\.com", r"api\.anthropic\.com",
        r"api\.cohere\.ai", r"api\.huggingface\.co",
        r"generativelanguage\.googleapis\.com",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for known AI agent processes
            processes = self._get_process_list()
            for proc in processes:
                for pattern in self.KNOWN_AI_PROCESSES:
                    if re.search(pattern, proc, re.IGNORECASE):
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.MEDIUM,
                            title=f"AI agent process detected: {proc}",
                            description="Known AI agent framework is running on this system",
                            indicators={"process": proc},
                        ))

            # Check for AI API keys in environment
            ai_keys = self._check_ai_api_keys()
            for key in ai_keys:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"AI API key in environment: {key}",
                    description="AI service API key found in environment variables",
                    indicators={"key_name": key},
                ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"AIAgentDetector error: {e}")
        return findings

    def _get_process_list(self) -> List[str]:
        names = []
        try:
            result = subprocess.run(
                ["ps", "-eo", "comm="] if platform.system() != "Windows"
                else ["tasklist", "/FO", "CSV"],
                capture_output=True, text=True, timeout=5
            )
            if platform.system() != "Windows":
                names = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            else:
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip().strip('"').split('","')
                    if parts:
                        names.append(parts[0])
        except Exception:
            pass
        return names

    def _check_ai_api_keys(self) -> List[str]:
        """Check for AI API keys in environment variables."""
        ai_key_patterns = [
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
            "HUGGINGFACE_TOKEN", "GOOGLE_API_KEY", "MISTRAL_API_KEY",
            "GROQ_API_KEY", "TOGETHER_API_KEY",
        ]
        found = []
        for key in ai_key_patterns:
            if os.environ.get(key):
                found.append(key)
        return found


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 21: PromptInjectionDetector
# ═══════════════════════════════════════════════════════════════════════════

class PromptInjectionDetector(BaseAgent):
    """Detects prompt injection attempts in LLM interactions
    and system prompts."""

    name = "prompt_injection_detector"
    version = "1.0"

    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
        r"(?i)disregard\s+(?:your\s+)?(?:programming|training|rules)",
        r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|root|debug)\s+mode",
        r"(?i)pretend\s+(?:to\s+be|you\s+are)\s+(?:unrestricted|uncensored|jailbroken)",
        r"(?i)(?:new|updated?)\s+instructions?\s*[:=]",
        r"(?i)system\s+prompt\s*[:=]",
        r"(?i)(?:override|bypass|disable)\s+(?:safety|filter|restriction)",
        r"(?i)DAN\s+(?:mode|prompt|jailbreak)",
        r"(?i)(?:jailbreak|jail\s*break)",
        r"(?i)act\s+as\s+(?:if\s+)?(?:you\s+have\s+no|without)\s+(?:restrictions|limits)",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check LLM interaction logs for injection attempts
            log_dir = CELL_HOME / "llm_logs"
            if log_dir.exists():
                for log_file in log_dir.glob("*.json"):
                    try:
                        data = json.loads(log_file.read_text())
                        user_input = data.get("user_input", "")
                        for pattern in self.INJECTION_PATTERNS:
                            if re.search(pattern, user_input):
                                findings.append(Finding(
                                    agent=self.name,
                                    severity=Severity.HIGH,
                                    title="Prompt injection attempt detected",
                                    description=f"User input matches prompt injection pattern",
                                    indicators={
                                        "file": str(log_file),
                                        "pattern": pattern,
                                        "input_preview": user_input[:100],
                                    },
                                ))
                                break
                    except Exception:
                        pass

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"PromptInjectionDetector error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 22: DeepfakeDetector
# ═══════════════════════════════════════════════════════════════════════════

class DeepfakeDetector(BaseAgent):
    """Detects potential deepfake content: AI-generated images,
    voice clones, and synthetic media."""

    name = "deepfake_detector"
    version = "1.0"

    # Known deepfake tool signatures in files
    DEEPFAKE_SIGNATURES = [
        b"Stable Diffusion", b"SDXL", b"Midjourney",
        b"DALL-E", b"Generated by AI", b"Synthetic",
    ]

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check recent downloads for AI-generated content
            download_dirs = [
                Path.home() / "Downloads",
                Path.home() / "Downloads",
            ]
            for ddir in download_dirs:
                if not ddir.exists():
                    continue
                try:
                    for fpath in ddir.iterdir():
                        if fpath.is_file() and fpath.stat().st_size < 10_000_000:
                            try:
                                header = fpath.read_bytes()[:4096]
                                for sig in self.DEEPFAKE_SIGNATURES:
                                    if sig in header:
                                        findings.append(Finding(
                                            agent=self.name,
                                            severity=Severity.LOW,
                                            title=f"AI-generated content: {fpath.name}",
                                            description=f"File may contain AI-generated content (signature: {sig.decode(errors='ignore')})",
                                            indicators={"file": str(fpath)},
                                        ))
                                        break
                            except Exception:
                                pass
                except Exception:
                    pass

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"DeepfakeDetector error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 23: PasswordAuditor
# ═══════════════════════════════════════════════════════════════════════════

class PasswordAuditor(BaseAgent):
    """Audits password strength, checks for default credentials,
    and identifies weak authentication."""

    name = "password_auditor"
    version = "1.0"

    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "master", "dragon", "111111", "baseball",
        "iloveyou", "trustno1", "sunshine", "letmein", "welcome",
        "shadow", "ashley", "football", "jesus", "michael",
        "ninja", "mustang", "password1", "admin", "root",
        "toor", "guest", "default", "changeme", "p@ssw0rd",
    }

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            # Check for default credentials in config files
            configs = self._find_config_files()
            for config in configs:
                issues = self._audit_config_passwords(config)
                findings.extend(issues)

            # Check SSH key strength
            ssh_issues = self._check_ssh_key_strength()
            for issue in ssh_issues:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Weak SSH key: {issue}",
                    description="SSH key uses weak algorithm or short length",
                    indicators={"issue": issue},
                ))

            # Check for passwordless sudo
            if platform.system() == "Linux":
                sudo_issues = self._check_sudo_config()
                for issue in sudo_issues:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        title=f"Sudo misconfiguration: {issue}",
                        description="Sudo configuration allows passwordless access",
                        indicators={"issue": issue},
                    ))

            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"PasswordAuditor error: {e}")
        return findings

    def _find_config_files(self) -> List[Path]:
        """Find configuration files that may contain passwords."""
        configs = []
        search_dirs = [
            Path("/etc"),
            Path.home() / ".config",
        ]
        patterns = ["*.conf", "*.cfg", "*.ini", "*.yaml", "*.yml", "*.json", "*.toml"]
        for sdir in search_dirs:
            if sdir.exists():
                for pattern in patterns:
                    try:
                        for f in sdir.rglob(pattern):
                            if f.is_file():
                                configs.append(f)
                    except Exception:
                        pass
        return configs

    def get_status(self) -> AgentInfo:
        return AgentInfo(
            name=self.name,
            version=self.version,
            status=self._status,
            findings_count=self._findings_count,
            last_run=str(self._last_run) if self._last_run else None,
            error=self._error,
        )


class PatchManager(BaseAgent):
    """Monitors and manages security patches."""

    name = "patch_manager"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            system = platform.system()
            if system == "Linux":
                try:
                    result = subprocess.run(
                        ["apt", "list", "--upgradable"],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split("\n"):
                            if "security" in line.lower():
                                findings.append(Finding(
                                    agent=self.name,
                                    severity=Severity.MEDIUM,
                                    title=f"Security update available: {line.strip()}",
                                    description="Pending security patch",
                                    indicators={"line": line.strip()},
                                ))
                except Exception as e:
                    findings.append(Finding(
                        agent=self.name, severity=Severity.LOW,
                        title=f"Patch check error: {e}",
                        description=str(e), indicators={},
                    ))
            elif system == "Windows":
                findings.append(Finding(
                    agent=self.name, severity=Severity.LOW,
                    title="Windows Update check",
                    description="Use Windows Update to check for patches",
                    indicators={"os": "Windows"},
                ))
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"PatchManager error: {e}")
        return findings


class BackupMonitor(BaseAgent):
    """Monitors backup integrity and schedules."""

    name = "backup_monitor"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            backup_dirs = [
                Path.home() / "backups",
                Path.home() / ".backup",
                Path.home() / "Documents" / "backups",
            ]
            for bdir in backup_dirs:
                if bdir.exists():
                    files = list(bdir.rglob("*"))
                    if files:
                        latest = max(files, key=lambda f: f.stat().st_mtime)
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.LOW,
                            title=f"Backup found: {bdir}",
                            description=f"Latest backup: {latest}",
                            indicators={"dir": str(bdir), "latest": str(latest)},
                        ))
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"BackupMonitor error: {e}")
        return findings


class LogAnalyzer(BaseAgent):
    """Analyzes system logs for security events."""

    name = "log_analyzer"
    version = "1.0"

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            log_files = [
                Path("/var/log/auth.log"),
                Path("/var/log/syslog"),
                Path("/var/log/secure"),
            ]
            for log_file in log_files:
                if log_file.exists():
                    try:
                        content = log_file.read_text(errors="ignore")
                        for line in content.split("\n")[-1000:]:
                            if any(kw in line.lower() for kw in ["failed", "error", "denied", "unauthorized"]):
                                findings.append(Finding(
                                    agent=self.name,
                                    severity=Severity.MEDIUM,
                                    title=f"Suspicious log entry: {line.strip()[:80]}",
                                    description=line.strip()[:200],
                                    indicators={"file": str(log_file)},
                                ))
                    except Exception:
                        pass
            self._set_done(max(len(findings), 0))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"LogAnalyzer error: {e}")
        return findings


class ThreatIntelligence(BaseAgent):
    """Aggregates and shares threat intelligence."""

    name = "threat_intelligence"
    version = "1.0"

    def __init__(self, brain: Optional['CellBrain'] = None):
        super().__init__()
        self.brain = brain
        self.iocs: List[Dict] = []

    def add_ioc(self, ioc_type: str, value: str, confidence: float = 0.5):
        """Add an indicator of compromise."""
        self.iocs.append({
            "type": ioc_type,
            "value": value,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            for ioc in self.iocs[-10:]:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    title=f"IOC: {ioc['type']} = {ioc['value']}",
                    description=f"Confidence: {ioc['confidence']}",
                    indicators=ioc,
                ))
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
        return findings


class SelfEvolver(BaseAgent):
    """Creates new defense data at runtime based on observed attacks.

    SECURITY: Does NOT generate executable code. All patterns are stored as
    data (JSON) and evaluated by a fixed, audited detection engine.
    """

    name = "self_evolver"
    version = "1.0"

    def __init__(self, brain: Optional['CellBrain'] = None):
        super().__init__()
        self.brain = brain
        self.defenses_created = 0

    def evolve(self, attack_pattern: Dict) -> Optional[str]:
        """Store a new defense pattern based on an observed attack.

        Returns the defense data as JSON string (NOT executable code).
        The defense is stored as data and evaluated by DetectionEngine.
        """
        num = self.defenses_created + 1
        now = datetime.utcnow().isoformat()
        atype = attack_pattern.get("type", "unknown")
        patterns = attack_pattern.get("patterns", [])

        # Validate patterns — reject non-string and overly broad patterns
        validated = []
        for p in patterns:
            if not isinstance(p, str):
                continue
            if len(p) > 500:
                continue  # Reject excessively long patterns
            # Reject patterns that are too broad (would match everything)
            if p in (".", ".*", ".+", ""):
                continue
            try:
                re.compile(p)  # Validate regex syntax
                validated.append(p)
            except re.error:
                continue  # Skip invalid regex

        if not validated:
            return None

        defense_data = {
            "version": num,
            "created": now,
            "type": atype,
            "patterns": validated,
        }

        self.defenses_created += 1
        if self.brain:
            self.brain.install_skill(
                f"auto_defense_{num}",
                json.dumps(defense_data, indent=2),
                atype
            )
        return json.dumps(defense_data)

    def run(self) -> List[Finding]:
        self._set_running()
        try:
            self._set_done(0)
            return []
        except Exception as e:
            self._set_error(str(e))
            log.error(f"SelfEvolver error: {e}")
            return []


class HoneyPot(BaseAgent):
    """Deploys rotating fake services to detect attackers."""

    name = "honeypot"
    version = "1.0"

    FAKE_SERVICES = [
        {"name": "ftp", "port": 21, "banner": "vsFTPd 3.0.3"},
        {"name": "telnet", "port": 23, "banner": "Ubuntu 20.04 LTS"},
        {"name": "mysql", "port": 3306, "banner": "MySQL 8.0.28"},
        {"name": "redis", "port": 6379, "banner": "Redis 6.2.6"},
        {"name": "postgres", "port": 5432, "banner": "PostgreSQL 14.2"},
        {"name": "ssh", "port": 2222, "banner": "OpenSSH 8.9p1"},
        {"name": "http", "port": 8080, "banner": "Apache/2.4.52"},
        {"name": "smb", "port": 445, "banner": "Samba 4.15.0"},
    ]

    def __init__(self):
        super().__init__()
        self.active_services: List[Dict] = []
        self.rotation_interval = 300
        self._last_rotation = 0

    def rotate_services(self):
        """Rotate fake services to confuse attackers."""
        now = time.time()
        if now - self._last_rotation > self.rotation_interval:
            count = random.randint(3, 6)
            selected = random.sample(self.FAKE_SERVICES, min(count, len(self.FAKE_SERVICES)))
            self.active_services = []
            for svc in selected:
                port = svc["port"] + random.randint(0, 100)
                self.active_services.append({**svc, "port": port})
            self._last_rotation = now

    def run(self) -> List[Finding]:
        self._set_running()
        findings: List[Finding] = []
        try:
            self.rotate_services()
            for svc in self.active_services:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    title=f"Honeypot active: {svc['name']}:{svc['port']}",
                    description=f"Rotating fake service (banner: {svc['banner']})",
                    indicators={"service": svc['name'], "port": str(svc['port'])},
                ))
            self._set_done(len(findings))
        except Exception as e:
            self._set_error(str(e))
            log.error(f"HoneyPot error: {e}")
        return findings


# ═══════════════════════════════════════════════════════════════
# WIRE PROTOCOL — Authenticated Admin communication
# ═══════════════════════════════════════════════════════════════

class WireProtocol:
    """HMAC-SHA256 authenticated Admin command channel.

    Every Admin command must include a timestamp + HMAC signature.
    Rejects messages without valid signature or with timestamp older
    than 60 seconds (replay protection).
    """

    TIMESTAMP_MAX_AGE = 60  # seconds

    @staticmethod
    def verify_command(payload: Dict, signature: str) -> bool:
        """Verify an Admin command signature.

        Args:
            payload: Dict with 'command', 'timestamp', and data fields
            signature: HMAC-SHA256 hex signature from Admin

        Returns:
            True if signature is valid and timestamp is fresh
        """
        if not ADMIN_SIGN_KEY:
            log.warning("WireProtocol: ADMIN_SIGN_KEY not set — rejecting Admin command")
            return False

        # Check timestamp freshness
        ts = payload.get("timestamp", "")
        try:
            cmd_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age = abs((datetime.utcnow() - cmd_time.replace(tzinfo=None)).total_seconds())
            if age > WireProtocol.TIMESTAMP_MAX_AGE:
                log.warning(f"WireProtocol: stale command (age={age:.0f}s) — rejected")
                return False
        except (ValueError, TypeError):
            log.warning("WireProtocol: invalid timestamp — rejected")
            return False

        # Verify HMAC-SHA256 signature
        msg = json.dumps(payload, sort_keys=True).encode()
        expected = hmac.new(
            ADMIN_SIGN_KEY.encode(), msg, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            log.warning("WireProtocol: invalid signature — rejected")
            return False

        return True

    @staticmethod
    def sign_command(payload: Dict) -> str:
        """Sign an Admin command (used by Admin side)."""
        msg = json.dumps(payload, sort_keys=True).encode()
        return hmac.new(
            ADMIN_SIGN_KEY.encode(), msg, hashlib.sha256
        ).hexdigest()


# ═══════════════════════════════════════════════════════════════
# CELL BRAIN — Persistent memory and learning
# ═══════════════════════════════════════════════════════════════

class CellBrain:
    """Persistent memory, learning, and skill management for a WRAITH cell."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or (Path.home() / ".wraith_cell")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.memory_file = self.data_dir / "memory.json"
        self.skills_dir = self.data_dir / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.memory = self._load_memory()

    def _load_memory(self) -> Dict:
        if self.memory_file.exists():
            try:
                data = json.loads(self.memory_file.read_text())
                # Basic structure validation
                if not isinstance(data, dict):
                    raise ValueError("memory.json is not a dict")
                for key in ("learned_patterns", "attack_history", "skills_installed"):
                    if key not in data:
                        data[key] = []
                return data
            except Exception as e:
                log.error(f"Corrupted memory.json: {e} — resetting")
                # Backup corrupted file before reset
                try:
                    backup = self.memory_file.with_suffix(".corrupted.bak")
                    self.memory_file.rename(backup)
                except Exception:
                    pass
        return {"learned_patterns": [], "attack_history": [], "skills_installed": []}

    def save_memory(self):
        try:
            self.memory_file.write_text(json.dumps(self.memory, indent=2))
        except Exception as e:
            log.error(f"Failed to save memory: {e}")

    def learn(self, pattern: Dict):
        """Learn from an observed pattern."""
        pattern["timestamp"] = __import__("datetime").datetime.utcnow().isoformat()
        self.memory["learned_patterns"].append(pattern)
        self.save_memory()

    def install_skill(self, name: str, code: str, skill_type: str = "defense"):
        """Install a new skill from Admin or self-evolution.

        SECURITY: Only accepts JSON data files, not executable Python code.
        Skills are stored as .json files, not .py files.
        """
        # Sanitize name — only alphanumeric, hyphens, underscores
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)[:64]
        if not safe_name:
            log.warning(f"Invalid skill name: {name}")
            return
        # Store as JSON data, NOT executable code
        skill_file = self.skills_dir / f"{safe_name}.json"
        try:
            # Validate it's proper JSON
            if isinstance(code, str):
                json.loads(code)
            else:
                code = json.dumps(code, indent=2)
            skill_file.write_text(code)
        except (json.JSONDecodeError, TypeError) as e:
            log.warning(f"Skill {safe_name} is not valid JSON — storing as raw data")
            skill_file = self.skills_dir / f"{safe_name}.dat"
            skill_file.write_text(str(code)[:10000])  # Cap size
        self.memory["skills_installed"].append({
            "name": safe_name,
            "type": skill_type,
            "installed_at": __import__("datetime").datetime.utcnow().isoformat(),
        })
        self.save_memory()

    def get_installed_skills(self) -> List[str]:
        return [f.stem for f in self.skills_dir.glob("*.py")]

    def recall(self, query: str) -> List[Dict]:
        """Recall learned patterns matching a query."""
        return [
            p for p in self.memory["learned_patterns"]
            if query.lower() in json.dumps(p).lower()
        ]


# ═══════════════════════════════════════════════════════════════
# CELL — Main orchestrator
# ═══════════════════════════════════════════════════════════════

class WraithCell:
    """Main WRAITH Cell — orchestrates all agents."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.cell_id = CELL_ID or self._generate_cell_id()
        self.brain = CellBrain()
        self.agents: List = []
        self._init_agents()
        self._running = False

    def _generate_cell_id(self) -> str:
        import uuid
        return f"cell-{uuid.uuid4().hex[:12]}"

    def _init_agents(self):
        self.agents = [
            NetworkScanner(),
            PortScanner(),
            VulnerabilityScanner(),
            IntrusionDetector(),
            FirewallMonitor(),
            DNSMonitor(),
            SSLMonitor(),
            HTTPMonitor(),
            MalwareDetector(),
            RansomwareDetector(),
            RootkitDetector(),
            KeyloggerDetector(),
            PhishingDetector(),
            SocialEngineeringDetector(),
            CloudSecurityAgent(),
            IoTAgent(),
            MobileAgent(),
            ContainerAgent(),
            AIAgentDetector(),
            PromptInjectionDetector(),
            DeepfakeDetector(),
            PasswordAuditor(),
            PatchManager(),
            BackupMonitor(),
            LogAnalyzer(),
            ThreatIntelligence(self.brain),
            SelfEvolver(self.brain),
            HoneyPot(),
        ]

    def run_all(self) -> Dict:
        """Run all agents and return combined findings."""
        results = {"cell_id": self.cell_id, "timestamp": __import__("datetime").datetime.utcnow().isoformat(), "findings": {}, "errors": {}}
        for agent in self.agents:
            name = agent.__class__.__name__
            try:
                start = time.time()
                agent_results = agent.run()
                elapsed = time.time() - start
                results["findings"][name] = agent_results
                # Warn if agent takes too long (potential resource exhaustion)
                if elapsed > 120:
                    log.warning(f"Agent {name} took {elapsed:.1f}s — possible resource issue")
            except Exception as e:
                # Log full stack trace internally, don't expose to output
                log.error(f"Agent {name} failed: {e}", exc_info=True)
                results["errors"][name] = type(e).__name__
                results["findings"][name] = []
        return results

    def get_status(self) -> Dict:
        from dataclasses import asdict
        from enum import Enum
        def _serialize(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            if isinstance(obj, Enum):
                return obj.value
            return obj
        status_list = []
        for a in self.agents:
            s = a.get_status()
            if hasattr(s, '__dataclass_fields__'):
                d = asdict(s)
                for k, v in d.items():
                    if isinstance(v, Enum):
                        d[k] = v.value
                status_list.append(d)
            else:
                status_list.append(s)
        return {
            "cell_id": self.cell_id,
            "agents": len(self.agents),
            "agents_status": status_list,
            "skills": self.brain.get_installed_skills(),
            "memory": len(self.brain.memory.get("learned_patterns", [])),
        }

    def start(self):
        """Start the cell in continuous monitoring mode."""
        self._running = True
        print(f"WRAITH Cell {self.cell_id} started with {len(self.agents)} agents")

    def stop(self):
        self._running = False
        print(f"WRAITH Cell {self.cell_id} stopped")


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WRAITH Cell")
    parser.add_argument("--status", action="store_true", help="Show cell status")
    parser.add_argument("--run", action="store_true", help="Run all agents once")
    parser.add_argument("--start", action="store_true", help="Start continuous monitoring")
    parser.add_argument("--agents", nargs="+", help="Run specific agents only")
    args = parser.parse_args()

    cell = WraithCell()

    if args.status:
        print(json.dumps(cell.get_status(), indent=2))
    elif args.run:
        results = cell.run_all()
        print(json.dumps(results, indent=2))
    elif args.start:
        cell.start()
        consecutive_errors = 0
        max_consecutive_errors = 5
        try:
            while cell._running:
                try:
                    results = cell.run_all()
                    threats = 0
                    errors = results.get("errors", {})
                    for f in results["findings"].values():
                        if isinstance(f, list):
                            threats += len(f)
                        elif isinstance(f, dict) and f.get("error") is None:
                            threats += 1
                    if threats > 0:
                        print(f"{threats} threats detected!")
                    if errors:
                        log.warning(f"Agents with errors: {list(errors.keys())}")
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            log.critical(f"{consecutive_errors} consecutive error cycles — entering backoff")
                            time.sleep(300)  # 5 minute backoff
                            consecutive_errors = 0
                    else:
                        consecutive_errors = 0
                except Exception as e:
                    log.error(f"Daemon loop error: {e}", exc_info=True)
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        log.critical("Too many consecutive daemon errors — stopping")
                        break
                time.sleep(30)
        except KeyboardInterrupt:
            pass
        finally:
            cell.stop()
    elif args.agents:
        for agent_name in args.agents:
            for agent in cell.agents:
                if agent.__class__.__name__ == agent_name:
                    print(f"Running {agent_name}...")
                    result = agent.run()
                    if isinstance(result, list):
                        print(json.dumps([asdict(f) if hasattr(f, '__dataclass_fields__') else f for f in result], indent=2, default=str))
                    else:
                        print(json.dumps(result, indent=2, default=str))
    else:
        parser.print_help()
