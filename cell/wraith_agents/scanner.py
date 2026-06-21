"""WRAITH Cell v4.0 — Port & Service Vulnerability Scanner."""
from __future__ import annotations
import logging, time, socket, json
from typing import Any

_LOG = logging.getLogger("wraith.scanner")

class ScannerAgent:
    """Scans ports and services for known vulnerabilities."""

    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

    def __init__(self, config: dict) -> None:
        self.config    = config
        self.active    = False
        self.target    = config.get("target", "127.0.0.1")
        self.ports      = config.get("ports", self.DEFAULT_PORTS)
        self.timeout    = config.get("timeout", 1.5)
        self._vulns: list[dict] = []
        _LOG.info("ScannerAgent initialized for %s.", self.target)

    def start(self) -> None:
        self.active = True
        _LOG.info("ScannerAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("ScannerAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan target ports and enumerate services."""
        try:
            open_ports, vulns = [], []
            for port in self.ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.timeout)
                        result = s.connect_ex((self.target, port))
                        if result == 0:
                            banner = self._grab_banner(s, port)
                            open_ports.append(port)
                            vuln = self._check_vuln(port, banner)
                            if vuln:
                                vulns.append(vuln)
                except OSError:
                    pass
            self._vulns.extend(vulns)
            return {"status": "ok", "open_ports": open_ports, "vulnerabilities": vulns,
                    "scanned": len(self.ports)}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze vulnerability scan results."""
        try:
            count = len(data.get("vulnerabilities", []))
            score = min(count * 15, 100)
            return {"vuln_score": score, "open_count": len(data.get("open_ports", [])),
                    "critical": [v for v in data.get("vulnerabilities", [])
                                 if v.get("severity") == "critical"]}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Scanner", "active": self.active, "target": self.target,
                "total_vulns": len(self._vulns)}

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.send(b"\r\n")
            return sock.recv(1024).decode(errors="ignore").strip()
        except Exception:
            return ""

    def _check_vuln(self, port: int, banner: str) -> dict | None:
        if "OpenSSH 7." in banner:
            return {"port": port, "severity": "high", "cve": "CVE-2018-15473", "banner": banner[:80]}
        if port == 445:
            return {"port": port, "severity": "critical", "cve": "CVE-2017-0144",
                    "note": "SMB exposed"}
        return None
