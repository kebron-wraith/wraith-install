"""WRAITH Cell v4.0 — Log Analysis & Forensics Agent."""
from __future__ import annotations
import logging, time, json, re, hashlib
from typing import Any
from collections import Counter

_LOG = logging.getLogger("wraith.analyst")

class AnalystAgent:
    """Analyzes system/security logs for forensic evidence."""

    PATTERNS = {
        "auth_failed":  re.compile(r"Failed password|authentication failure", re.I),
        "priv_escal":   re.compile(r"sudo|su\[|execve.*root", re.I),
        "port_scan":    re.compile(r"SYN.*DST.*port", re.I),
        "malware_drop": re.compile(r"chmod.*\+(s|x)|wget.*http|curl.*-o", re.I),
        "data_exfil":   re.compile(r"scp\s|rsync\s|large\s+outbound", re.I),
    }

    def __init__(self, config: dict) -> None:
        self.config   = config
        self.active   = False
        self.log_dirs  = config.get("log_dirs", ["/var/log"])
        self._findings: list[dict] = []
        _LOG.info("AnalystAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("AnalystAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("AnalystAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan log files for suspicious patterns."""
        try:
            matches = []
            # Placeholder: production would walk log_dirs and tail files
            sample_lines = self._fetch_new_lines()
            for line in sample_lines:
                for threat_type, pattern in self.PATTERNS.items():
                    if pattern.search(line):
                        matches.append({"line": line[:200], "type": threat_type,
                                        "ts": time.time(),
                                        "hash": hashlib.sha256(line.encode()).hexdigest()[:12]})
            self._findings.extend(matches)
            return {"status": "ok", "matches": matches, "lines_scanned": len(sample_lines)}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Reconstruct attack timeline from findings."""
        try:
            matches = data.get("matches", [])
            types = Counter(m["type"] for m in matches)
            timeline = sorted(matches, key=lambda m: m["ts"])
            return {"attack_types": dict(types), "timeline": timeline[:10],
                    "evidence_hash": hashlib.sha256(str(timeline).encode()).hexdigest()[:16]}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        by_type = Counter(f["type"] for f in self._findings)
        return {"agent": "Analyst", "active": self.active, "findings": len(self._findings),
                "by_type": dict(by_type)}

    def _fetch_new_lines(self) -> list[str]:
        """Placeholder: tail log files for new entries."""
        return []
