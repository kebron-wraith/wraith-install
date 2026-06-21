"""WRAITH Cell v4.0 — Intrusion Detection & Alerting Agent."""
from __future__ import annotations
import logging, time, json, hashlib
from typing import Any
from collections import defaultdict

_LOG = logging.getLogger("wraith.breach")

class BreachAgent:
    """Detects active intrusion attempts and triggers alerts."""

    SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, config: dict = None) -> None:
        self.name = "BreachAgent"
        self.config          = config or {}
        self.active          = False
        self.alert_threshold = self.config.get("alert_threshold", "medium")
        self._alerts: list[dict] = []
        self._failed_logins: dict[str, int] = defaultdict(int)
        _LOG.info("BreachAgent initialized (threshold=%s).", self.alert_threshold)

    def start(self) -> None:
        self.active = True
        _LOG.info("BreachAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("BreachAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for ongoing intrusion indicators."""
        try:
            alerts = []
            now = time.time()
            # Check brute-force evidence
            for ip, count in list(self._failed_logins.items()):
                sev = "critical" if count > 20 else "high" if count > 10 else "medium" if count > 5 else None
                if sev and self.SEVERITY[sev] >= self.SEVERITY[self.alert_threshold]:
                    alerts.append({"ts": now, "source_ip": ip, "type": "brute_force",
                                   "severity": sev, "attempts": count})
            # Simulated: check for new indicators
            new = self._fetch_new_indicators()
            alerts.extend(new)
            self._alerts.extend(alerts)
            return {"status": "scan_complete", "agent": "BreachAgent", "alerts": alerts, "alert_count": len(alerts), "findings": alerts}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "agent": "BreachAgent", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze alerts and correlate attack chains."""
        try:
            alerts = data.get("alerts", [])
            sev_scores = [self.SEVERITY.get(a.get("severity","low"),1) for a in alerts]
            max_sev = max(sev_scores) if sev_scores else 0
            ips = list({a.get("source_ip","?") for a in alerts if a.get("source_ip")})
            chain_id = hashlib.sha256(str(alerts).encode()).hexdigest()[:12]
            return {"chain_id": chain_id, "max_severity": max_sev,
                    "attack_sources": ips, "action": "block_and_isolate" if max_sev >=3 else "monitor"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        critical = sum(1 for a in self._alerts if a.get("severity") == "critical")
        return {"agent": "Breach", "active": self.active, "total_alerts": len(self._alerts),
                "critical_alerts": critical}

    def _fetch_new_indicators(self) -> list[dict]:
        """Placeholder: integrate with syslog / auditd / OSSEC hooks."""
        return []

    def _remediation(self, category: str) -> str:
        """Return remediation guidance for a vulnerability category."""
        remediations = {
            "sqli": "Use parameterized queries/prepared statements. Apply input validation. Deploy WAF with SQLi rules. Principle of least privilege for DB accounts.",
            "xss": "Implement Content Security Policy (CSP). Encode output properly. Use HTTPOnly/Secure cookie flags. Sanitize all user input on both client and server side.",
            "ssrf": "Validate and whitelist allowed URLs/destrict outbound requests. Disable unused URL schemes. Implement network segmentation for internal services.",
            "cmd_injection": "Never pass user input directly to system calls. Use allowlists for allowed commands. Apply strict input validation. Run with least privileges.",
            "path_traversal": "Validate file paths against allowlists. Use chroot or containerization. Normalize paths before access. Disable directory listing.",
        }
        return remediations.get(category, f"Review OWASP guidelines for {category} and apply defense-in-depth controls.")

    def record_failed_login(self, source_ip: str) -> None:
        """External hook: call on failed auth events."""
        self._failed_logins[source_ip] += 1
