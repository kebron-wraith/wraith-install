"""WRAITH Cell v4.0 — System Hardening Agent."""
from __future__ import annotations
import logging, time, json, platform, subprocess
from typing import Any

_LOG = logging.getLogger("wraith.engineer")

class EngineerAgent:
    """Hardens the host OS and services against attack."""

    HARDENING_RULES = [
        {"id": "H001", "name": "disable_telnet",          "check": "telnet_disabled"},
        {"id": "H002", "name": "disable_svpn",             "check": "svpn_disabled"},
        {"id": "H003", "name": "enable_firewall",          "check": "firewall_enabled"},
        {"id": "H004", "name": "disable_root_ssh",         "check": "no_root_ssh"},
        {"id": "H005", "name": "password_policy",          "check": "pw_policy_set"},
        {"id": "H006", "name": "disable_usb_autorun",      "check": "usb_autorun_off"},
        {"id": "H007", "name": "enable_audit_logging",     "check": "audit_on"},
        {"id": "H008", "name": "secure_temp_dirs",         "check": "tmp_secure"},
    ]

    def __init__(self, config: dict) -> None:
        self.config   = config
        self.active   = False
        self._results: list[dict] = []
        _LOG.info("EngineerAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("EngineerAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("EngineerAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan system against hardening rules."""
        try:
            results = []
            for rule in self.HARDENING_RULES:
                passed = self._check_rule(rule)
                results.append({"rule": rule["id"], "name": rule["name"],
                                "passed": passed, "ts": time.time()})
            self._results.extend(results)
            failed = [r for r in results if not r["passed"]]
            return {"status": "ok", "checks": results, "failed": failed,
                    "compliance_pct": round((len(results) - len(failed)) / len(results) * 100, 1)}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Prioritize remediation actions."""
        try:
            failed = data.get("failed", [])
            priority = sorted(failed, key=lambda x: x["rule"])
            return {"remediate": priority, "compliance": data.get("compliance_pct", 0),
                    "risk": "high" if len(failed) > 3 else "medium" if failed else "low"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        last = self._results[-len(self.HARDENING_RULES):] if self._results else []
        failed = sum(1 for r in last if not r["passed"])
        return {"agent": "Engineer", "active": self.active, "total_checks": len(self._results),
                "last_failed": failed}

    def _check_rule(self, rule: dict) -> bool:
        """Placeholder: perform actual OS-level check."""
        # Production would run OS-specific commands
        return True
