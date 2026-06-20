"""WRAITH Cell v4.0 — Firewall & Access Control Agent."""
from __future__ import annotations
import logging, time, json, hashlib
from typing import Any

_LOG = logging.getLogger("wraith.guardian")

class GuardianAgent:
    """Manages firewall rules and access-control policies."""

    def __init__(self, config: dict) -> None:
        self.config      = config
        self.active      = False
        self.default_policy = config.get("default_policy", "deny")
        self._rules: list[dict] = []
        self._violations: list[dict] = []
        _LOG.info("GuardianAgent initialized (policy=%s).", self.default_policy)

    def start(self) -> None:
        self.active = True
        self._apply_default_policy()
        _LOG.info("GuardianAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("GuardianAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for firewall misconfigurations and violations."""
        try:
            violations = []
            # Check for overly permissive rules
            for rule in self._rules:
                if rule.get("action") == "allow" and rule.get("source") == "0.0.0.0/0":
                    violations.append({"rule": rule, "issue": "overly_permissive",
                                       "severity": "high"})
            # Check default policy enforcement
            if not any(r.get("default") for r in self._rules):
                violations.append({"issue": "no_default_policy", "severity": "medium"})
            self._violations.extend(violations)
            return {"status": "ok", "violations": violations, "rule_count": len(self._rules)}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze violations and recommend remediation."""
        try:
            violations = data.get("violations", [])
            high = [v for v in violations if v.get("severity") == "high"]
            return {"risk_level": "critical" if high else "medium" if violations else "low",
                    "remediate": [v.get("rule", {}) for v in high]}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Guardian", "active": self.active, "rules": len(self._rules),
                "violations": len(self._violations), "policy": self.default_policy}

    def add_rule(self, rule: dict) -> bool:
        rule["id"] = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()[:8]
        rule["created"] = time.time()
        self._rules.append(rule)
        return True

    def _apply_default_policy(self) -> None:
        self._rules.insert(0, {"id": "default", "action": self.default_policy,
                               "source": "any", "dest": "any", "port": "any",
                               "protocol": "any", "default": True})
