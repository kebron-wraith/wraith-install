"""WRAITH Cell v4.0 — Attack Pattern Learning & Analysis Agent."""
from __future__ import annotations
import logging, time, json, hashlib
from typing import Any
from collections import Counter

_LOG = logging.getLogger("wraith.learner")

class LearnerAgent:
    """Learns attack patterns from observed events using statistical analysis."""

    def __init__(self, config: dict) -> None:
        self.config   = config
        self.active   = False
        self._patterns: list[dict] = []
        self._event_log: list[dict] = []
        self.learning_rate = config.get("learning_rate", 0.01)
        _LOG.info("LearnerAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("LearnerAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("LearnerAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan new events and extract patterns."""
        try:
            events = self._fetch_events()
            patterns = []
            if events:
                types = Counter(e.get("type", "unknown") for e in events)
                ips = Counter(e.get("source", "?") for e in events)
                for etype, count in types.most_common(5):
                    patterns.append({"type": etype, "count": count,
                                     "frequency": count / max(len(events), 1)})
                for ip, count in ips.most_common(3):
                    if count > 3:
                        patterns.append({"type": "persistent_source", "source": ip, "count": count})
            self._patterns.extend(patterns)
            self._event_log.extend(events)
            return {"status": "ok", "events_analyzed": len(events), "patterns": patterns}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze learned patterns for emerging threats."""
        try:
            patterns = data.get("patterns", [])
            high_freq = [p for p in patterns if p.get("frequency", 0) > 0.3]
            persistent = [p for p in patterns if p["type"] == "persistent_source"]
            return {"emerging_threats": len(high_freq),
                    "persistent_attackers": len(persistent),
                    "indicators": patterns[:5]}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Learner", "active": self.active, "patterns_known": len(self._patterns),
                "events_processed": len(self._event_log)}

    def _fetch_events(self) -> list[dict]:
        """Placeholder: consume from event bus / syslog / SIEM."""
        return []
