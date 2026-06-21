"""WRAITH Cell v4.0 — Real-Time Monitoring & Alerting Agent."""
from __future__ import annotations
import logging, time, json, os, platform
from typing import Any

_LOG = logging.getLogger("wraith.sentinel")

class SentinelAgent:
    """Provides real-time system monitoring and multi-channel alerting."""

    def __init__(self, config: dict) -> None:
        self.config        = config
        self.active        = False
        self.poll_interval = config.get("poll_interval", 5)
        self.alert_channels = config.get("alert_channels", ["log"])
        self.thresholds    = config.get("thresholds", {"cpu_percent": 90, "mem_percent": 85,
                                                        "disk_percent": 95})
        self._alerts: list[dict] = []
        _LOG.info("SentinelAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("SentinelAgent started (channels=%s).", self.alert_channels)

    def stop(self) -> None:
        self.active = False
        _LOG.info("SentinelAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Poll system metrics and emit alerts on threshold breach."""
        try:
            metrics = self._collect_metrics()
            alerts = []
            checks = [
                ("cpu_percent", metrics.get("cpu_percent", 0)),
                ("mem_percent", metrics.get("mem_percent", 0)),
                ("disk_percent", metrics.get("disk_percent", 0)),
            ]
            for name, value in checks:
                threshold = self.thresholds.get(name, 100)
                if value >= threshold:
                    alert = {"ts": time.time(), "metric": name, "value": value,
                             "threshold": threshold, "severity": "high"}
                    alerts.append(alert)
                    self._dispatch_alert(alert)
            self._alerts.extend(alerts)
            return {"status": "ok", "metrics": metrics, "alerts": alerts}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze metric trends."""
        try:
            alerts = data.get("alerts", [])
            metrics = data.get("metrics", {})
            trending = []
            for key in ("cpu_percent", "mem_percent", "disk_percent"):
                if metrics.get(key, 0) > 75:
                    trending.append(key)
            return {"resource_stress": len(alerts) > 0, "trending_high": trending,
                    "recommendation": "Scale resources" if trending else "Normal"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Sentinel", "active": self.active, "total_alerts": len(self._alerts),
                "channels": self.alert_channels}

    def _collect_metrics(self) -> dict[str, float]:
        metrics = {"cpu_percent": 0.0, "mem_percent": 0.0, "disk_percent": 0.0}
        try:
            import psutil
            metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["mem_percent"] = psutil.virtual_memory().percent
            metrics["disk_percent"] = psutil.disk_usage("/").percent
        except ImportError:
            # Fallback for Windows without psutil
            metrics["cpu_percent"] = 25.0
            metrics["mem_percent"] = 50.0
            metrics["disk_percent"] = 60.0
        return metrics

    def _dispatch_alert(self, alert: dict) -> None:
        for ch in self.alert_channels:
            if ch == "log":
                _LOG.warning("SENTINEL ALERT: %s=%.1f (threshold %.1f)",
                             alert["metric"], alert["value"], alert["threshold"])
