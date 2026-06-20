"""WRAITH Cell v4.0 — Agent Orchestration & Command Agent."""
from __future__ import annotations
import logging, time, json, uuid
from typing import Any

_LOG = logging.getLogger("wraith.commander")

class CommanderAgent:
    """Orchestrates WRAITH agents: dispatch, prioritize, and coordinate responses."""

    def __init__(self, config: dict) -> None:
        self.config    = config
        self.active    = False
        self._agents: dict[str, Any] = {}
        self._queue: list[dict] = []
        _LOG.info("CommanderAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("CommanderAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("CommanderAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Check agent health and queue status."""
        try:
            health = {}
            for name, agent in self._agents.items():
                try:
                    agent_health = agent.report()
                    health[name] = {"active": agent_health.get("active", False),
                                    "agent": agent_health.get("agent", name)}
                except Exception as e:
                    health[name] = {"active": False, "error": str(e)}
            return {"status": "ok", "agent_health": health, "queue_depth": len(self._queue)}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze overall cell health and optimize dispatch."""
        try:
            health = data.get("agent_health", {})
            offline = [n for n, h in health.items() if not h.get("active")]
            return {"offline_agents": offline, "cell_health": "degraded" if offline else "healthy",
                    "recommendation": "Restart offline agents" if offline else "All systems nominal"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Commander", "active": self.active,
                "managed_agents": len(self._agents), "queued_tasks": len(self._queue)}

    def register_agent(self, name: str, agent: Any) -> None:
        self._agents[name] = agent
        _LOG.info("Registered agent: %s", name)

    def dispatch(self, task: dict) -> str:
        task_id = str(uuid.uuid4())[:8]
        task["id"] = task_id
        task["dispatched_at"] = time.time()
        self._queue.append(task)
        _LOG.info("Dispatched task %s to queue.", task_id)
        return task_id
