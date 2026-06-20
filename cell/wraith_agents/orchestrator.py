"""WRAITH Cell v4.0 — Multi-Agent Coordination Orchestrator."""
from __future__ import annotations
import logging, time, json, uuid
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

_LOG = logging.getLogger("wraith.orchestrator")

class OrchestratorAgent:
    """Coordinates parallel execution of multiple WRAITH security agents."""

    def __init__(self, config: dict) -> None:
        self.config     = config
        self.active     = False
        self._agents: dict[str, Any] = {}
        self.max_workers = config.get("max_workers", 4)
        self._runs: list[dict] = []
        _LOG.info("OrchestratorAgent initialized (workers=%d).", self.max_workers)

    def start(self) -> None:
        self.active = True
        _LOG.info("OrchestratorAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("OrchestratorAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Run all registered agents in parallel and collect results."""
        try:
            results = self._run_all_agents()
            validated = self._validate_results(results)
            run = {"run_id": str(uuid.uuid4())[:8], "ts": time.time(),
                   "results": results, "valid": validated}
            self._runs.append(run)
            return {"status": "ok", "run": run}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Cross-correlate findings from all agents."""
        try:
            results = data.get("run", {}).get("results", {})
            all_findings = []
            for agent_name, result in results.items():
                if isinstance(result, dict) and result.get("status") == "ok":
                    for key in ("findings", "alerts", "vulnerabilities", "detections"):
                        if key in result:
                            all_findings.extend(result[key])
            return {"total_findings": len(all_findings),
                    "correlated": self._correlate(all_findings)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Orchestrator", "active": self.active,
                "agents": len(self._agents), "runs": len(self._runs)}

    def register_agent(self, name: str, agent: Any) -> None:
        self._agents[name] = agent

    def _run_all_agents(self) -> dict[str, Any]:
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._safe_scan, name, ag): name
                       for name, ag in self._agents.items()}
            for future in as_completed(futures, timeout=30):
                name = futures[future]
                try:
                    results[name] = future.result(timeout=10)
                except Exception as e:
                    results[name] = {"status": "error", "error": str(e)}
        return results

    def _safe_scan(self, name: str, agent: Any) -> dict:
        if hasattr(agent, "scan") and callable(agent.scan):
            return agent.scan()
        return {"status": "error", "error": f"{name} has no scan method"}

    def _validate_results(self, results: dict) -> bool:
        return all(r.get("status") == "ok" if isinstance(r, dict) else False
                   for r in results.values())

    def _correlate(self, findings: list) -> list[dict]:
        """Group findings by shared attributes (IP, host, etc.)."""
        groups: dict[str, list] = {}
        for f in findings:
            key = f.get("source_ip", f.get("src", "unknown"))
            groups.setdefault(key, []).append(f)
        return [{"key": k, "count": len(v)} for k, v in groups.items()]
