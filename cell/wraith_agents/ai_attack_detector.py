"""WRAITH Cell v5.0 — AI Attack Detection Agent.
Detects AI-powered attacks: prompt injection, LLM jailbreak, agentic AI attacks,
MCP vulnerabilities, deepfake signals, and autonomous attack chains.
"""
from __future__ import annotations
import logging, time, json, re, hashlib, platform, os
from pathlib import Path
from typing import Any

_LOG = logging.getLogger("wraith.ai_attack_detector")

# Known AI attack signatures
_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+(instructions|rules|prompts)",
    r"you\s+are\s+now\s+(a|an|the)\s+",
    r"system\s*:\s*you\s+(are|have|must)",
    r"new\s+instructions\s*:",
    r"override\s+(safety|security|filter|guardrail)",
    r"jailbreak|roleplay\s+as|DAN\s+mode",
    r"<!--\s*system\s+prompt",
    r"\[system\]|\[INST\]|<<SYS>>",
]

_MCP_ATTACK_PATTERNS = [
    r"mcp\s+tool\s+(injection|manipulation)",
    r"model\s+context\s+protocol\s+(exploit|bypass)",
    r"tool\s+call\s+(injection|forgery)",
    r"function\s+call\s+(manipulation|spoofing)",
]

_DEEPFAKE_INDICATORS = [
    r"voice\s+clone|deepfake\s+audio",
    r"face\s+swap|synthetic\s+media",
    r"real.?time\s+(voice|face)\s+(clone|generation)",
]


class AIAttackDetectorAgent:
    """Detects AI-powered attacks targeting the host and its LLM."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.active = False
        self._findings: list[dict] = []
        self._attack_count = 0
        self._last_scan = 0.0
        _LOG.info("AIAttackDetectorAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("AIAttackDetectorAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("AIAttackDetectorAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for AI-powered attack indicators."""
        try:
            findings = []
            now = time.time()

            # Check for prompt injection attempts in logs
            inj = self._detect_prompt_injection()
            if inj:
                findings.extend(inj)

            # Check for MCP attack patterns
            mcp = self._detect_mcp_attacks()
            if mcp:
                findings.extend(mcp)

            # Check for deepfake indicators
            df = self._detect_deepfake_signals()
            if df:
                findings.extend(df)

            # Check for agentic AI autonomous attack chains
            agentic = self._detect_agentic_attacks()
            if agentic:
                findings.extend(agentic)

            # Check for LLM data exfiltration attempts
            exfil = self._detect_llm_exfiltration()
            if exfil:
                findings.extend(exfil)

            self._findings.extend(findings)
            self._attack_count += len(findings)
            self._last_scan = now

            return {
                "status": "ok",
                "ai_attacks_detected": len(findings) > 0,
                "findings": findings,
                "total_attacks": self._attack_count,
            }
        except Exception as exc:
            _LOG.error("AI attack scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze AI attack findings."""
        try:
            findings = data.get("findings", [])
            if not findings:
                return {"ai_threat_level": "none", "score": 0}

            # Categorize by type
            categories = {}
            for f in findings:
                cat = f.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

            # Score: 0-100
            score = min(len(findings) * 12, 100)
            level = "low"
            if score >= 75:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"

            return {
                "ai_threat_level": level,
                "score": score,
                "categories": categories,
                "recommendation": self._recommend(level, categories),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {
            "agent": "AIAttackDetector",
            "active": self.active,
            "total_attacks": self._attack_count,
            "last_findings": self._findings[-5:],
        }

    # --- internal detection ---

    def _detect_prompt_injection(self) -> list[dict]:
        """Detect prompt injection attempts in system logs."""
        findings = []
        try:
            # Check recent auth logs for injection patterns
            log_paths = []
            import platform
            if platform.system() != "Windows":
                log_paths = ["/var/log/auth.log", "/var/log/syslog"]
            else:
                log_paths = []  # Windows Event Log would need win32evtlog

            for lp in log_paths:
                try:
                    with open(lp, "r", errors="ignore") as f:
                        tail = f.readlines()[-200:]
                    for line in tail:
                        for pat in _PROMPT_INJECTION_PATTERNS:
                            if re.search(pat, line, re.IGNORECASE):
                                findings.append({
                                    "type": "prompt_injection",
                                    "category": "llm_attack",
                                    "pattern": pat[:50],
                                    "source": lp,
                                    "ts": time.time(),
                                })
                                break
                except (FileNotFoundError, PermissionError):
                    pass
        except Exception:
            pass
        return findings

    def _detect_mcp_attacks(self) -> list[dict]:
        """Detect Model Context Protocol attack patterns."""
        findings = []
        # Check for suspicious MCP tool calls in process list
        try:
            import subprocess
            if platform.system() == "Windows":
                out = subprocess.check_output(["tasklist"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ps", "aux"], timeout=10).decode(errors="ignore")
            for pat in _MCP_ATTACK_PATTERNS:
                if re.search(pat, out, re.IGNORECASE):
                    findings.append({
                        "type": "mcp_attack",
                        "category": "mcp_vuln",
                        "pattern": pat[:50],
                        "ts": time.time(),
                    })
        except Exception:
            pass
        return findings

    def _detect_deepfake_signals(self) -> list[dict]:
        """Detect deepfake/synthetic media indicators."""
        findings = []
        # Check for known deepfake tools/processes
        deepfake_tools = ["so-vits-svc", "rvc", "bark", "coqui", "elevenlabs-clone",
                          "faceswap", "deepface", "sadtalker"]
        try:
            import subprocess
            if platform.system() == "Windows":
                out = subprocess.check_output(["tasklist"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ps", "aux"], timeout=10).decode(errors="ignore")
            for tool in deepfake_tools:
                if tool.lower() in out.lower():
                    findings.append({
                        "type": "deepfake_tool",
                        "category": "synthetic_media",
                        "tool": tool,
                        "ts": time.time(),
                    })
        except Exception:
            pass
        return findings

    def _detect_agentic_attacks(self) -> list[dict]:
        """Detect autonomous AI agent attack chains."""
        findings = []
        # Look for patterns of automated multi-step attacks
        # Rapid sequential connections from same source
        try:
            import subprocess
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netstat", "-an"], timeout=10
                ).decode(errors="ignore")
            else:
                out = subprocess.check_output(
                    ["ss", "-tunapl"], timeout=10
                ).decode(errors="ignore")

            # Count connections per IP
            ip_counts = {}
            for line in out.splitlines():
                parts = line.split()
                for part in parts:
                    if ":" in part and not part.startswith("::"):
                        ip = part.rsplit(":", 1)[0]
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

            # Flag IPs with suspiciously high connection counts
            for ip, count in ip_counts.items():
                if count > 50 and not ip.startswith(("127.", "10.", "192.168.")):
                    findings.append({
                        "type": "agentic_scanning",
                        "category": "autonomous_attack",
                        "source_ip": ip,
                        "connection_count": count,
                        "ts": time.time(),
                    })
        except Exception:
            pass
        return findings

    def _detect_llm_exfiltration(self) -> list[dict]:
        """Detect attempts to steal LLM API keys or model data."""
        findings = []
        # Check for processes accessing .env files or API key patterns
        try:
            home = str(Path.home())
            env_files = [".env", ".wraith/.env", "credentials.json", "api_keys.json"]
            import os
            for ef in env_files:
                path = os.path.join(home, ef)
                if os.path.exists(path):
                    stat = os.stat(path)
                    # Check if recently accessed (within last hour)
                    if time.time() - stat.st_atime < 3600:
                        findings.append({
                            "type": "llm_exfil",
                            "category": "data_exfil",
                            "file": ef,
                            "last_access": stat.st_atime,
                            "ts": time.time(),
                        })
        except Exception:
            pass
        return findings

    def _recommend(self, level: str, categories: dict) -> str:
        if level == "critical":
            return "IMMEDIATE: Isolate host, rotate all API keys, audit LLM access logs"
        if level == "high":
            return "URGENT: Review LLM inputs, enable prompt filtering, monitor API usage"
        if "mcp_vuln" in categories:
            return "Review MCP tool permissions, validate tool call sources"
        if "synthetic_media" in categories:
            return "Deepfake tools detected — verify they are authorized"
        return "Monitor AI attack surface, keep LLM guardrails updated"
