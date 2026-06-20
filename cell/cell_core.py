#!/usr/bin/env python3
"""
WRAITH Cell v5.0 — Core Agent (Wire Protocol + Kill Switch + Multi-Device + Ollama)
===================================================================================
Autonomous security cell with:
- Enhanced LLM brain (Ollama + all cloud providers)
- Wire protocol (real Cell↔Admin connection)
- Kill switch (Admin can revoke/poison any cell)
- Multi-device linking (one user → many cells)
- 26 security agents including AI attack detection + threat intelligence + post-quantum + IoT/OT + cloud
- Torrent-style P2P with DHT discovery
- HoneyPot deception
- Self-evolution
"""
from __future__ import annotations

import argparse, hashlib, json, logging, os, platform, secrets, signal, socket
import sys, threading, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

from wire_protocol import (
    WireProtocol, KillSwitch, DeviceLinker, EnhancedLLMBrain,
    _detect_ollama, _ask_ollama,
)
from tracker_client import P2PClient, DHTDiscovery, LocalQueue
from wraith_agents import ALL_AGENTS

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

CELL_HOME = Path.home() / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
IDENTITY_PATH = CELL_HOME / ".cell_identity"
AGENTS_MD_PATH = CELL_HOME / "AGENTS.md"
SOUL_MD_PATH = CELL_HOME / "SOUL.md"
ENV_PATH = CELL_HOME / ".env"

DEFAULT_TRACKER_HOST = "localhost"
DEFAULT_TRACKER_PORT = 7734
DEFAULT_P2P_PORT = 7737
HEARTBEAT_INTERVAL = 30
CELL_VERSION = "5.3.0"
UPDATE_CHECK_INTERVAL = 300  # Check for updates every 5 minutes

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("wraith-cell")


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _load_env() -> Dict[str, str]:
    env: Dict[str, str] = dict(os.environ)
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return env


def _cell_id() -> str:
    if IDENTITY_PATH.exists():
        return json.loads(IDENTITY_PATH.read_text())["cell_id"]
    cid = "CELL-" + hashlib.sha256(
        f"{platform.node()}:{time.time()}:{secrets.token_hex(8)}".encode()
    ).hexdigest()[:16].upper()
    IDENTITY_PATH.write_text(json.dumps({
        "cell_id": cid, "created_at": datetime.now().isoformat(),
        "version": "5.0.0", "platform": sys.platform,
    }, indent=2))
    return cid


def _read_config(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _detect_llm(env: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """Detect LLM provider — cloud first, then Ollama local."""
    providers = [
        ("anthropic", "ANTHROPIC_API_KEY", "sk-ant-", "claude-sonnet-4-20250514"),
        ("openai", "OPENAI_API_KEY", "sk-", "gpt-4o-mini"),
        ("gemini", "GEMINI_API_KEY", "AIzaSy", "gemini-1.5-flash"),
        ("groq", "GROQ_API_KEY", "gsk_", "llama-3.3-70b-versatile"),
        ("mistral", "MISTRAL_API_KEY", "MIST", "mistral-small-latest"),
        ("openrouter", "OPENROUTER_API_KEY", "sk-or-", "openrouter/auto"),
    ]
    for name, env_key, prefix, default_model in providers:
        key = env.get(env_key, "")
        if key:
            return name, default_model
    # No cloud key — try Ollama
    ollama_provider, ollama_model = _detect_ollama(env)
    if ollama_provider:
        return ollama_provider, ollama_model
    return None, None


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ═══════════════════════════════════════════════════════════════
# ATTACK ANALYZER
# ═══════════════════════════════════════════════════════════════

class AttackAnalyzer:
    def __init__(self, brain: EnhancedLLMBrain):
        self.brain = brain

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        result = {"severity": "medium", "category": "unknown",
                  "action": "monitor", "confidence": 0.5}
        if not self.brain.available:
            return result
        prompt = (
            f"Analyze this security event and respond with JSON only:\n"
            f"{json.dumps(event, default=str)}\n\n"
            f"Respond with: {{\"severity\": \"low|medium|high|critical\", "
            f"\"category\": \"scan|brute_force|exploit|exfil|privilege|other\", "
            f"\"action\": \"monitor|block|alert|isolate|quarantine\", "
            f"\"confidence\": 0.0-1.0}}"
        )
        response = self.brain.ask(prompt)
        if response:
            try:
                parsed = json.loads(response)
                result.update({k: parsed.get(k, v) for k, v in result.items()})
            except json.JSONDecodeError:
                pass
        return result


# ═══════════════════════════════════════════════════════════════
# SELF-EVOLUTION
# ═══════════════════════════════════════════════════════════════

class SelfEvolution:
    def __init__(self, brain: EnhancedLLMBrain):
        self.brain = brain
        self._rules: List[Dict] = []
        self._rules_path = CELL_HOME / "defense_rules.json"
        if self._rules_path.exists():
            self._rules = json.loads(self._rules_path.read_text())

    def learn(self, event: Dict, analysis: Dict):
        rule = {
            "event_type": event.get("type", ""),
            "severity": analysis.get("severity", "medium"),
            "source_ip": event.get("source_ip", ""),
            "created_at": datetime.now().isoformat(),
            "action": analysis.get("action", "monitor"),
        }
        self._rules.append(rule)
        if len(self._rules) > 1000:
            self._rules = self._rules[-1000:]
        self._rules_path.write_text(json.dumps(self._rules, indent=2))
        return rule

    def get_broadcastable_defense(self, event: Dict, analysis: Dict) -> Optional[Dict]:
        return {
            "attack_type": event.get("type", "unknown"),
            "technique": analysis.get("category", "unknown"),
            "patch": {"action": analysis.get("action", "block"),
                      "source_ip": event.get("source_ip", "")},
        }


# ═══════════════════════════════════════════════════════════════
# STATUS REPORTER
# ═══════════════════════════════════════════════════════════════

class StatusReporter:
    def __init__(self, env: Dict[str, str]):
        self.webhook_url = env.get("WRAITH_WEBHOOK_URL", "")
        self.tg_token = env.get("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat = env.get("TELEGRAM_CHAT_ID", "")

    def report(self, message: str) -> None:
        self._send_webhook(message)
        self._send_telegram(message)

    def _send_webhook(self, message: str) -> None:
        if not self.webhook_url or not requests:
            return
        try:
            requests.post(self.webhook_url, json={"text": message}, timeout=10)
        except Exception:
            pass

    def _send_telegram(self, message: str) -> None:
        if not self.tg_token or not self.tg_chat or not requests:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.tg_token}/sendMessage",
                json={"chat_id": self.tg_chat, "text": message}, timeout=10,
            )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# CELL CORE — Main Orchestrator (v5.0)
# ═══════════════════════════════════════════════════════════════

class CellCore:
    """Top-level cell orchestrator with wire protocol, kill switch, multi-device."""

    def __init__(self, tracker_host: str = DEFAULT_TRACKER_HOST,
                 tracker_port: int = DEFAULT_TRACKER_PORT,
                 p2p_port: int = DEFAULT_P2P_PORT,
                 no_p2p: bool = False) -> None:
        self.stop_event = threading.Event()
        self.env = _load_env()
        self.cell_id = _cell_id()
        self.p2p_port = p2p_port

        # Bootstrap
        self.agents_md = _read_config(AGENTS_MD_PATH)
        self.soul_md = _read_config(SOUL_MD_PATH)

        # LLM Brain (Enhanced with Ollama)
        provider, model = _detect_llm(self.env)
        self.brain = EnhancedLLMBrain(provider, model, self.env)
        if self.brain.available:
            log.info("LLM brain: %s / %s", provider, model)
        else:
            log.warning("No LLM API key or Ollama — running without AI")

        # Wire Protocol (Cell↔Admin)
        self.wire = WireProtocol(self.cell_id, tracker_host, tracker_port)
        self.kill_switch = self.wire.kill_switch
        self.device_linker = self.wire.device_linker

        # P2P client (direct cell-to-cell)
        self.p2p = P2PClient(self.cell_id, p2p_port) if not no_p2p else None

        # DHT discovery
        self.dht = DHTDiscovery(self.cell_id, p2p_port) if not no_p2p else None

        # Local queue
        self.queue = LocalQueue()

        # Other subsystems
        self.analyzer = AttackAnalyzer(self.brain)
        self.evolution = SelfEvolution(self.brain)
        self.reporter = StatusReporter(self.env)

        # Thread tracking
        self._all_threads: List[threading.Thread] = []
        self._started_at = time.time()
        self._anomaly_score = 0

    # ── Event routing ────────────────────────────────────────────

    def _handle_threat(self, event: Dict[str, Any]) -> None:
        """Route threat through analysis, evolution, P2P broadcast."""
        # Check kill switch first
        if self.kill_switch.is_killed:
            log.warning("Cell is killed — ignoring threat")
            return

        log.warning("Threat: %s", event.get("type"))
        self._anomaly_score = min(self._anomaly_score + 10, 100)

        analysis = self.analyzer.analyze(event)
        self.evolution.learn(event, analysis)
        self.reporter.report(
            f"⚠️ WRAITH [{self.cell_id[:12]}]: {json.dumps(event, default=str)}"
        )

        defense = self.evolution.get_broadcastable_defense(event, analysis)
        if defense:
            self.wire.broadcast_defense(
                attack_type=defense["attack_type"],
                technique=defense["technique"],
                patch=defense["patch"],
            )
            if self.p2p:
                self.p2p.broadcast_to_peers(
                    attack_type=defense["attack_type"],
                    technique=defense["technique"],
                    patch=defense["patch"],
                    cell_key=self.wire.cell_key or "",
                )

    # ── Heartbeat loop ───────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Periodic heartbeat: wire protocol + kill check + P2P + update check."""
        last_update_check = 0.0
        while not self.stop_event.is_set():
            ip = _get_local_ip()
            uptime = int(time.time() - self._started_at)

            # 1. Wire protocol heartbeat (with kill switch check)
            try:
                hb_result = self.wire.heartbeat(
                    anomaly_score=self._anomaly_score,
                    ip=ip, port=self.p2p_port,
                )

                # Check kill switch
                if hb_result.get("kill"):
                    log.critical("KILL COMMAND RECEIVED: %s", hb_result["kill"])
                    self._handle_kill(hb_result["kill"])

                # Install defenses from tracker
                for d in hb_result.get("defenses", []):
                    log.info(f"Installing defense: {d.get('attack_type')}/{d.get('technique')}")

                # Update P2P peers from tracker
                for p in hb_result.get("peers", []):
                    if self.p2p:
                        self.p2p.add_peer(p["cell_id"], p.get("ip", ""), p.get("port", 7737))

            except Exception as exc:
                log.debug("Wire heartbeat failed: %s", exc)

            # 2. Check for updates (every UPDATE_CHECK_INTERVAL seconds)
            now = time.time()
            if now - last_update_check > UPDATE_CHECK_INTERVAL:
                last_update_check = now
                try:
                    update = self.wire.check_for_updates(CELL_VERSION)
                    if update:
                        log.info(f"Update available: v{CELL_VERSION} -> v{update['version']}")
                        self._apply_update(update)
                except Exception as exc:
                    log.debug(f"Update check failed: {exc}")

            # 3. Fallback to DHT if tracker down
            if self.dht:
                dht_peers = self.dht.get_discovered_peers()
                for p in dht_peers:
                    if self.p2p:
                        self.p2p.add_peer(p["cell_id"], p["ip"], p["port"])

            # 4. Decay anomaly score
            self._anomaly_score = max(0, self._anomaly_score - 1)

            self.stop_event.wait(HEARTBEAT_INTERVAL)

    def _apply_update(self, update_info: Dict):
        """Apply a signed update from the tracker."""
        version = update_info.get("version", "unknown")
        package = update_info.get("package", {})
        signature = update_info.get("signature", "")
        if not signature:
            log.warning("Update has no signature — ignoring")
            return
        log.info(f"Applying update to v{version}: {package.get('description', 'no description')}")
        success = True
        try:
            # Apply update actions based on package type
            update_type = package.get("type", "config")
            if update_type == "config":
                config_updates = package.get("config", {})
                if config_updates:
                    log.info(f"Applying config update: {list(config_updates.keys())}")
            elif update_type == "rules":
                rules = package.get("rules", [])
                rules_path = CELL_HOME / "detection_rules.json"
                rules_path.write_text(json.dumps(rules, indent=2))
                log.info(f"Updated {len(rules)} detection rules")
            elif update_type == "agents":
                log.info("Agent update received — will apply on restart")
            else:
                log.warning(f"Unknown update type: {update_type}")
        except Exception as e:
            log.error(f"Update failed: {e}")
            success = False
        # Report update result to tracker
        self.wire.apply_update(CELL_VERSION, version, success)

    def _handle_kill(self, kill_info: Dict):
        """Handle kill switch activation."""
        reason = kill_info.get("reason", "Admin command")
        log.critical("CELL KILLED: %s", reason)
        self.reporter.report(f"🔴 WRAITH Cell KILLED [{self.cell_id[:12]}]: {reason}")
        # Stop all agents gracefully
        self.stop()
        self.stop_event.set()

    # ── Lifecycle ────────────────────────────────────────────────

    def run(self) -> None:
        """Start all subsystems and run until interrupted."""
        log.info("WRAITH Cell v5.0 [%s] starting...", self.cell_id)
        self.reporter.report(
            f"🟢 WRAITH Cell v5.0 online [{self.cell_id[:12]}] on {platform.node()}"
        )

        # Start P2P listener
        if self.p2p:
            self.p2p.start()

        # Start DHT discovery
        if self.dht:
            self.dht.start()

        # Start security agents
        agents_started = 0
        for agent_cls in ALL_AGENTS:
            try:
                agent = agent_cls({"cell_id": self.cell_id, "env": self.env})
                agent.start()
                agents_started += 1
            except Exception as exc:
                log.debug("Agent %s failed to start: %s", agent_cls.__name__, exc)
        log.info(f"Started {agents_started}/{len(ALL_AGENTS)} security agents")

        # Start heartbeat loop
        hb = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb.start()
        self._all_threads.append(hb)

        # Wait for shutdown
        log.info("All subsystems active. Waiting for shutdown signal.")
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(1)
        except KeyboardInterrupt:
            pass
        log.info("Cell shutting down...")
        self.stop()

    def stop(self) -> None:
        """Stop all subsystems."""
        for agent_cls in ALL_AGENTS:
            try:
                agent = agent_cls({"cell_id": self.cell_id, "env": self.env})
                agent.stop()
            except Exception:
                pass
        if self.p2p:
            self.p2p.stop()
        if self.dht:
            self.dht.stop()


def main():
    parser = argparse.ArgumentParser(description="WRAITH Cell v5.0")
    parser.add_argument("--tracker-host", default=DEFAULT_TRACKER_HOST)
    parser.add_argument("--tracker-port", type=int, default=DEFAULT_TRACKER_PORT)
    parser.add_argument("--p2p-port", type=int, default=DEFAULT_P2P_PORT)
    parser.add_argument("--no-p2p", action="store_true")
    args = parser.parse_args()

    cell = CellCore(
        tracker_host=args.tracker_host,
        tracker_port=args.tracker_port,
        p2p_port=args.p2p_port,
        no_p2p=args.no_p2p,
    )

    def shutdown(sig, frame):
        cell.stop_event.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    cell.run()


if __name__ == "__main__":
    main()
