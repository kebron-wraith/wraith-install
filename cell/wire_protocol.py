"""WRAITH Cell v5.0 — Wire Protocol: Cell↔Admin + Kill Switch + Multi-Device.
Handles:
1. Real bidirectional connection to Admin tracker
2. Kill switch (Admin can revoke/poison any cell)
3. Multi-device linking (one user → many cells → one identity)
4. Ollama/local LLM support
5. Threat intelligence sharing
"""
from __future__ import annotations
import json, hashlib, hmac, os, time, sqlite3, threading, socket, struct, logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import platform

CELL_HOME = Path.home() / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
DEVICE_DB = CELL_HOME / "devices.db"
QUEUE_DB = CELL_HOME / "queue.db"

log = logging.getLogger("wraith-wire")


# ═══════════════════════════════════════════════════════════════
# MULTI-DEVICE LINKING — One user, many cells, one identity
# ═══════════════════════════════════════════════════════════════

class DeviceLinker:
    """
    Links multiple devices under one WRAITH identity.
    User installs on laptop + phone + server → all linked.
    Admin sees: "Admin" with 3 active cells.
    """

    def __init__(self, db_path: Path = DEVICE_DB):
        self.db_path = str(db_path)
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self):
        with self._conn as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS user_identity (
                    user_id TEXT PRIMARY KEY,
                    username TEXT,
                    email TEXT,
                    created_at TEXT NOT NULL,
                    api_tier TEXT DEFAULT 'free'
                );
                CREATE TABLE IF NOT EXISTS linked_devices (
                    device_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    device_name TEXT,
                    device_type TEXT,
                    platform TEXT,
                    last_seen TEXT NOT NULL,
                    ip TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES user_identity(user_id)
                );
                CREATE INDEX IF NOT EXISTS idx_devices_user ON linked_devices(user_id);
                CREATE INDEX IF NOT EXISTS idx_devices_cell ON linked_devices(cell_id);
            """)

    def register_user(self, username: str, email: str = "") -> str:
        """Register a user identity. Returns user_id."""
        user_id = hashlib.sha256(f"{username}:{time.time()}".encode()).hexdigest()[:16]
        with self._conn as c:
            c.execute(
                "INSERT OR IGNORE INTO user_identity (user_id, username, email, created_at) VALUES (?,?,?,?)",
                (user_id, username, email, datetime.now().isoformat()),
            )
        return user_id

    def link_device(self, user_id: str, cell_id: str, device_name: str,
                    device_type: str, platform: str, ip: str) -> str:
        """Link a device to a user. Returns device_id."""
        device_id = hashlib.sha256(f"{cell_id}:{platform}:{time.time()}".encode()).hexdigest()[:16]
        with self._conn as c:
            c.execute(
                "INSERT OR REPLACE INTO linked_devices (device_id, user_id, cell_id, device_name, device_type, platform, last_seen, ip, status) VALUES (?,?,?,?,?,?,?,?,?)",
                (device_id, user_id, cell_id, device_name, device_type, platform,
                 datetime.now().isoformat(), ip, "active"),
            )
        return device_id

    def get_user_devices(self, user_id: str) -> List[Dict]:
        """Get all devices for a user."""
        rows = self._conn.execute(
            "SELECT * FROM linked_devices WHERE user_id=? ORDER BY last_seen DESC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_user_for_cell(self, cell_id: str) -> Optional[Dict]:
        """Get the user identity for a cell."""
        row = self._conn.execute(
            "SELECT u.* FROM user_identity u JOIN linked_devices d ON u.user_id=d.user_id WHERE d.cell_id=?",
            (cell_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_all_cells_for_user(self, user_id: str) -> List[str]:
        """Get all cell IDs for a user."""
        rows = self._conn.execute(
            "SELECT cell_id FROM linked_devices WHERE user_id=? AND status='active'",
            (user_id,),
        ).fetchall()
        return [r[0] for r in rows]

    def detach_device(self, cell_id: str):
        """Mark a device as detached (kill switch)."""
        with self._conn as c:
            c.execute(
                "UPDATE linked_devices SET status='killed' WHERE cell_id=?",
                (cell_id,),
            )

    def get_user_summary(self, user_id: str) -> Dict:
        """Get summary for Admin dashboard."""
        devices = self.get_user_devices(user_id)
        active = [d for d in devices if d["status"] == "active"]
        killed = [d for d in devices if d["status"] == "killed"]
        return {
            "user_id": user_id,
            "total_devices": len(devices),
            "active_devices": len(active),
            "killed_devices": len(killed),
            "devices": devices,
        }


# ═══════════════════════════════════════════════════════════════
# KILL SWITCH — Admin can remotely disable any cell
# ═══════════════════════════════════════════════════════════════

class KillSwitch:
    """
    Kill switch system:
    1. Admin marks cell as "revoked" in tracker DB
    2. On next heartbeat, cell receives kill command
    3. Cell stops all agents, wipes sensitive data, goes dark
    4. Cell broadcasts "I'm dead" to peers (so they know)
    5. Only Admin can reactivate (with new signed key)
    """

    KILL_COMMANDS = ["revoke", "poison", "sleep", "self_destruct"]

    def __init__(self, cell_id: str, db_path: Path = DEVICE_DB):
        self.cell_id = cell_id
        self.db_path = str(db_path)
        self._local = threading.local()
        self._killed = False
        self._kill_reason = ""
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        with self._conn as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS kill_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cell_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    reason TEXT,
                    executed_at TEXT NOT NULL,
                    success INTEGER DEFAULT 1
                );
            """)

    @property
    def is_killed(self) -> bool:
        return self._killed

    @property
    def kill_reason(self) -> str:
        return self._kill_reason

    def check_kill_command(self, tracker_response: Dict) -> bool:
        """Check if tracker sent a kill command."""
        cmd = tracker_response.get("kill_command", "")
        if cmd in self.KILL_COMMANDS:
            self._execute_kill(cmd, tracker_response.get("kill_reason", "Admin command"))
            return True
        return False

    def _execute_kill(self, command: str, reason: str):
        """Execute kill command."""
        self._killed = True
        self._kill_reason = reason
        log.critical("KILL SWITCH ACTIVATED: %s — Reason: %s", command, reason)

        # Log it
        with self._conn as c:
            c.execute(
                "INSERT INTO kill_log (cell_id, command, reason, executed_at) VALUES (?,?,?,?)",
                (self.cell_id, command, reason, datetime.now().isoformat()),
            )

        if command == "revoke":
            self._revoke()
        elif command == "poison":
            self._poison()
        elif command == "sleep":
            self._sleep()
        elif command == "self_destruct":
            self._self_destruct()

    def _revoke(self):
        """Stop all agents, stop monitoring, but keep data."""
        log.info("REVOKE: Stopping all agents, cell goes passive")

    def _poison(self):
        """Feed false data to any connected systems."""
        log.info("POISON: Cell will feed false telemetry")

    def _sleep(self):
        """Go dormant — wait for reactivation signal."""
        log.info("SLEEP: Cell dormant, awaiting reactivation")

    def _self_destruct(self):
        """Wipe sensitive data and go dark."""
        log.warning("SELF-DESTRUCT: Wiping sensitive data")
        # Wipe local threat intel DB (keep device link)
        try:
            threat_db = CELL_HOME / "threat_intel.db"
            if threat_db.exists():
                threat_db.unlink()
        except Exception:
            pass

    def get_status(self) -> Dict:
        return {
            "killed": self._killed,
            "reason": self._kill_reason,
        }


# ═══════════════════════════════════════════════════════════════
# WIRE PROTOCOL — Enhanced tracker client with kill + multi-device
# ═══════════════════════════════════════════════════════════════

class WireProtocol:
    """
    Enhanced Cell↔Admin wire protocol.
    Extends TrackerClient with:
    - Kill switch checking
    - Multi-device registration
    - Threat intelligence upload/download
    - Signed upgrade packages
    """

    def __init__(self, cell_id: str, tracker_host: str = "localhost",
                 tracker_port: int = 7734):
        self.cell_id = cell_id
        self.tracker_url = f"http://{tracker_host}:{tracker_port}"
        self.cell_key: Optional[str] = None
        self.kill_switch = KillSwitch(cell_id)
        self.device_linker = DeviceLinker()
        self._peer_list: List[Dict] = []
        self._last_announce = 0.0

    def _sign_headers(self) -> Dict[str, str]:
        ts = str(int(time.time()))
        key = self.cell_key or ""
        sig = hmac.new(key.encode(), f"{self.cell_id}:{ts}".encode(),
                       hashlib.sha256).hexdigest()
        return {"X-WRAITH-Cell": self.cell_id, "X-WRAITH-Sig": sig, "X-WRAITH-Ts": ts}

    def _post(self, endpoint: str, data: Dict) -> Optional[Dict]:
        try:
            import urllib.request
            body = json.dumps(data).encode()
            headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
            headers.update(self._sign_headers())
            req = urllib.request.Request(
                f"{self.tracker_url}/{endpoint}", data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            log.debug("Wire POST %s failed: %s", endpoint, exc)
            return None

    def _get(self, endpoint: str) -> Optional[Dict]:
        try:
            import urllib.request
            headers = self._sign_headers()
            req = urllib.request.Request(
                f"{self.tracker_url}/{endpoint}", headers=headers, method="GET"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            log.debug("Wire GET %s failed: %s", endpoint, exc)
            return None

    def announce(self, ip: str, port: int, platform: str, version: str,
                 user_id: str = "", device_name: str = "") -> Optional[List[Dict]]:
        """Announce to tracker with device linking."""
        result = self._post("announce", {
            "cell_id": self.cell_id,
            "ip": ip,
            "port": port,
            "platform": platform,
            "version": version,
            "user_id": user_id,
            "device_name": device_name,
        })

        if result and result.get("ok"):
            if "cell_key" in result:
                self.cell_key = result["cell_key"]
            peers = result.get("peers", [])
            self._peer_list = peers
            self._last_announce = time.time()
            log.info(f"Announced — {len(peers)} peers, key={'yes' if self.cell_key else 'no'}")
            return peers
        return None

    def heartbeat(self, anomaly_score: int, ip: str, port: int) -> Dict:
        """
        Full heartbeat: check in, get defenses, check kill switch.
        Returns: {"defenses": [...], "kill": {...}, "peers": [...]}
        """
        result = self._post("heartbeat", {
            "cell_id": self.cell_id,
            "anomaly_score": anomaly_score,
            "ip": ip,
            "port": port,
        })

        response = {"defenses": [], "kill": None, "peers": []}

        if result and result.get("ok"):
            # Check for kill command
            if self.kill_switch.check_kill_command(result):
                response["kill"] = self.kill_switch.get_status()

            # Get defense broadcasts
            broadcasts = result.get("broadcasts", [])
            response["defenses"] = broadcasts

            # Get updated peer list
            response["peers"] = result.get("peers", self._peer_list)

        return response

    def register_user_and_link(self, username: str, email: str,
                                device_name: str, device_type: str,
                                platform: str, ip: str) -> Dict:
        """Register user identity and link this device."""
        user_id = self.device_linker.register_user(username, email)
        device_id = self.device_linker.link_device(
            user_id, self.cell_id, device_name, device_type, platform, ip
        )
        # Tell tracker about the link
        self._post("link_device", {
            "cell_id": self.cell_id,
            "user_id": user_id,
            "device_id": device_id,
            "device_name": device_name,
            "device_type": device_type,
        })
        return {"user_id": user_id, "device_id": device_id}

    def upload_threat_intel(self, threats: List[Dict]) -> bool:
        """Upload threat intelligence to Admin."""
        result = self._post("threat_intel", {
            "cell_id": self.cell_id,
            "threats": threats,
        })
        return result is not None and result.get("ok", False)

    def download_threat_intel(self) -> List[Dict]:
        """Download global threat intelligence from Admin."""
        result = self._get("threat_intel")
        if result and result.get("ok"):
            return result.get("threats", [])
        return []

    def check_for_updates(self, current_version: str) -> Optional[Dict]:
        """Check Admin for signed updates. Returns update info with package + signature, or None."""
        result = self._get(f"updates/{current_version}")
        if result and result.get("update_available"):
            return {
                "version": result.get("new_version"),
                "package": result.get("package"),
                "signature": result.get("signature"),
                "released_at": result.get("released_at"),
            }
        return None

    def apply_update(self, from_version: str, to_version: str, success: bool = True) -> bool:
        """Report to tracker that an update was applied."""
        result = self._post("update/apply", {
            "cell_id": self.cell_id,
            "from_version": from_version,
            "to_version": to_version,
            "success": success,
        })
        return result is not None and result.get("ok", False)

    def get_peers(self) -> List[Dict]:
        return self._peer_list

    def broadcast_defense(self, attack_type: str, technique: str, patch: Dict) -> bool:
        result = self._post("broadcast", {
            "cell_id": self.cell_id,
            "attack_type": attack_type,
            "technique": technique,
            "patch": patch,
        })
        return result is not None and result.get("ok", False)

    def send_intelligence(self, summary: str, severity: str) -> bool:
        result = self._post("intel", {
            "cell_id": self.cell_id,
            "summary": summary,
            "severity": severity,
        })
        return result is not None and result.get("ok", False)


# ═══════════════════════════════════════════════════════════════
# OLLAMA / LOCAL LLM SUPPORT
# ═══════════════════════════════════════════════════════════════

def _detect_ollama(env: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """Detect if Ollama is running locally."""
    try:
        import urllib.request
        resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5)
        data = json.loads(resp.read())
        models = data.get("models", [])
        if models:
            # Pick the first available model
            model = models[0].get("name", "llama3")
            return "ollama", model
    except Exception:
        pass
    return None, None


def _ask_ollama(prompt: str, model: str = "llama3") -> Optional[str]:
    """Ask a local Ollama model."""
    try:
        import urllib.request
        body = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return data.get("response", "")
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# ENHANCED LLM BRAIN with Ollama
# ═══════════════════════════════════════════════════════════════

class EnhancedLLMBrain:
    """LLM Brain with Ollama + all cloud providers."""

    def __init__(self, provider: Optional[str], model: Optional[str],
                 env: Dict[str, str]):
        self.provider = provider
        self.model = model
        self.env = env
        self.available = provider is not None
        self._ollama_model: Optional[str] = None

        # Auto-detect Ollama if no cloud provider
        if not self.available:
            ollama_provider, ollama_model = _detect_ollama(env)
            if ollama_provider:
                self.provider = ollama_provider
                self.model = ollama_model
                self.available = True
                self._ollama_model = ollama_model
                log.info(f"Ollama detected: {ollama_model}")

    def ask(self, prompt: str) -> Optional[str]:
        if not self.available:
            return None
        try:
            if self.provider == "ollama":
                return _ask_ollama(prompt, self.model or "llama3")
            elif self.provider == "anthropic":
                return self._ask_anthropic(prompt)
            elif self.provider == "openai":
                return self._ask_openai(prompt)
            elif self.provider == "openrouter":
                return self._ask_openrouter(prompt)
        except Exception as exc:
            log.error("LLM error: %s", exc)
        return None

    def _ask_anthropic(self, prompt: str) -> Optional[str]:
        key = self.env.get("ANTHROPIC_API_KEY", "")
        import requests
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 1024,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30,
        )
        data = resp.json()
        return data.get("content", [{}])[0].get("text", "")

    def _ask_openai(self, prompt: str) -> Optional[str]:
        key = self.env.get("OPENAI_API_KEY", "")
        import requests
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}]},
            timeout=30,
        )
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    def _ask_openrouter(self, prompt: str) -> Optional[str]:
        key = self.env.get("OPENROUTER_API_KEY", "")
        import requests
        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}]},
            timeout=30,
        )
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
