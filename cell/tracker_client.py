#!/usr/bin/env python3
"""
WRAITH Cell v4.0 — Tracker Client (Torrent-Style P2P)
=======================================================
Each cell talks to the Admin tracker AND directly to other cells.

Protocol (like BitTorrent):
1. ANNOUNCE → Tell tracker "I'm here, give me peers"
2. GET PEERS → Tracker returns list of active cells
3. PEER CONNECT → Cell connects directly to other cells (P2P)
4. BROADCAST → Cell shares attack intelligence with all peers
5. QUEUE → If tracker/cell unreachable, queue locally in SQLite

If tracker goes down:
- Cells keep talking to known peers directly
-Cells find new peers via DHT-like UDP broadcast
- Reports queue locally and sync when tracker is back
"""

from __future__ import annotations

import os
import sys
import json
import time
import hashlib
import hmac
import sqlite3
import threading
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

CELL_HOME = Path.home() / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
QUEUE_DB = CELL_HOME / "queue.db"

import logging
log = logging.getLogger("wraith-cell-tracker")


# ═══════════════════════════════════════════════════════════════
# LOCAL QUEUE — SQLite store for when tracker/peers are unreachable
# ═══════════════════════════════════════════════════════════════

class LocalQueue:
    """Queues reports/broadcasts locally when network is unavailable."""

    def __init__(self, db_path: Path = QUEUE_DB):
        self.db_path = str(db_path)
        self._local = threading.local()
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
                CREATE TABLE IF NOT EXISTS report_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    synced INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS defense_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    broadcast_id TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    patch_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    from_cell TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    installed INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS peer_cache (
                    cell_id TEXT PRIMARY KEY,
                    ip TEXT,
                    port INTEGER,
                    last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_report_synced ON report_queue(synced);
            """)

    def queue_report(self, report_type: str, payload: Dict):
        with self._conn as c:
            c.execute(
                "INSERT INTO report_queue (report_type, payload_json, created_at) VALUES (?, ?, ?)",
                (report_type, json.dumps(payload), datetime.now().isoformat())
            )

    def get_unsynced_reports(self, limit: int = 50) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM report_queue WHERE synced=0 ORDER BY id LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_synced(self, ids: List[int]):
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._conn as c:
            c.execute(f"UPDATE report_queue SET synced=1 WHERE id IN ({placeholders})", ids)

    def queue_defense(self, broadcast_id: str, attack_type: str, technique: str,
                      patch_json: str, signature: str, from_cell: str):
        with self._conn as c:
            c.execute("""
                INSERT OR IGNORE INTO defense_queue
                (broadcast_id, attack_type, technique, patch_json, signature, from_cell, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (broadcast_id, attack_type, technique, patch_json, signature,
                  from_cell, datetime.now().isoformat()))

    def get_queued_defenses(self) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM defense_queue WHERE installed=0 ORDER BY id LIMIT 20"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_defense_installed(self, broadcast_ids: List[str]):
        if not broadcast_ids:
            return
        placeholders = ",".join("?" * len(broadcast_ids))
        with self._conn as c:
            c.execute(f"UPDATE defense_queue SET installed=1 WHERE broadcast_id IN ({placeholders})",
                      broadcast_ids)

    def cache_peer(self, cell_id: str, ip: str, port: int):
        with self._conn as c:
            c.execute("""
                INSERT OR REPLACE INTO peer_cache (cell_id, ip, port, last_seen)
                VALUES (?, ?, ?, ?)
            """, (cell_id, ip, port, datetime.now().isoformat()))

    def get_cached_peers(self, limit: int = 20) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM peer_cache ORDER BY last_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def flush_old(self, days: int = 7):
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._conn as c:
            c.execute("DELETE FROM report_queue WHERE synced=1 AND created_at < ?", (cutoff,))
            c.execute("DELETE FROM defense_queue WHERE installed=1 AND created_at < ?", (cutoff,))


# ═══════════════════════════════════════════════════════════════
# TRACKER CLIENT — Talks to Admin tracker
# ═══════════════════════════════════════════════════════════════

class TrackerClient:
    """
    Torrent-style tracker client.
    Announces to tracker, gets peers, broadcasts defenses.
    """

    def __init__(self, cell_id: str, tracker_host: str = "localhost",
                 tracker_port: int = 7734):
        self.cell_id = cell_id
        self.tracker_url = f"http://{tracker_host}:{tracker_port}"
        self.cell_key: Optional[str] = None
        self.queue = LocalQueue()
        self._peer_list: List[Dict] = []
        self._last_announce = 0.0

    def _sign_headers(self) -> Dict[str, str]:
        """Sign request headers with cell key."""
        ts = str(int(time.time()))
        key = self.cell_key or ""
        sig = hmac.new(key.encode(), f"{self.cell_id}:{ts}".encode(),
                       hashlib.sha256).hexdigest()
        return {"X-WRAITH-Cell": self.cell_id, "X-WRAITH-Sig": sig, "X-WRAITH-Ts": ts}

    def _post(self, endpoint: str, data: Dict) -> Optional[Dict]:
        try:
            import urllib.request
            body = json.dumps(data).encode()
            headers = {"Content-Type": "application/json",
                       "Content-Length": str(len(body))}
            headers.update(self._sign_headers())
            req = urllib.request.Request(
                f"{self.tracker_url}/{endpoint}",
                data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            log.debug("Tracker POST %s failed: %s", endpoint, exc)
            return None

    def _get(self, endpoint: str) -> Optional[Dict]:
        try:
            import urllib.request
            headers = self._sign_headers()
            req = urllib.request.Request(
                f"{self.tracker_url}/{endpoint}",
                headers=headers, method="GET"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            log.debug("Tracker GET %s failed: %s", endpoint, exc)
            return None

    def announce(self, ip: str, port: int, platform: str,
                 version: str) -> Optional[List[Dict]]:
        """
        Announce to tracker (like torrent announce).
        Returns peer list or None if tracker unreachable.
        """
        result = self._post("announce", {
            "cell_id": self.cell_id,
            "ip": ip,
            "port": port,
            "platform": platform,
            "version": version,
        })

        if result and result.get("ok"):
            if "cell_key" in result:
                self.cell_key = result["cell_key"]
            peers = result.get("peers", [])
            # Cache peers locally
            for p in peers:
                self.queue.cache_peer(p["cell_id"], p.get("ip", ""), p.get("port", 7737))
            self._peer_list = peers
            self._last_announce = time.time()
            log.info(f"Announced to tracker — got {len(peers)} peers")
            return peers
        else:
            log.warning("Announce failed — tracker unreachable")
            return None

    def heartbeat(self, anomaly_score: int, ip: str,
                  port: int) -> Optional[List[Dict]]:
        """
        Heartbeat to tracker. Returns new defense broadcasts.
        Also syncs any queued reports.
        """
        result = self._post("heartbeat", {
            "cell_id": self.cell_id,
            "anomaly_score": anomaly_score,
            "ip": ip,
            "port": port,
        })

        if result and result.get("ok"):
            # Got new defense broadcasts
            broadcasts = result.get("broadcasts", [])
            for b in broadcasts:
                self.queue.queue_defense(
                    broadcast_id=b.get("broadcast_id", ""),
                    attack_type=b.get("attack_type", "unknown"),
                    technique=b.get("technique", "unknown"),
                    patch_json=json.dumps(b.get("patch_json", {})),
                    signature=b.get("signature", ""),
                    from_cell=b.get("from_cell", ""),
                )

            # Sync queued reports
            self._sync_reports()
            return broadcasts

        else:
            # Tracker down — queue locally
            log.debug("Heartbeat failed — tracker may be down")
            return None

    def get_peers(self) -> Optional[List[Dict]]:
        """Get peer list from tracker."""
        result = self._get("peers")
        if result and result.get("ok"):
            peers = result.get("peers", [])
            for p in peers:
                self.queue.cache_peer(p["cell_id"], p.get("ip", ""), p.get("port", 7737))
            self._peer_list = peers
            return peers
        return None

    def broadcast_defense(self, attack_type: str, technique: str,
                          patch: Dict) -> bool:
        """Broadcast a defense to all peers via tracker."""
        patch_json = json.dumps(patch)
        sig = hmac.new(
            (self.cell_key or "").encode(), patch_json.encode(), hashlib.sha256
        ).hexdigest()

        result = self._post("broadcast", {
            "cell_id": self.cell_id,
            "attack_type": attack_type,
            "technique": technique,
            "patch": patch,
            "signature": sig,
        })

        if result and result.get("ok"):
            log.info(f"Broadcast sent: {attack_type}/{technique}")
            return True
        else:
            log.warning("Broadcast failed — tracker unreachable")
            return False

    def send_intelligence(self, summary: str, severity: str) -> bool:
        """Send summarized intelligence to tracker."""
        result = self._post("intel", {
            "cell_id": self.cell_id,
            "summary": summary,
            "severity": severity,
        })
        return result is not None and result.get("ok", False)

    def get_queued_defenses(self) -> List[Dict]:
        """Get defenses from local queue (to install)."""
        return self.queue.get_queued_defenses()

    def install_defenses(self, installed_ids: List[str]):
        """Mark defenses as installed."""
        self.queue.mark_defense_installed(installed_ids)

    def _sync_reports(self):
        """Sync queued reports to tracker."""
        reports = self.queue.get_unsynced_reports()
        if not reports:
            return
        synced = []
        for r in reports:
            if self.send_intelligence(
                summary=f"[{r['report_type']}] {r['payload_json'][:200]}",
                severity="medium"
            ):
                synced.append(r["id"])
        if synced:
            self.queue.mark_synced(synced)
            log.info(f"Synced {len(synced)} queued reports")

    def get_known_peers(self) -> List[Dict]:
        """Get known peers (from tracker or local cache)."""
        if self._peer_list:
            return self._peer_list
        return self.queue.get_cached_peers()


# ═══════════════════════════════════════════════════════════════
# P2P PEER CLIENT — Direct cell-to-cell communication
# ═══════════════════════════════════════════════════════════════

class P2PClient:
    """
    Direct P2P communication between cells (like torrent peers).
    Bypasses tracker — cells talk directly to each other.
    """

    def __init__(self, cell_id: str, listen_port: int = 7737):
        self.cell_id = cell_id
        self.listen_port = listen_port
        self._peers: Dict[str, Tuple[str, int]] = {}  # cell_id -> (ip, port)
        self._running = False
        self._server_thread = None

    def start(self):
        """Start P2P listener."""
        self._running = True
        self._server_thread = threading.Thread(target=self._listen, daemon=True)
        self._server_thread.start()
        log.info(f"P2P listener on port {self.listen_port}")

    def stop(self):
        self._running = False

    def add_peer(self, cell_id: str, ip: str, port: int):
        self._peers[cell_id] = (ip, port)
        log.debug(f"Peer added: {cell_id[:12]} @ {ip}:{port}")

    def _listen(self):
        """Listen for incoming P2P connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.listen_port))
            sock.listen(5)
            sock.settimeout(2.0)
            while self._running:
                try:
                    conn, addr = sock.accept()
                    t = threading.Thread(target=self._handle_peer,
                                         args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
            sock.close()
        except Exception as exc:
            log.warning(f"P2P listener error: {exc}")

    def _handle_peer(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle incoming P2P message from another cell."""
        try:
            data = conn.recv(4096)
            if data:
                msg = json.loads(data)
                msg_type = msg.get("type", "")
                if msg_type == "defense_broadcast":
                    log.info(f"P2P defense from {msg.get('from_cell', 'unknown')[:12]}: "
                             f"{msg.get('attack_type')}/{msg.get('technique')}")
                    # Store in local queue for installation
                    queue = LocalQueue()
                    patch = msg.get("patch", {})
                    patch_json = json.dumps(patch)
                    queue.queue_defense(
                        broadcast_id=msg.get("broadcast_id", ""),
                        attack_type=msg.get("attack_type", "unknown"),
                        technique=msg.get("technique", "unknown"),
                        patch_json=patch_json,
                        signature=msg.get("signature", ""),
                        from_cell=msg.get("from_cell", ""),
                    )
                    conn.sendall(json.dumps({"ok": True}).encode())
                elif msg_type == "ping":
                    conn.sendall(json.dumps({"ok": True, "cell_id": self.cell_id}).encode())
                else:
                    conn.sendall(json.dumps({"error": "unknown_type"}).encode())
        except Exception as exc:
            log.debug(f"P2P handle error: {exc}")
        finally:
            conn.close()

    def send_to_peer(self, peer_id: str, msg: Dict) -> bool:
        """Send a message directly to a peer."""
        if peer_id not in self._peers:
            return False
        ip, port = self._peers[peer_id]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))
            sock.sendall(json.dumps(msg).encode())
            resp = sock.recv(4096)
            sock.close()
            return json.loads(resp).get("ok", False)
        except Exception as exc:
            log.debug(f"P2P send to {peer_id[:12]} failed: {exc}")
            return False

    def broadcast_to_peers(self, attack_type: str, technique: str,
                           patch: Dict, cell_key: str) -> int:
        """Broadcast defense to ALL known peers directly."""
        patch_json = json.dumps(patch)
        sig = hmac.new(
            (cell_key or "").encode(), patch_json.encode(), hashlib.sha256
        ).hexdigest()

        broadcast_id = hashlib.sha256(
            f"{self.cell_id}:{time.time()}:{patch_json}".encode()
        ).hexdigest()[:16]

        msg = {
            "type": "defense_broadcast",
            "from_cell": self.cell_id,
            "broadcast_id": broadcast_id,
            "attack_type": attack_type,
            "technique": technique,
            "patch": patch,
            "signature": sig,
        }

        sent = 0
        for peer_id in list(self._peers.keys()):
            if self.send_to_peer(peer_id, msg):
                sent += 1

        log.info(f"P2P broadcast to {sent}/{len(self._peers)} peers: "
                 f"{attack_type}/{technique}")
        return sent


# ═══════════════════════════════════════════════════════════════
# DHT DISCOVERY — Find peers without tracker (like torrent DHT)
# ═══════════════════════════════════════════════════════════════

class DHTDiscovery:
    """
    UDP-based peer discovery when tracker is unreachable.
    Broadcasts on local network to find other WRAITH cells.
    """

    DHT_PORT = 7736
    MAGIC = b"WRAITH_DHT_v4"

    def __init__(self, cell_id: str, p2p_port: int = 7737):
        self.cell_id = cell_id
        self.p2p_port = p2p_port
        self._running = False
        self._discovered: Dict[str, Tuple[str, int, float]] = {}  # cell_id -> (ip, port, last_seen)

    def start(self):
        self._running = True
        # Listener
        t1 = threading.Thread(target=self._listen, daemon=True)
        t1.start()
        # Periodic broadcaster
        t2 = threading.Thread(target=self._broadcast_loop, daemon=True)
        t2.start()
        log.info("DHT discovery started")

    def stop(self):
        self._running = False

    def _listen(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.DHT_PORT))
            sock.settimeout(2.0)
            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data.startswith(self.MAGIC):
                        self._handle_discovery(data, addr)
                except socket.timeout:
                    continue
            sock.close()
        except Exception as exc:
            log.debug(f"DHT listen error: {exc}")

    def _handle_discovery(self, data: bytes, addr: Tuple[str, int]):
        try:
            msg = json.loads(data[len(self.MAGIC):])
            sender_id = msg.get("cell_id", "")
            sender_port = msg.get("p2p_port", 7737)
            if sender_id and sender_id != self.cell_id:
                self._discovered[sender_id] = (addr[0], sender_port, time.time())
                log.debug(f"DHT discovered: {sender_id[:12]} @ {addr[0]}:{sender_port}")
        except (json.JSONDecodeError, KeyError):
            pass

    def _broadcast_loop(self):
        """Broadcast presence on local network every 30 seconds."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            msg = self.MAGIC + json.dumps({
                "cell_id": self.cell_id,
                "p2p_port": self.p2p_port,
                "ts": time.time(),
            }).encode()
            while self._running:
                try:
                    sock.sendto(msg, ("255.255.255.255", self.DHT_PORT))
                except Exception:
                    pass
                time.sleep(30)
            sock.close()
        except Exception as exc:
            log.debug(f"DHT broadcast error: {exc}")

    def get_discovered_peers(self) -> List[Dict]:
        """Get peers discovered via DHT."""
        now = time.time()
        # Filter: only seen in last 5 minutes
        active = [
            {"cell_id": cid, "ip": ip, "port": port}
            for cid, (ip, port, last_seen) in self._discovered.items()
            if now - last_seen < 300
        ]
        return active
