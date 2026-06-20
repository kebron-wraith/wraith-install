"""WRAITH Cell v4.0 — Immutable Audit Log Agent."""
from __future__ import annotations
import logging, time, json, hashlib, os
from typing import Any

_LOG = logging.getLogger("wraith.ledger")

class LedgerAgent:
    """Maintains a tamper-evident, append-only audit log using hash chains."""

    def __init__(self, config: dict) -> None:
        self.config    = config
        self.active    = False
        self.log_file  = config.get("log_file", "./wraith_audit.chain")
        self._entries: list[dict] = []
        self._last_hash = "GENESIS"
        _LOG.info("LedgerAgent initialized (file=%s).", self.log_file)

    def start(self) -> None:
        self.active = True
        _LOG.info("LedgerAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("LedgerAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Verify the integrity of the audit chain."""
        try:
            corrupted = self._verify_chain()
            return {"status": "ok", "entries": len(self._entries),
                    "chain_valid": not corrupted,
                    "corrupted_at": corrupted}
        except Exception as exc:
            _LOG.error("scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze audit patterns for suspicious admin activity."""
        try:
            valid = data.get("chain_valid", True)
            return {"audit_integrity": "verified" if valid else "COMPROMISED",
                    "total_entries": len(self._entries),
                    "action": "alert_admin" if not valid else "none"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {"agent": "Ledger", "active": self.active, "entries": len(self._entries),
                "current_hash": self._last_hash}

    def append(self, event: dict) -> str:
        """Append an entry to the immutable chain. Returns the entry hash."""
        entry = {
            "index": len(self._entries),
            "timestamp": time.time(),
            "event": event,
            "prev_hash": self._last_hash,
        }
        raw = json.dumps(entry, sort_keys=True).encode()
        entry_hash = hashlib.sha256(raw).hexdigest()
        entry["hash"] = entry_hash
        self._entries.append(entry)
        self._last_hash = entry_hash
        return entry_hash

    def _verify_chain(self) -> int:
        """Returns -1 if valid, or the index of first corruption."""
        for i, entry in enumerate(self._entries):
            if i == 0:
                continue
            expected = self._entries[i - 1]["hash"]
            if entry.get("prev_hash") != expected:
                return i
        return -1
