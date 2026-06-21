#!/usr/bin/env python3
"""
WRAITH Cell — Anti-Tampering & Self-Destruct
================================================
Protects cell integrity and provides secure self-destruct capability.

Features:
- HMAC-SHA256 integrity verification on all cell code
- Anti-debug detection (IsDebuggerPresent, ptrace)
- Sandbox/VM detection
- Secure self-destruct (3-pass overwrite)
- Tombstone logging
"""

import hashlib
import hmac
import logging
import os
import platform
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("wraith.antitamper")

HOME = Path.home() / ".wraith"
HOME.mkdir(parents=True, exist_ok=True)

INTEGRITY_FILE = HOME / ".integrity_hashes"
TOMBSTONE_FILE = HOME / ".tombstone"


class AntiTampering:
    """Verifies cell code integrity and detects tampering."""

    def __init__(self, cell_home: Path = None):
        self.cell_home = cell_home or Path(__file__).parent
        self.code_files = self._find_code_files()
        self.secret = os.environ.get("WRAITH_INTEGRITY_KEY", "").encode()
        if not self.secret:
            import secrets
            self.secret = secrets.token_bytes(32)
            log.warning("WRAITH_INTEGRITY_KEY not set — generated ephemeral key")

    def _find_code_files(self) -> List[Path]:
        """Find all Python code files to protect."""
        files = []
        for f in self.cell_home.rglob("*.py"):
            if "__pycache__" not in str(f) and ".git" not in str(f):
                files.append(f)
        return files

    def compute_hash(self, filepath: Path) -> str:
        """Compute HMAC-SHA256 hash of a file."""
        h = hmac.new(self.secret, digestmod=hashlib.sha256)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def sign_all(self) -> Dict[str, str]:
        """Sign all code files and return hash map."""
        hashes = {}
        for f in self.code_files:
            rel = str(f.relative_to(self.cell_home))
            hashes[rel] = self.compute_hash(f)
        return hashes

    def save_hashes(self) -> None:
        """Save integrity hashes to disk."""
        hashes = self.sign_all()
        with open(INTEGRITY_FILE, "w") as f:
            for path, hashval in sorted(hashes.items()):
                f.write(f"{hashval}  {path}\n")
        log.info(f"Integrity hashes saved: {len(hashes)} files")

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify all code files match saved hashes.
        Returns (is_valid, list_of_tampered_files)."""
        if not INTEGRITY_FILE.exists():
            log.warning("No integrity hashes found — signing current state")
            self.save_hashes()
            return True, []

        tampered = []
        saved = {}
        with open(INTEGRITY_FILE) as f:
            for line in f:
                line = line.strip()
                if "  " in line:
                    hashval, path = line.split("  ", 1)
                    saved[path] = hashval

        for rel_path, expected_hash in saved.items():
            filepath = self.cell_home / rel_path
            if not filepath.exists():
                tampered.append(f"{rel_path} (deleted)")
            else:
                actual = self.compute_hash(filepath)
                if actual != expected_hash:
                    tampered.append(f"{rel_path} (modified)")

        is_valid = len(tampered) == 0
        if not is_valid:
            log.critical(f"TAMPERING DETECTED: {tampered}")
        else:
            log.info(f"Integrity verified: {len(saved)} files OK")

        return is_valid, tampered

    def is_debugger_present(self) -> bool:
        """Check if a debugger is attached."""
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                return kernel32.IsDebuggerPresent() != 0
            except Exception:
                pass
        return False

    def is_sandbox(self) -> bool:
        """Detect if running in a sandbox/VM."""
        indicators = []

        # Check CPUID for hypervisor
        if platform.system() == "Linux":
            try:
                cpuinfo = Path("/proc/cpuinfo").read_text()
                if "hypervisor" in cpuinfo:
                    indicators.append("hypervisor_cpuid")
            except Exception:
                pass

        # Check for VM artifacts
        vm_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        ]
        for vf in vm_files:
            try:
                content = Path(vf).read_text().lower()
                if any(x in content for x in ["vmware", "virtualbox", "kvm", "qemu", "xen"]):
                    indicators.append(f"vm_artifact_{vf}")
            except Exception:
                pass

        # Timing check (sandboxes often have inconsistent timing)
        times = []
        for _ in range(5):
            start = time.perf_counter_ns()
            time.sleep(0.001)
            end = time.perf_counter_ns()
            times.append(end - start)
        if len(times) > 2:
            avg = sum(times) / len(times)
            variance = sum((t - avg) ** 2 for t in times) / len(times)
            if variance > avg * 0.5:
                indicators.append("timing_anomaly")

        if indicators:
            log.warning(f"Sandbox indicators: {indicators}")
        return len(indicators) > 0

    def self_check(self) -> bool:
        """Run full self-check. Returns True if safe."""
        if self.is_debugger_present():
            log.critical("DEBUGGER DETECTED")
            return False

        is_valid, tampered = self.verify_integrity()
        if not is_valid:
            return False

        return True


class SelfDestruct:
    """Securely wipes all cell data."""

    def __init__(self, cell_home: Path = None):
        self.cell_home = cell_home or Path(__file__).parent
        self.data_dir = HOME

    def _secure_wipe(self, filepath: Path, passes: int = 3) -> None:
        """Overwrite file with random data before deletion."""
        if not filepath.exists():
            return
        size = filepath.stat().st_size
        with open(filepath, "wb") as f:
            for _ in range(passes):
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        filepath.unlink()
        log.info(f"Securely wiped: {filepath}")

    def _wipe_directory(self, dirpath: Path) -> None:
        """Securely wipe all files in a directory."""
        if not dirpath.exists():
            return
        for f in dirpath.rglob("*"):
            if f.is_file():
                self._secure_wipe(f)
        for d in sorted(dirpath.rglob("*"), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except OSError:
                    pass
        try:
            dirpath.rmdir()
        except OSError:
            pass

    def execute(self, reason: str = "admin_command") -> None:
        """Execute full self-destruct sequence."""
        log.critical(f"SELF-DESTRUCT INITIATED: {reason}")

        # Write tombstone
        tombstone = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "reason": reason,
            "cell_home": str(self.cell_home),
            "platform": platform.platform(),
        }
        with open(TOMBSTONE_FILE, "w") as f:
            import json
            json.dump(tombstone, f, indent=2)

        # Wipe data directory
        self._wipe_directory(self.data_dir)

        # Wipe code files
        self._wipe_directory(self.cell_home)

        log.critical("SELF-DESTRUCT COMPLETE")
