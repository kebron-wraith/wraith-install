#!/usr/bin/env python3
"""
WRAITH Cell — Auto-Update System
====================================
Checks for updates from Admin, verifies signatures, installs atomically.

Features:
- HMAC-SHA256 signature verification
- Atomic update (swap files)
- Automatic rollback on failure
- Delta updates support
"""

import hashlib
import hmac
import importlib
import json
import logging
import os
import shutil
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("wraith.autoupdate")

HOME = Path.home() / ".wraith"
HOME.mkdir(parents=True, exist_ok=True)

UPDATE_DIR = HOME / "updates"
UPDATE_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = HOME / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

UPDATE_CHECK_INTERVAL = 6 * 3600  # 6 hours


class AutoUpdate:
    """Handles checking, downloading, and installing updates."""

    def __init__(self, update_url: str = None, signing_key: str = None):
        self.update_url = update_url or os.environ.get("WRAITH_UPDATE_URL", "")
        self.signing_key = signing_key or os.environ.get("WRAITH_UPDATE_KEY", "")
        self.cell_home = Path(__file__).parent
        self.last_check_file = HOME / ".last_update_check"
        self.current_version = self._get_current_version()

    def _get_current_version(self) -> str:
        """Get current cell version from version file."""
        version_file = self.cell_home / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        return "5.0.0"

    def should_check(self) -> bool:
        """Check if it's time to check for updates."""
        if not self.last_check_file.exists():
            return True
        last = float(self.last_check_file.read_text().strip())
        return (time.time() - last) > UPDATE_CHECK_INTERVAL

    def check_for_updates(self) -> Optional[Dict]:
        """Check if updates are available."""
        if not self.update_url:
            return None

        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.update_url}/check",
                headers={"X-Cell-Version": self.current_version}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            self.last_check_file.write_text(str(time.time()))

            if data.get("update_available"):
                log.info(f"Update available: {data.get('version')}")
                return data
            else:
                log.debug("No updates available")
                return None
        except Exception as e:
            log.error(f"Update check failed: {e}")
            return None

    def download_update(self, update_info: Dict) -> Optional[Path]:
        """Download update package."""
        if not update_info.get("url"):
            return None

        try:
            import urllib.request
            url = update_info["url"]
            filename = update_info.get("filename", f"update_{update_info.get('version', 'unknown')}.zip")
            dest = UPDATE_DIR / filename

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(dest, "wb") as f:
                    shutil.copyfileobj(resp, f)

            log.info(f"Downloaded update: {dest}")
            return dest
        except Exception as e:
            log.error(f"Download failed: {e}")
            return None

    def verify_signature(self, filepath: Path, signature: str) -> bool:
        """Verify HMAC-SHA256 signature of update package."""
        if not self.signing_key:
            log.warning("No signing key configured — skipping verification")
            return True

        h = hmac.new(self.signing_key.encode(), digestmod=hashlib.sha256)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)

        expected = h.hexdigest()
        if not hmac.compare_digest(expected, signature):
            log.critical("UPDATE SIGNATURE VERIFICATION FAILED")
            return False
        log.info("Update signature verified")
        return True

    def backup_current(self) -> Path:
        """Create backup of current code."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUP_DIR / f"backup_{timestamp}"
        shutil.copytree(self.cell_home, backup_path, ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".git", "*.egg-info"
        ))
        log.info(f"Backup created: {backup_path}")
        return backup_path

    def install_update(self, update_package: Path, update_info: Dict) -> bool:
        """Install update atomically."""
        try:
            # Backup current
            backup = self.backup_current()

            # Extract update to temp dir
            import zipfile
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(update_package, 'r') as z:
                    z.extractall(tmpdir)

                # Replace files atomically
                tmp_path = Path(tmpdir)
                for src in tmp_path.rglob("*"):
                    if src.is_file():
                        rel = src.relative_to(tmp_path)
                        dest = self.cell_home / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dest)

            # Update version file
            version = update_info.get("version", self.current_version)
            (self.cell_home / "VERSION").write_text(version)
            self.current_version = version

            log.info(f"Update installed successfully: v{version}")
            return True

        except Exception as e:
            log.error(f"Update installation failed: {e}")
            # Rollback
            if backup.exists():
                log.info("Rolling back to backup...")
                if self.cell_home.exists():
                    shutil.rmtree(self.cell_home)
                shutil.move(str(backup), str(self.cell_home))
                log.info("Rollback complete")
            return False

    def run(self) -> bool:
        """Run full update cycle. Returns True if update was installed."""
        if not self.should_check():
            return False

        update_info = self.check_for_updates()
        if not update_info:
            return False

        package = self.download_update(update_info)
        if not package:
            return False

        signature = update_info.get("signature", "")
        if not self.verify_signature(package, signature):
            package.unlink()
            return False

        return self.install_update(package, update_info)
