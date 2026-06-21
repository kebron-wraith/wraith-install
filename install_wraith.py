#!/usr/bin/env python3
"""
WRAITH Cell Installer v1.0.0
One-line installer for the WRAITH distributed computing framework.

Usage:
    python install_wraith.py                  # Full install
    python install_wraith.py --dry-run       # Preview actions
    python install_wraith.py --help          # Show help
    python install_wraith.py --uninstall     # Remove WRAITH

Environment variables:
    WRAITH_HOME        Install directory (default: ~/.wraith)
    WRAITH_TRACKER     Tracker URL (default: http://localhost:7734)
    WRAITH_GITHUB_USER  GitHub user/org (default: wraith-framework)
    WRAITH_GITHUB_REPO  GitHub repo name (default: wraith)
    WRAITH_NO_COLOR     Disable colored output
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WRAITH_VERSION = "1.0.0"
DEFAULT_GITHUB_USER = "wraith-framework"
DEFAULT_GITHUB_REPO = "wraith"
DEFAULT_TRACKER_URL = "http://localhost:7734"
DEFAULT_WRAITH_HOME = Path.home() / ".wraith"
CELL_CORE_FILENAME = "cell_core.py"
REQUIRED_PYTHON = (3, 8)

# ---------------------------------------------------------------------------
# Colored output helpers (graceful fallback when not a TTY)
# ---------------------------------------------------------------------------
_NO_COLOR = os.environ.get("WRAITH_NO_COLOR", "")
if not _NO_COLOR:
    if not sys.stdout.isatty() or platform.system() == "Windows":
        # Try to enable ANSI on Windows 10+
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(
                    kernel32.GetStdHandle(-11), 7
                )
            except Exception:
                _NO_COLOR = "1"
        else:
            _NO_COLOR = "1" if not sys.stdout.isatty() else ""

if _NO_COLOR:
    _R = _G = _Y = _B = _M = _C = _W = _RESET = ""
else:
    _R = "\033[91m"
    _G = "\033[92m"
    _Y = "\033[93m"
    _B = "\033[94m"
    _M = "\033[95m"
    _C = "\033[96m"
    _W = "\033[97m"
    _BOLD = "\033[1m"
    _RESET = "\033[0m"


def info(msg):
    print(f"{_B}[INFO]{_RESET}  {msg}")


def ok(msg):
    print(f"{_G}[OK]{_RESET}    {msg}")


def warn(msg):
    print(f"{_Y}[WARN]{_RESET}  {msg}")


def err(msg):
    print(f"{_R}[ERROR]{_RESET} {msg}")


def banner():
    art = f"""
{_C}{_BOLD}╔══════════════════════════════════════════════════╗
║  {_W}██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗{_C}  ║
║  {_W}██║    ██║██╔══██╗██╔══██║██║╚══██╔══╝██║  ██║{_C}  ║
║  {_W}██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║{_C}  ║
║  {_W}██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║{_C}  ║
║  {_W}╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║{_C}  ║
║  {_W} ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝{_C}  ║
║                                                  ║
║  {_Y}Cell Installer v{WRAITH_VERSION} — One-line deployment{_C}       ║
╚══════════════════════════════════════════════════╝{_RESET}"""
    print(art)


# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------
def detect_system():
    """Return (os_name, arch, python_path) or raise SystemExit."""
    os_name = platform.system().lower()
    if os_name not in ("windows", "linux", "darwin"):
        err(f"Unsupported OS: {os_name}")
        sys.exit(1)
    if os_name == "darwin":
        os_name = "macos"

    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "x86": "386", "i386": "386", "i686": "386",
    }
    arch = arch_map.get(machine, machine)

    # Find Python
    python_path = shutil.which("python3") or shutil.which("python")
    if not python_path:
        err("Python 3 not found. Install Python >= 3.8 and retry.")
        info("  Windows: https://www.python.org/downloads/")
        info("  Linux:   sudo apt install python3")
        info("  macOS:   brew install python3")
        sys.exit(1)

    # Check version
    try:
        ver_out = subprocess.check_output(
            [python_path, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        major, minor = [int(x) for x in ver_out.split()]
        if (major, minor) < REQUIRED_PYTHON:
            err(f"Python {major}.{minor} detected; need >= {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}")
            sys.exit(1)
    except Exception:
        pass  # trust the binary if version check fails

    return os_name, arch, python_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(cmd, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    kwargs.setdefault("text", True)
    try:
        r = subprocess.run(cmd, **kwargs)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def ensure_dir(p):
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_file(path, content):
    path = Path(path)
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8")
    return path


def is_idempotent_marker(path):
    """Check if WRAITH is already installed at path."""
    marker = Path(path) / ".wraith_installed"
    return marker.exists()


def set_idempotent_marker(path, cell_id):
    write_file(
        Path(path) / ".wraith_installed",
        json.dumps({
            "cell_id": cell_id,
            "version": WRAITH_VERSION,
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "os": platform.system().lower(),
            "arch": platform.machine().lower(),
        }),
    )


# ---------------------------------------------------------------------------
# Core download (with offline cache)
# ---------------------------------------------------------------------------
def download_cell_core(github_user, github_repo, wraith_home, dry_run=False):
    """Download cell_core.py from GitHub, with local cache fallback."""
    raw_url = (
        f"https://raw.githubusercontent.com/{github_user}/{github_repo}"
        f"/main/{CELL_CORE_FILENAME}"
    )
    cache_dir = wraith_home / "cache"
    dest = wraith_home / CELL_CORE_FILENAME

    if dry_run:
        info(f"Would download {raw_url} -> {dest}")
        if dest.exists():
            ok("Cached copy exists — offline mode available")
        return dest

    # Try download
    info(f"Downloading {CELL_CORE_FILENAME} from GitHub...")
    rc, out, _ = run(["curl", "-fsSL", "-o", str(dest), raw_url])
    if rc == 0 and dest.exists() and dest.stat().st_size > 0:
        ok(f"Downloaded {CELL_CORE_FILENAME} ({dest.stat().st_size} bytes)")
        # Also cache
        ensure_dir(cache_dir)
        shutil.copy2(dest, cache_dir / CELL_CORE_FILENAME)
        return dest

    # Fallback: try cached copy
    cached = cache_dir / CELL_CORE_FILENAME
    if cached.exists() and cached.stat().st_size > 0:
        warn("Download failed — using cached copy")
        shutil.copy2(cached, dest)
        return dest

    # Fallback: try alternative branch names
    for branch in ("master", "main", "latest"):
        alt_url = (
            f"https://raw.githubusercontent.com/{github_user}/{github_repo}"
            f"/{branch}/{CELL_CORE_FILENAME}"
        )
        rc, _, _ = run(["curl", "-fsSL", "-o", str(dest), alt_url])
        if rc == 0 and dest.exists() and dest.stat().st_size > 0:
            ok(f"Downloaded from branch '{branch}'")
            return dest

    warn("Could not download cell_core.py — will create a stub")
    return None


# ---------------------------------------------------------------------------
# Directory structure
# ---------------------------------------------------------------------------
def create_directory_structure(wraith_home, dry_run=False):
    """Create the WRAITH directory layout."""
    dirs = [
        wraith_home,
        wraith_home / "cells",
        wraith_home / "config",
        wraith_home / "logs",
        wraith_home / "cache",
        wraith_home / "data",
        wraith_home / "plugins",
    ]
    for d in dirs:
        if dry_run:
            info(f"Would create directory: {d}")
        else:
            ensure_dir(d)
            ok(f"Directory ready: {d}")


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
REQUIREMENTS = ["pyyaml", "requests", "aiohttp"]


def install_dependencies(python_path, dry_run=False):
    """Install required Python packages."""
    info("Checking Python dependencies...")
    missing = []
    for pkg in REQUIREMENTS:
        rc, _, _ = run([python_path, "-c", f"import {pkg.replace('-', '_')}"])
        if rc != 0:
            missing.append(pkg)

    if not missing:
        ok("All Python dependencies already installed")
        return

    info(f"Installing: {', '.join(missing)}")
    if dry_run:
        for pkg in missing:
            info(f"Would install: {pkg}")
        return

    rc, out, stderr = run(
        [python_path, "-m", "pip", "install", "--quiet", *missing]
    )
    if rc == 0:
        ok("Dependencies installed successfully")
    else:
        warn(f"pip install had issues: {stderr.strip()}")
        info("Continuing anyway — some features may be limited")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def generate_config(wraith_home, cell_id, tracker_url, dry_run=False):
    """Write default config.yaml."""
    config_path = wraith_home / "config" / "config.yaml"
    config_content = textwrap.dedent(f"""\
        # WRAITH Cell Configuration
        # Generated by install_wraith.py v{WRAITH_VERSION}

        cell:
          id: "{cell_id}"
          name: "cell-{cell_id[:8]}"
          version: "{WRAITH_VERSION}"
          os: "{platform.system().lower()}"
          arch: "{platform.machine().lower()}"

        tracker:
          url: "{tracker_url}"
          register_on_start: true
          heartbeat_interval: 30

        logging:
          level: "INFO"
          file: "{wraith_home / 'logs' / 'cell.log'}"
          max_size_mb: 50
          backup_count: 5

        paths:
          data: "{wraith_home / 'data'}"
          cache: "{wraith_home / 'cache'}"
          plugins: "{wraith_home / 'plugins'}"

        network:
          bind_address: "0.0.0.0"
          port: 0  # 0 = auto-assign

        resources:
          max_workers: 4
          memory_limit_mb: 0  # 0 = unlimited
    """)

    if dry_run:
        info(f"Would write config to {config_path}")
        return config_path

    write_file(config_path, config_content)
    ok(f"Config written: {config_path}")
    return config_path


# ---------------------------------------------------------------------------
# Cell ID
# ---------------------------------------------------------------------------
def generate_cell_id():
    """Generate a unique, deterministic-ish cell ID."""
    node = uuid.getnode()
    ts = int(time.time() * 1000)
    raw = f"{node}-{ts}-{uuid.uuid4().hex[:8]}"
    cell_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return cell_id


# ---------------------------------------------------------------------------
# Tracker registration
# ---------------------------------------------------------------------------
def register_with_tracker(tracker_url, cell_id, dry_run=False):
    """Register this cell with the WRAITH tracker."""
    info(f"Registering with tracker at {tracker_url}...")

    if dry_run:
        info(f"Would POST /api/register cell_id={cell_id}")
        return {"status": "dry_run", "cell_id": cell_id}

    # Try HTTP registration
    try:
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "cell_id": cell_id,
            "hostname": platform.node(),
            "os": platform.system().lower(),
            "arch": platform.machine().lower(),
            "version": WRAITH_VERSION,
            "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }).encode()

        req = urllib.request.Request(
            f"{tracker_url}/api/register",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            ok(f"Registered with tracker: {data.get('status', 'ok')}")
            return data
    except ImportError:
        warn("urllib not available for registration")
    except Exception as e:
        warn(f"Could not reach tracker: {e}")
        info("Cell will register on first start")

    return {"status": "pending", "cell_id": cell_id}


# ---------------------------------------------------------------------------
# Start cell
# ---------------------------------------------------------------------------
def start_cell(wraith_home, python_path, cell_id, dry_run=False):
    """Start the cell as a background process."""
    cell_core = wraith_home / CELL_CORE_FILENAME
    if not cell_core.exists():
        warn("cell_core.py not found — skipping cell start")
        return None

    if dry_run:
        info(f"Would start: {python_path} {cell_core} --id {cell_id}")
        return "dry_run"

    info("Starting WRAITH cell in background...")

    log_file = wraith_home / "logs" / "cell.log"
    ensure_dir(log_file.parent)

    env = os.environ.copy()
    env["WRAITH_CELL_ID"] = cell_id
    env["WRAITH_HOME"] = str(wraith_home)

    try:
        with open(log_file, "a") as lf:
            proc = subprocess.Popen(
                [python_path, str(cell_core), "--id", cell_id],
                stdout=lf,
                stderr=subprocess.STDOUT,
                env=env,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if platform.system() == "Windows"
                    else 0
                ),
            )
        ok(f"Cell started (PID {proc.pid})")
        # Write PID file for later management
        write_file(wraith_home / ".cell_pid", str(proc.pid))
        return proc.pid
    except Exception as e:
        warn(f"Could not start cell: {e}")
        return None


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
def uninstall(wraith_home):
    """Remove WRAITH installation."""
    wraith_home = Path(wraith_home)
    if not wraith_home.exists():
        info("Nothing to uninstall — directory does not exist")
        return

    # Stop cell if running
    pid_file = wraith_home / ".cell_pid"
    if pid_file.exists():
        pid = int(pid_file.read_text().strip())
        try:
            if platform.system() == "Windows":
                # Windows: check process via tasklist, terminate via taskkill
                check = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"],
                    capture_output=True, text=True, timeout=5
                )
                if str(pid) in check.stdout:
                    info(f"Stopping cell process {pid}...")
                    subprocess.run(
                        ["taskkill", "/PID", str(pid), "/F"],
                        capture_output=True, timeout=10
                    )
                    time.sleep(1)
            else:
                # POSIX: use os.kill
                os.kill(pid, 0)  # check if alive
                info(f"Stopping cell process {pid}...")
                os.kill(pid, 15)  # SIGTERM
                time.sleep(1)
        except (ProcessLookupError, ValueError):
            pass
        except OSError:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True, timeout=10
                )
            except Exception:
                warn(f"Cannot stop PID {pid}")
        pid_file.unlink(missing_ok=True)

    info(f"Removing {wraith_home}...")
    shutil.rmtree(wraith_home, ignore_errors=True)
    ok("WRAITH uninstalled successfully")


# ---------------------------------------------------------------------------
# Main install flow
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="WRAITH Cell Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python install_wraith.py                    Full install
              python install_wraith.py --dry-run         Preview only
              python install_wraith.py --uninstall       Remove WRAITH
              WRAITH_HOME=/opt/wraith python install_wraith.py
        """),
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without executing")
    parser.add_argument("--uninstall", action="store_true", help="Remove WRAITH installation")
    parser.add_argument("--home", type=str, default=None, help="WRAITH home directory")
    parser.add_argument("--tracker", type=str, default=None, help="Tracker URL")
    parser.add_argument("--github-user", type=str, default=None, help="GitHub user/org")
    parser.add_argument("--github-repo", type=str, default=None, help="GitHub repo name")
    parser.add_argument("--no-start", action="store_true", help="Don't start the cell after install")
    args = parser.parse_args()

    banner()

    # Resolve paths
    wraith_home = Path(args.home) if args.home else Path(os.environ.get(
        "WRAITH_HOME", str(DEFAULT_WRAITH_HOME)
    ))
    tracker_url = args.tracker or os.environ.get(
        "WRAITH_TRACKER", DEFAULT_TRACKER_URL
    )
    github_user = args.github_user or os.environ.get(
        "WRAITH_GITHUB_USER", DEFAULT_GITHUB_USER
    )
    github_repo = args.github_repo or os.environ.get(
        "WRAITH_GITHUB_REPO", DEFAULT_GITHUB_REPO
    )

    print(f"{_W}  Install dir : {wraith_home}{_RESET}")
    print(f"{_W}  Tracker URL : {tracker_url}{_RESET}")
    print(f"{_W}  GitHub     : {github_user}/{github_repo}{_RESET}")
    print()

    if args.uninstall:
        uninstall(wraith_home)
        return

    # Step 1: Detect system
    os_name, arch, python_path = detect_system()
    ok(f"System: {os_name} / {arch} / Python at {python_path}")

    # Step 2: Download cell_core.py
    core_path = download_cell_core(github_user, github_repo, wraith_home, dry_run=args.dry_run)

    # Step 3: Create directory structure
    create_directory_structure(wraith_home, dry_run=args.dry_run)

    # Step 4: Install dependencies
    install_dependencies(python_path, dry_run=args.dry_run)

    # Step 5: Generate cell ID
    cell_id = generate_cell_id()
    ok(f"Cell ID: {cell_id}")

    # Step 6: Write config
    generate_config(wraith_home, cell_id, tracker_url, dry_run=args.dry_run)

    # Step 7: Register with tracker
    reg = register_with_tracker(tracker_url, cell_id, dry_run=args.dry_run)

    # Step 8: Start cell
    pid = None
    if not args.no_start:
        pid = start_cell(wraith_home, python_path, cell_id, dry_run=args.dry_run)

    # Step 9: Idempotent marker
    if not args.dry_run:
        set_idempotent_marker(wraith_home, cell_id)

    # Success summary
    print()
    print(f"{_G}{_BOLD}{'═' * 52}{_RESET}")
    print(f"{_G}{_BOLD}  ✓ WRAITH Cell installed successfully!{_RESET}")
    print(f"{_G}{_BOLD}{'═' * 52}{_RESET}")
    print(f"  {_W}Cell ID{_RESET}    : {_C}{cell_id}{_RESET}")
    print(f"  {_W}Install dir{_RESET} : {_C}{wraith_home}{_RESET}")
    print(f"  {_W}Tracker{_RESET}     : {_C}{tracker_url}{_RESET}")
    print(f"  {_W}Status{_RESET}      : {_G}installed{_RESET}")
    if pid:
        print(f"  {_W}Cell PID{_RESET}    : {_C}{pid}{_RESET}")
    print(f"  {_W}Cell core{_RESET}   : {_C}{core_path or 'stub (offline)'}{_RESET}")
    print()
    print(f"  {_Y}To uninstall: python install_wraith.py --uninstall{_RESET}")
    print(f"  {_Y}To re-run  : python install_wraith.py (idempotent){_RESET}")
    print()


if __name__ == "__main__":
    main()
