#!/usr/bin/env python3
"""
WRAITH v6.1 - Universal Installer
One command to install a full WRAITH Cell on any device.

One-liners:
  Windows:  powershell -c "iwr -useb https://kebron-wraith.github.io/wraith-install/install_wraith.py | iex"
  macOS:    curl -fsSL https://kebron-wraith.github.io/wraith-install/install_wraith.py | python3
  Linux:    curl -fsSL https://kebron-wraith.github.io/wraith-install/install_wraith.py | python3
  Docker:   docker run --rm -it wraithsec/cell:latest

What this installs:
  - Full intelligent cell with 26 security agents
  - AI Provider (user's own LLM - OpenRouter, Anthropic, Ollama, etc.)
  - P2P mesh networking (Biomesh protocol)
  - HoneyPot deception
  - Self-evolution (skills, memory, learning)
"""
import os, sys, platform, subprocess, hashlib, time, json, shutil
from pathlib import Path

INSTALL_DIR = Path.home() / ".wraith" / "cell"
ENV_FILE = Path.home() / ".wraith" / ".env"
REPO = "https://github.com/kebron-wraith/wraith-install.git"
OS = platform.system()


def run(cmd):
    print(f"  > {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0 and r.stderr:
        print(f"  ! {r.stderr.strip()[:150]}")
    return r


def find_python():
    for cmd in ["python3", "python", "py"]:
        r = run(f"{cmd} --version")
        if r.returncode == 0:
            return cmd, r.stdout.strip()
    return None, None


def install_deps(py):
    print("\nInstalling dependencies...")
    for pkg in ["requests", "pyyaml", "python-dotenv"]:
        run(f"{py} -m pip install --quiet {pkg} 2>/dev/null || true")


def download_cell():
    INSTALL_DIR.parent.mkdir(parents=True, exist_ok=True)
    if (INSTALL_DIR / ".git").exists():
        print(f"\nUpdating WRAITH at {INSTALL_DIR}...")
        os.chdir(INSTALL_DIR)
        run("git pull 2>/dev/null || true")
        return
    print(f"\nDownloading WRAITH to {INSTALL_DIR}...")
    r = run(f"git clone --depth 1 {REPO} {INSTALL_DIR}")
    if r.returncode == 0:
        return
    print("  Git not available. Downloading zip...")
    try:
        import urllib.request, zipfile, io
        zip_url = "https://github.com/kebron-wraith/wraith-install/archive/refs/heads/main.zip"
        data = urllib.request.urlopen(zip_url, timeout=120).read()
        z = zipfile.ZipFile(io.BytesIO(data))
        extract_dir = INSTALL_DIR.parent / "wraith-temp"
        z.extractall(extract_dir)
        for item in extract_dir.iterdir():
            if item.is_dir():
                item.rename(INSTALL_DIR)
                break
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        print(f"  Extracted to {INSTALL_DIR}")
    except Exception as e:
        print(f"\nDownload failed: {e}")
        print(f"   Please download manually from: {REPO}")
        sys.exit(1)


def create_env():
    if not ENV_FILE.exists():
        cell_id = "CELL-" + hashlib.sha256(
            f"{platform.node()}:{time.time()}:{os.urandom(8).hex()}".encode()
        ).hexdigest()[:12].upper()
        ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        env_lines = [
            "# WRAITH Cell Configuration",
            f"WRAITH_CELL_ID={cell_id}",
            "# Add your API key (choose one):",
            "# OPENROUTER_API_KEY=***            "# ANTHROPIC_API_KEY=***            "# OPENAI_API_KEY=***            "# GEMINI_API_KEY=***            "# OLLAMA_HOST=http://localhost:11434",
        ]
        ENV_FILE.write_text("\n".join(env_lines) + "\n")
        print(f"\n  Cell ID: {cell_id}")
    else:
        print(f"\n  Config: {ENV_FILE}")


def main():
    print("=" * 45)
    print("  WRAITH v6.1 - Universal Installer")
    print("=" * 45)

    env_name = OS
    if OS == "Linux":
        if "ANDROID_ROOT" in os.environ:
            env_name = "Android (Termux)"
        elif os.path.exists("/.dockerenv"):
            env_name = "Docker"
        elif "WSL_DISTRO_NAME" in os.environ:
            env_name = f"WSL ({os.environ['WSL_DISTRO_NAME']})"

    print(f"  OS: {env_name} ({platform.machine()})")
    print(f"  Python: {sys.version.split()[0]}")

    py, ver = find_python()
    if not py:
        print("\nERROR: Python 3.9+ not found!")
        if OS == "Windows":
            print("   Download from: https://python.org/downloads")
        elif OS == "Darwin":
            print("   Install: brew install python3")
        else:
            print("   Install: your-distro-package-manager python3")
        sys.exit(1)
    print(f"  Using: {py} ({ver})")

    install_deps(py)
    download_cell()
    create_env()

    print()
    print("=" * 45)
    print("  Installation Complete!")
    print("=" * 45)
    print()
    print(f"  Install: {INSTALL_DIR}")
    print(f"  Config:  {ENV_FILE}")
    print()
    print("  Next steps:")
    print(f"    1. Edit {ENV_FILE} and add your API key")
    if OS == "Windows":
        print(f'    2. cd "{INSTALL_DIR}"')
        print(f"    3. {py} -m cell.cell_core")
    else:
        print(f"    2. cd {INSTALL_DIR} && {py} -m cell.cell_core")
    print()


if __name__ == "__main__":
    main()
