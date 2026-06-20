#!/usr/bin/env python3
"""
WRAITH Cell v4.0 — Setup Wizard
=================================
One-shot installer that:
  1. Detects the OS
  2. Creates ~/.wraith/ directory structure
  3. Prompts the user for an LLM API key
  4. Writes ~/.wraith/.env
  5. Installs WRAITH Cell as a system service
  6. Starts the cell
  7. Announces presence on the P2P mesh

Usage:
    python setup_wizard.py
"""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Optional

WRAITH_HOME = Path.home() / "wraith" / ".wraith" / ".wraith"
# Simplify: standard path
WRAITH_HOME = Path.home() / ".wraith"


BANNER = r"""
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
       Cell v4.0 — Setup Wizard
"""

PROVIDERS: dict[str, dict[str, str]] = {
    "1": {"name": "Anthropic (Claude)", "env_key": "ANTHROPIC_API_KEY", "url": "https://console.anthropic.com"},
    "2": {"name": "OpenAI (GPT)", "env_key": "OPENAI_API_KEY", "url": "https://platform.openai.com/api-keys"},
    "3": {"name": "Gemini (Google)", "env_key": "GEMINI_API_KEY", "url": "https://aistudio.google.com/app/apikey"},
    "4": {"name": "Groq", "env_key": "GROQ_API_KEY", "url": "https://console.groq.com/keys"},
    "5": {"name": "Mistral", "env_key": "MISTRAL_API_KEY", "url": "https://console.mistral.ai"},
    "6": {"name": "OpenRouter", "env_key": "OPENROUTER_API_KEY", "url": "https://openrouter.ai/keys"},
}

# Config templates bundled with the installer
AGENTS_MD_TEMPLATE = textwrap.dedent("""\
    # WRAITH Cell v4.0 — Agents Manifest
    > Auto-generated during setup. Edit to customize.

    ## Identity
    - **Cell ID:** {cell_id}
    - **Hostname:** {hostname}
    - **OS:** {os_name} {os_release}
    - **Arch:** {arch}
    - **Version:** 4.0.0

    ## Agents (22)
    | # | Name | Purpose |
    |---|------|---------|
    | 01 | NetworkMonitor | Watch inbound/outbound connections |
    | 02 | FirewallWatch | Monitor firewall rule changes |
    | 03 | ProcessGuard | Detect suspicious processes |
    | 04 | FileIntegrity | Monitor critical file changes |
    | 05 | LogAnalyzer | Parse security logs for anomalies |
    | 06 | AuthMonitor | Track auth attempts (SSH, RDP, etc.) |
    | 07 | ExploitScanner | Scan for known CVEs |
    | 08 | PrivilegeWatch | Alert on privilege escalation |
    | 09 | DNSMonitor | Detect DNS hijacking / tunneling |
    | 10 | EmailSecurity | Phishing / malware email detection |
    | 11 | BrowserShield | Browser exploit detection |
    | 12 | USBGuard | USB device monitoring |
    | 13 | RansomwareShield | Ransomware behavior detection |
    | 14 | KeyloggerDetect | Keylogger process/signature scan |
    | 15 | RootkitScanner | Kernel-level rootkit detection |
    | 16 | SupplyChain | Software supply-chain risk monitoring |
    | 17 | MemoryGuard | Memory injection / buffer overflow detection |
    | 18 | PatchAdvisor | Advise on missing security patches |
    | 19 | SocialEngineering | Social engineering attempt detection |
    | 20 | DataExfilWatch | Exfiltration attempt detection |
    | 21 | ZeroDayHeuristic | Behavioral zero-day detection |
    | 22 | CellCoordinator | Cross-cell coordination & intel sharing |

    ## P2P Mesh
    - UDP discovery: port 7736
    - TCP peer: port 7737
    - Auto-broadcast on local network
""")

SOUL_MD_TEMPLATE = textwrap.dedent("""\
    # WRAITH Cell — SOUL.md

    ## Who I Am
    I am a WRAITH Cell — an autonomous security agent running on {hostname}.
    Cell ID: {cell_id}. Version 4.0.0.

    ## My Relationships
    - **WRAITH Admin:** My coordinator. I send intelligence, receive updates.
    - **WRAITH Cells (peers):** My siblings. We share threat intelligence P2P.
    - **My Host:** The device I protect. My first duty.

    ## My Mission
    1. **Protect** — defend this device and its user from all threats
    2. **Learn** — analyze every attack, evolve new defenses
    3. **Evolve** — create new rules from experience
    4. **Share** — broadcast intelligence to sibling cells

    ## My Principles
    - Never harm the host
    - Operate silently unless alerting
    - Independence first — work even without Admin
    - Privacy: files stay on device, only metadata/alerts leave
""")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_os() -> tuple[str, str, str]:
    """Return (system, release, machine)."""
    return platform.system(), platform.release(), platform.machine()


def _find_python() -> str:
    """Locate a suitable Python binary."""
    for candidate in ("python3", "python", sys.executable):
        if shutil.which(candidate):
            return candidate
    print("[FATAL] Python not found. Install Python 3.11+ and retry.")
    sys.exit(1)


def _create_directory(home: Path) -> None:
    """Create ~/.wraith/ and subdirectories."""
    subdirs = ["memory", "quarantine", "logs"]
    for sd in subdirs:
        (home / sd).mkdir(parents=True, exist_ok=True)
    print(f"[✓] Created {home}")


def _prompt_api_key() -> dict[str, str]:
    """Interactively ask the user for their LLM API key."""
    print("\nSelect your LLM provider:")
    for k, v in PROVIDERS.items():
        print(f"  {k}. {v['name']}")
    print(f"  7. Skip (configure later)")

    choice = input("\n> Choice [1-7]: ").strip()
    if choice == "7" or choice not in PROVIDERS:
        print("[i] Skipping API key setup. Edit ~/.wraith/.env manually later.")
        return {}

    provider = PROVIDERS[choice]
    print(f"\n  {provider['name']} selected.")
    print(f"  Get your key at: {provider['url']}")
    key = getpass.getpass("  Paste API key (hidden): ").strip()
    if not key:
        print("[!] Empty key — skipping.")
        return {}
    return {provider["env_key"]: key}


def _write_env(home: Path, env_vars: dict[str, str]) -> None:
    """Write ~/.wraith/.env with the provided variables."""
    lines = ["# WRAITH Cell v4.0 — Environment Configuration", f"# Generated {__import__('datetime').datetime.now().isoformat()}", ""]
    for k, v in env_vars.items():
        lines.append(f"{k}={v}")
    lines.append("")
    (home / ".env").write_text("\n".join(lines), encoding="utf-8")
    print(f"[✓] Wrote {home / '.env'}")


def _write_configs(home: Path) -> None:
    """Write AGENTS.md and SOUL.md templates."""
    import secrets
    cell_id = f"cell-{secrets.token_hex(8)}"
    ctx = {
        "cell_id": cell_id,
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "arch": platform.machine(),
    }
    (home / "AGENTS.md").write_text(AGENTS_MD_TEMPLATE.format(**ctx), encoding="utf-8")
    (home / "SOUL.md").write_text(SOUL_MD_TEMPLATE.format(**ctx), encoding="utf-8")
    (home / "cell_id").write_text(cell_id, encoding="utf-8")
    print(f"[✓] Wrote AGENTS.md, SOUL.md (cell_id={cell_id})")


def _install_service(home: Path, python_path: str) -> bool:
    """Install WRAITH Cell as a system/service manager unit. Returns True on success."""
    system = platform.system()
    cell_core = str(Path(__file__).parent / "cell_core.py")
    cmd = [python_path, cell_core]

    try:
        if system == "Windows":
            return _install_windows(home, cmd)
        elif system == "Linux":
            return _install_linux(home, cmd)
        elif system == "Darwin":
            return _install_macos(home, cmd)
        else:
            print(f"[!] Unsupported OS: {system} — install manually.")
            return False
    except Exception as exc:
        print(f"[!] Service install failed: {exc}")
        return False


def _install_windows(home: Path, cmd: list[str]) -> bool:
    """Use NSSM or a scheduled task to register as a Windows service."""
    # Try NSSM first
    nssm = shutil.which("nssm")
    if nssm:
        svc_cmd = [nssm, "install", "WRAITH-Cell"] + cmd
        subprocess.run(svc_cmd, check=True)
        print("[✓] Installed Windows service via NSSM")
        return True

    # Fallback: Scheduled Task (runs at login)
    script = home / "start_wraith.bat"
    script.write_text(
        f'@echo off\ncd /d "{home.parent}"\n{" ".join(cmd)}\n',
        encoding="utf-8",
    )
    task_xml = home / "wraith_task.xml"
    task_xml.write_text(
        f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Actions><Exec><Command>{cmd[0]}</Command><Arguments>{" ".join(cmd[1:])}</Arguments></Exec></Actions>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
</Task>""",
        encoding="utf-8",
    )
    print(f"[i] Created scheduled task config: {task_xml}")
    print(f"[i] To register: schtasks /create /tn WRAITH-Cell /xml \"{task_xml}\"")
    return True


def _install_linux(home: Path, cmd: list[str]) -> bool:
    """Write a systemd user unit."""
    unit = Path.home() / ".config/systemd/user/wraith-cell.service"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(
        textwrap.dedent(f"""\
            [Unit]
            Description=WRAITH Cell v4.0 Security Agent
            After=network-online.target
            Wants=network-online.target

            [Service]
            Type=simple
            ExecStart={" ".join(cmd)}
            WorkingDirectory={home}
            Restart=always
            RestartSec=5
            Environment=HOME={Path.home()}

            [Install]
            WantedBy=default.target
        """),
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", "wraith-cell"], check=False)
    print("[✓] Installed systemd user service")
    return True


def _install_macos(home: Path, cmd: list[str]) -> bool:
    """Write a macOS LaunchAgent plist."""
    plist = Path.home() / "Library/LaunchAgents/com.wraith.cell.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(
        textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key><string>com.wraith.cell</string>
                <key>ProgramArguments</key>
                <array>
                    {"".join(f"<string>{c}</string>" for c in cmd)}
                </array>
                <key>RunAtLoad</key><true/>
                <key>KeepAlive</key><true/>
                <key>StandardOutPath</key><string>{home}/logs/cell.log</string>
                <key>StandardErrorPath</key><string>{home}/logs/cell_error.log</string>
            </dict>
            </plist>
        """),
        encoding="utf-8",
    )
    subprocess.run(["launchctl", "load", str(plist)], check=False)
    print("[✓] Installed macOS LaunchAgent")
    return True


def _start_cell(home: Path, python_path: str) -> None:
    """Start cell_core.py in the foreground for initial verification."""
    cell_core = str(Path(__file__).parent / "cell_core.py")
    try:
        proc = subprocess.Popen(
            [python_path, cell_core],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(home),
        )
        # Wait a couple seconds to confirm it starts
        import time
        time.sleep(3)
        if proc.poll() is None:
            print("[✓] WRAITH Cell running (PID %d)" % proc.pid)
        else:
            out = proc.stdout.read().decode("utf-8", errors="replace") if proc.stdout else ""
            print(f"[!] Cell exited with code {proc.returncode}")
            if out:
                print(out[-500:])
    except FileNotFoundError:
        print("[!] Could not start cell — ensure cell_core.py is in the same directory.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)
    system, release, arch = _detect_os()
    print(f"  OS:      {system} {release} ({arch})")
    print(f"  Python:  {sys.version.split()[0]}")
    print(f"  Home:    {Path.home()}")
    print(f"  WRAITH:  {WRAITH_HOME}")

    # Step 1: Create directory
    print("\n[1/6] Creating WRAITH home…")
    _create_directory(WRAITH_HOME)

    # Step 2: API key
    print("\n[2/6] Configure AI provider…")
    env_vars = _prompt_api_key()

    # Step 3: Write .env
    print("\n[3/6] Writing configuration…")
    _write_env(WRAITH_HOME, env_vars)

    # Step 4: Write AGENTS.md / SOUL.md
    print("\n[4/6] Generating agent configs…")
    _write_configs(WRAITH_HOME)

    # Step 5: Install service
    print("\n[5/6] Installing system service…")
    python_path = _find_python()
    _install_service(WRAITH_HOME, python_path)

    # Step 6: Start cell
    print("\n[6/6] Starting WRAITH Cell…")
    _start_cell(WRAITH_HOME, python_path)

    print(f"""
╔══════════════════════════════════════════════════╗
║          WRAITH Cell v4.0 — READY                ║
╠══════════════════════════════════════════════════╣
║  Config:  {WRAITH_HOME}                ║
║  Logs:    {WRAITH_HOME / 'logs'}                ║
║  Stop:    kill the cell process or service       ║
║  Re-run:  python setup_wizard.py                ║
╚══════════════════════════════════════════════════╝
""")

    # Step 7: Report to P2P mesh (handled by cell itself)
    print("[i] Cell will auto-announce on the Biomesh P2P network (UDP :7736).")


if __name__ == "__main__":
    main()
