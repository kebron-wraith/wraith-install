#!/usr/bin/env python3
"""
WRAITH Cell v4.0 — Binary Compiler
====================================
Compiles cell_core.py into a standalone executable using PyInstaller.
Bundles AGENTS.md, SOUL.md, and all dependencies.

Outputs:
    dist/cell.exe   (Windows)
    dist/cell.bin   (Linux)
    dist/cell.app   (macOS)

Usage:
    python compile_binary.py           # compile for current OS
    python compile_binary.py --onefile # single-file binary (default)
    python compile_binary.py --test    # quick syntax check, no compile
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CELL_CORE = Path(__file__).parent / "cell_core.py"
CONFIG_DIR = Path(__file__).parent / "config"
DIST_DIR = Path(__file__).parent / "dist"
PYINSTALLER = "pyinstaller"

# Files to bundle alongside the binary (accessible at runtime via sys._MEIPASS)
DATASOURCES: list[tuple[str, str]] = [
    (str(CONFIG_DIR / "AGENTS.md"), "config"),
    (str(CONFIG_DIR / "SOUL.md"), "config"),
]

# Hidden imports that PyInstaller may not auto-detect
HIDDEN_IMPORTS: list[str] = [
    "requests",
    "dotenv",
    "anthropic",
    "openai",
    "google.generativeai",
    "groq",
    "mistralai",
]


def _check_pyinstaller() -> bool:
    """Return True if pyinstaller is available."""
    if shutil.which(PYINSTALLER):
        return True
    try:
        import PyInstaller  # noqa: F401  # type: ignore
        return True
    except ImportError:
        print("[!] PyInstaller not found.")
        print("    Install: pip install pyinstaller")
        return False


def _output_name() -> str:
    """Return the expected output binary name for the current OS."""
    system = platform.system()
    if system == "Windows":
        return "cell.exe"
    elif system == "Darwin":
        return "cell.app"
    else:
        return "cell.bin"


def _build_cmd(onefile: bool = True, windowed: bool = False) -> list[str]:
    """Construct the pyinstaller command."""
    cmd = [
        PYINSTALLER,
        "--clean",
        "--noconfirm",
        "--log-level=WARN",
        f"--name=cell",
    ]
    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")
    if windowed:
        cmd.append("--windowed")
    if not windowed:
        cmd.append("--console")

    # Add bundled data files
    for src, dst in DATASOURCES:
        if Path(src).exists():
            separator = ";" if platform.system() == "Windows" else ":"
            cmd.extend(["--add-data", f"{src}{separator}{dst}"])

    # Add hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", imp])

    # Output destination
    cmd.extend(["--distpath", str(DIST_DIR)])
    cmd.extend(["--workpath", str(Path(__file__).parent / "build")])
    cmd.extend(["--specpath", str(Path(__file__).parent)])

    # Entry point
    cmd.append(str(CELL_CORE))
    return cmd


def _syntax_check() -> bool:
    """Quick syntax check: compile cell_core.py without running it."""
    print("[i] Running syntax check…")
    try:
        import py_compile
        py_compile.compile(str(CELL_CORE), doraise=True)
        print("[✓] Syntax OK")
        return True
    except py_compile.PyCompileError as exc:
        print(f"[✗] Syntax error: {exc}")
        return False


def _verify_output() -> bool:
    """Check that the expected output binary exists."""
    output = DIST_DIR / _output_name()
    if output.exists():
        size_mb = output.stat().st_size / (1024 * 1024)
        print(f"[✓] Output: {output} ({size_mb:.1f} MB)")
        return True
    else:
        # Onedir mode creates cell/ directory
        dir_output = DIST_DIR / "cell"
        if dir_output.is_dir():
            print(f"[✓] Output directory: {dir_output}")
            print(f"    Binary: {dir_output / _output_name()}")
            return True
        print(f"[✗] Expected output not found: {output}")
        return False


def build(onefile: bool = True, test_only: bool = False) -> bool:
    """Run the full build pipeline."""
    # Pre-flight
    if not CELL_CORE.exists():
        print(f"[FATAL] Entry point not found: {CELL_CORE}")
        return False

    if not _syntax_check():
        return False

    if test_only:
        return True

    if not _check_pyinstaller():
        return False

    # Clean previous builds
    build_dir = Path(__file__).parent / "build"
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    if build_dir.exists():
        shutil.rmtree(build_dir)

    # Build
    cmd = _build_cmd(onefile=onefile)
    print(f"[i] Building: {' '.join(cmd[:8])}…")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if result.stderr:
            # PyInstaller prints warnings to stderr — only show if build fails
            pass
    except subprocess.CalledProcessError as exc:
        print(f"[✗] Build failed (exit code {exc.returncode})")
        if exc.stdout:
            print(exc.stdout[-1000:])
        if exc.stderr:
            print(exc.stderr[-1000:])
        return False
    except FileNotFoundError:
        print("[FATAL] pyinstaller not found in PATH")
        return False

    return _verify_output()


def print_post_build_info() -> None:
    """Print helpful info after a successful build."""
    system = platform.system()
    output = _output_name()
    print(f"""
╔══════════════════════════════════════════════════╗
║     WRAITH Cell v4.0 — Build Complete            ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║  Output:  dist/{output:<34}║
║  OS:      {system:<40}║
║                                                  ║
║  Deploy:  Copy the binary to the target device   ║
║           and run setup_wizard.py to configure.  ║
║                                                  ║
║  Direct:  .\\dist\\{output} --help{' ' * (33 - len(output))}║
╚══════════════════════════════════════════════════╝
""")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    onefile = "--onedir" not in args
    test_only = "--test" in args

    success = build(onefile=onefile, test_only=test_only)
    if success and not test_only:
        print_post_build_info()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
