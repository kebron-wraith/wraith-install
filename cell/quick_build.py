#!/usr/bin/env python3
"""Quick cell binary build — minimal imports, onedir mode."""
import subprocess, sys, os
from pathlib import Path

cell_dir = Path(__file__).parent
dist_dir = cell_dir / "dist"

# Kill any stale build processes
os.system('taskkill /f /im pyinstaller 2>nul')
os.system('taskkill /f /im python 2>nul')

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onedir",
    "--name", "wraith-cell",
    "--distpath", str(dist_dir / "cell"),
    "--workpath", str(dist_dir / "build"),
    "--specpath", str(dist_dir),
    "--paths", str(cell_dir),
    "--paths", str(cell_dir.parent / "core"),
    "--paths", str(cell_dir.parent / "admin"),
    "--hidden-import", "requests",
    "--hidden-import", "dotenv",
    "--hidden-import", "yaml",
    "--hidden-import", "cryptography",
    "--hidden-import", "nacl",
    "--hidden-import", "reportlab",
    "--hidden-import", "sqlite3",
    "--hidden-import", "hashlib",
    "--hidden-import", "hmac",
    "--hidden-import", "secrets",
    "--hidden-import", "json",
    "--hidden-import", "threading",
    "--hidden-import", "socket",
    "--hidden-import", "http.server",
    "--hidden-import", "urllib.request",
    "--hidden-import", "datetime",
    "--hidden-import", "pathlib",
    "--hidden-import", "logging",
    "--hidden-import", "argparse",
    "--hidden-import", "subprocess",
    "--hidden-import", "platform",
    "--hidden-import", "signal",
    "--hidden-import", "struct",
    "--hidden-import", "time",
    "--hidden-import", "os",
    "--hidden-import", "sys",
    "--hidden-import", "typing",
    "--hidden-import", "collections",
    "--hidden-import", "email.mime.text",
    "--hidden-import", "email.mime.multipart",
    "--hidden-import", "smtplib",
    "--hidden-import", "ssl",
    "--hidden-import", "base64",
    "--hidden-import", "uuid",
    "--hidden-import", "wave",
    "--hidden-import", "math",
    "--hidden-import", "random",
    "--hidden-import", "re",
    "--hidden-import", "io",
    "--hidden-import", "textwrap",
    "--hidden-import", "functools",
    "--hidden-import", "itertools",
    "--hidden-import", "operator",
    "--hidden-import", "copy",
    "--hidden-import", "pprint",
    "--hidden-import", "string",
    "--hidden-import", "textwrap",
    "--clean",
    "--noconfirm",
    "--log-level=ERROR",
    str(cell_dir / "cell_core.py")
]

print("Building wraith-cell binary (this takes 2-3 minutes)...")
result = subprocess.run(cmd, timeout=300)

if result.returncode == 0:
    binary = dist_dir / "cell" / "wraith-cell.exe"
    if binary.exists():
        size = binary.stat().st_size / (1024*1024)
        print(f"SUCCESS: {binary} ({size:.1f} MB)")
    else:
        print("Build succeeded but binary not found")
        # Check what was created
        for f in (dist_dir / "cell").rglob("*"):
            if f.is_file() and f.suffix in ('.exe', '.dll', '.pyd'):
                print(f"  {f.name} ({f.stat().st_size/1024:.0f} KB)")
else:
    print(f"Build failed (exit {result.returncode})")
    if result.stderr:
        print(result.stderr.decode()[-500:])
