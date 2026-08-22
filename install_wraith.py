#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WRAITH Installation Script
Provides automated setup of WRAITH platform and cells.
"""
import os
import sys
import subprocess
import json

def run_cmd(cmd, shell=False):
    """Run a command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {cmd}\nError: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    print("🚀 Starting WRAITH installation...")
    # Ensure we are in the expected directory
    wraith_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print(f"Working directory: {wraith_dir}")

    # 1. Clone the main WRAITH repo if not present
    if not os.path.isdir(os.path.join(wraith_dir, "wraith")):
        print("Cloning WRAITH repository...")
        run_cmd(f"git clone https://github.com/kebron-wraith/wraith.git {wraith_dir}/wraith")
    else:
        print("WRAITH repository already cloned.")

    # 2. Set up Python virtual environment
    venv_path = os.path.join(wraith_dir, "wraith", "venv")
    if not os.path.isdir(venv_path):
        print("Creating Python virtual environment...")
        run_cmd(f"python -m venv {venv_path}")
        # Activate venv and install dependencies
        activate = os.path.join(venv_path, "Scripts", "activate")
        run_cmd(f". {activate} && pip install -r {wraith_dir}/wraith/requirements.txt")
    else:
        print("Virtual environment already exists.")

    # 3. Initialize tracker DB if missing
    tracker_db = os.path.join(wraith_dir, "wraith", "tracker.db")
    if not os.path.isfile(tracker_db):
        print("Initializing tracker database...")
        # Assuming init_db.py exists in wraith repo
        run_cmd(f". {activate} && python {wraith_dir}/wraith/scripts/init_db.py")

    # 4. Deploy cell templates
    cell_dir = os.path.join(wraith_dir, "wraith", "cells")
    if not os.path.isdir(cell_dir):
        print("Deploying cell templates...")
        run_cmd(f"git clone https://github.com/kebron-wraith/wraith-cells.git {cell_dir}")
    else:
        print("Cell templates already deployed.")

    print("\n✅ WRAITH installation completed successfully.")
    print("You can now run `python wraith/cell_health.py` to verify.")

if __name__ == "__main__":
    main()