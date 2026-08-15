#!/usr/bin/env python3
"""
WRAITH Installation Script
This script sets up the WRAITH AI cyber operations platform.
It will clone required submodules, configure environment variables,
and launch core services.
"""

import os
import subprocess
import sys

def main():
    print("Installing WRAITH...")
    # Install required submodules, including cell
    subprocess.run(["git", "submodule", "update", "--init", "--recursive"], check=True)
    subprocess.run(["git", "clone", "https://github.com/kebron-wraith/wraith-cell.git", "cell"], check=True)
    # Set up virtual environment
    subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
    print("WRAITH installation completed successfully.")

if __name__ == "__main__":
    main()