#!/usr/bin/env python3
"""
WRAITH Cell Update + Auth System
- Cells authenticate with tracker using HMAC-signed messages
- Faka pushes signed updates to cells
- Cells verify signature before installing updates
"""
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# CELL AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

def generate_cell_key(cell_id, master_key):
    """Generate a unique cell key from master key + cell_id."""
    return hmac.new(
        master_key.encode(),
        cell_id.encode(),
        hashlib.sha256
    ).hexdigest()

def sign_message(cell_id, cell_key, message):
    """Sign a message with the cell key."""
    payload = f"{cell_id}:{message}:{int(time.time())}"
    signature = hmac.new(
        cell_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return {
        "cell_id": cell_id,
        "message": message,
        "timestamp": int(time.time()),
        "signature": signature
    }

def verify_signature(cell_id, cell_key, signed_message):
    """Verify a signed message."""
    payload = f"{cell_id}:{signed_message['message']}:{signed_message['timestamp']}"
    expected = hmac.new(
        cell_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Check signature
    if not hmac.compare_digest(expected, signed_message["signature"]):
        return False
    
    # Check timestamp (reject if > 5 min old)
    if abs(time.time() - signed_message["timestamp"]) > 300:
        return False
    
    return True

# ═══════════════════════════════════════════════════════════════
# SIGNED UPDATES
# ═══════════════════════════════════════════════════════════════

def sign_update(update_data, master_key):
    """Sign an update package."""
    payload = json.dumps(update_data, sort_keys=True)
    signature = hmac.new(
        master_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return {
        "update": update_data,
        "signature": signature,
        "timestamp": datetime.now().isoformat(),
        "version": update_data.get("version", "unknown")
    }

def verify_update(signed_update, master_key):
    """Verify a signed update."""
    payload = json.dumps(signed_update["update"], sort_keys=True)
    expected = hmac.new(
        master_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signed_update["signature"])

# ═══════════════════════════════════════════════════════════════
# UPDATE MECHANISM
# ═══════════════════════════════════════════════════════════════

def create_update(version, files, changelog=""):
    """Create a signed update package."""
    master_key = os.environ.get("WRAITH_MASTER_KEY", "")
    if not master_key:
        raise ValueError("WRAITH_MASTER_KEY not set")
    
    update_data = {
        "version": version,
        "files": files,  # {filename: content}
        "changelog": changelog,
        "created_at": datetime.now().isoformat(),
    }
    
    return sign_update(update_data, master_key)

def apply_update(signed_update, install_dir):
    """Verify and apply an update."""
    master_key = os.environ.get("WRAITH_MASTER_KEY", "")
    if not master_key:
        raise ValueError("WRAITH_MASTER_KEY not set")
    
    if not verify_update(signed_update, master_key):
        raise ValueError("Invalid update signature — REJECTED")
    
    install_path = Path(install_dir)
    applied = []
    
    for filename, content in signed_update["update"]["files"].items():
        file_path = install_path / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Backup existing
        if file_path.exists():
            backup = file_path.with_suffix(f".backup_{int(time.time())}")
            backup.write_text(file_path.read_text())
        
        # Write new
        file_path.write_text(content)
        applied.append(filename)
    
    return applied

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WRAITH Cell Auth + Updates")
    sub = parser.add_subparsers(dest="command")
    
    p_key = sub.add_parser("generate-key")
    p_key.add_argument("--cell-id", required=True)
    p_key.add_argument("--master-key", required=True)
    
    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--cell-id", required=True)
    p_sign.add_argument("--cell-key", required=True)
    p_sign.add_argument("--message", required=True)
    
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--cell-id", required=True)
    p_verify.add_argument("--cell-key", required=True)
    p_verify.add_argument("--signature", required=True)
    p_verify.add_argument("--message", required=True)
    p_verify.add_argument("--timestamp", type=int, required=True)
    
    args = parser.parse_args()
    
    if args.command == "generate-key":
        key = generate_cell_key(args.cell_id, args.master_key)
        print(f"Cell key: {key}")
    elif args.command == "sign":
        result = sign_message(args.cell_id, args.cell_key, args.message)
        print(json.dumps(result, indent=2))
    elif args.command == "verify":
        msg = {"message": args.message, "timestamp": args.timestamp, "signature": args.signature}
        valid = verify_signature(args.cell_id, args.cell_key, msg)
        print(f"Valid: {valid}")
