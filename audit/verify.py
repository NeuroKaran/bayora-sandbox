"""
Bayora Sandbox - Hash-Chain Verifier CLI
Cryptographically verifies the integrity and immutability of the audit chain.
"""

import sys
import os
import json
from datetime import datetime
from typing import Optional

# Allow running from anywhere
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain import verify_chain, compute_hash, canonical_json, DEFAULT_LOG_PATH, GENESIS_HASH


def print_banner():
    print("""
======================================================
  BAYORA SANDBOX - AUDIT HASH CHAIN VERIFIER
======================================================
""")


def inspect_and_verify(log_path: Optional[str] = None) -> bool:
    if log_path is None:
        log_path = os.getenv("BAYORA_AUDIT_LOG", DEFAULT_LOG_PATH)

    print_banner()
    print(f"[*] Target Log: {os.path.abspath(log_path)}")

    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        print("[!] Warning: Log file does not exist or is empty.")
        return True

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"[*] Found {len(lines)} recorded block(s).\n" + "-" * 60)

    for i, line in enumerate(lines):
        try:
            b = json.loads(line)
            ts = datetime.fromtimestamp(b.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            idx = b.get("index", "?")
            prev_h = b.get("prev_hash", "")[:16] + "..." if b.get("prev_hash") else "None"
            curr_h = b.get("hash", "")[:16] + "..." if b.get("hash") else "None"
            data_summary = b.get("data", {k: v for k, v in b.items() if k not in ("index", "timestamp", "prev_hash", "hash")})
            
            data_str = json.dumps(data_summary)
            if len(data_str) > 60:
                data_str = data_str[:57] + "..."

            print(f"Block #{idx:<4} | Time: {ts} | Hash: {curr_h}")
            print(f"  Prev Hash: {prev_h}")
            print(f"  Data:      {data_str}")
            print("-" * 60)
        except Exception as e:
            print(f"[!] Malformed entry at line {i + 1}: {e}")

    valid, msg, idx = verify_chain(log_path)
    if valid:
        print(f"\n[SUCCESS] Integrity Check Passed: {msg}\n")
        return True
    else:
        print(f"\n[FAIL] Tampering / Corruption Detected at Block #{idx}: {msg}\n", file=sys.stderr)
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.getenv("BAYORA_AUDIT_LOG", DEFAULT_LOG_PATH)
    success = inspect_and_verify(target)
    sys.exit(0 if success else 1)
