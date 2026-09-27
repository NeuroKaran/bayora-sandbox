"""
Bayora Sandbox - Tamper-Evident Hash-Chain Audit Logger
Implements an append-only cryptographic SHA-256 hash-chain guaranteeing log integrity and non-repudiation.
"""

import os
import sys
import json
import time
import hashlib
import threading
from typing import Any, Dict, Optional, Tuple

GENESIS_HASH = "0" * 64
DEFAULT_LOG_PATH = os.getenv(
    "BAYORA_AUDIT_LOG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.jsonl")
)

_file_lock = threading.Lock()


def canonical_json(obj: Any) -> str:
    """
    Serialize data to deterministic, canonical JSON with sorted keys
    and no extraneous whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def compute_hash(block: Dict[str, Any]) -> str:
    """
    Compute the SHA-256 digest of a block.
    Hashes all fields in the block EXCEPT the 'hash' field itself.
    """
    payload = {k: v for k, v in block.items() if k != "hash"}
    serialized = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def get_last_entry(log_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve the last entry from the hash-chain log file, or None if empty/non-existent.
    """
    if log_path is None:
        log_path = os.getenv("BAYORA_AUDIT_LOG", DEFAULT_LOG_PATH)

    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        return None

    try:
        # Seek from end for fast retrieval on large files
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            buffer_size = 4096
            remaining = size
            buffer = b""
            lines = []
            while remaining > 0 and len(lines) < 2:
                read_size = min(buffer_size, remaining)
                remaining -= read_size
                f.seek(remaining)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                lines = buffer.split(b"\n")
            for line in reversed(lines):
                line_str = line.strip().decode("utf-8", errors="ignore")
                if line_str:
                    return json.loads(line_str)
    except Exception:
        # Fallback to standard line scan
        with open(log_path, "r", encoding="utf-8") as f:
            valid_lines = [l.strip() for l in f if l.strip()]
            if valid_lines:
                return json.loads(valid_lines[-1])

    return None


def log_entry(data: Any, log_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Append an entry to the hash-chain log.

    Args:
        data: The payload/event dict or object to record.
        log_path: Path to the JSONL log file (defaults to BAYORA_AUDIT_LOG or audit/log.jsonl).

    Returns:
        The complete block recorded in the hash-chain.
    """
    if log_path is None:
        log_path = os.getenv("BAYORA_AUDIT_LOG", DEFAULT_LOG_PATH)

    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    with _file_lock:
        last_block = get_last_entry(log_path)

        if last_block is None:
            index = 0
            prev_hash = GENESIS_HASH
        else:
            index = last_block.get("index", 0) + 1
            prev_hash = last_block.get("hash", GENESIS_HASH)

        # Determine timestamp: preserve if provided in data dict, else use current time
        if isinstance(data, dict) and "timestamp" in data and isinstance(data["timestamp"], (int, float)):
            timestamp = float(data["timestamp"])
        else:
            timestamp = time.time()

        # Build block structure
        block: Dict[str, Any] = {
            "index": index,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
        }

        # Embed data both under 'data' and unpack keys if dict (for transparent field access)
        if isinstance(data, dict):
            block["data"] = data
            for k, v in data.items():
                if k not in ("index", "prev_hash", "hash"):
                    block[k] = v
        else:
            block["data"] = data

        # Calculate cryptographic hash over canonical block
        block["hash"] = compute_hash(block)

        # Append atomically to log file
        line = json.dumps(block, sort_keys=True) + "\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

        return block


def verify_chain(log_path: Optional[str] = None) -> Tuple[bool, str, Optional[int]]:
    """
    Verify the cryptographic integrity of the entire hash chain.

    Returns:
        (is_valid, message, count_or_failed_index)
    """
    if log_path is None:
        log_path = os.getenv("BAYORA_AUDIT_LOG", DEFAULT_LOG_PATH)

    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        return True, "Chain file is empty (valid)", 0

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        return True, "Chain file contains no entries (valid)", 0

    expected_prev_hash = GENESIS_HASH

    for i, line in enumerate(lines):
        try:
            block = json.loads(line)
        except json.JSONDecodeError as e:
            return False, f"JSON parse error at line {i + 1}: {e}", i

        # Verify required keys
        for key in ("index", "timestamp", "prev_hash", "hash"):
            if key not in block:
                return False, f"Block {i} missing required header field '{key}'", i

        # Verify sequential indexing
        if block["index"] != i:
            return False, f"Block {i} index mismatch: expected {i}, found {block['index']}", i

        # Verify prev_hash matches prior block's hash
        if block["prev_hash"] != expected_prev_hash:
            return False, (
                f"Block {i} prev_hash mismatch: expected {expected_prev_hash[:16]}..., "
                f"found {block['prev_hash'][:16]}..."
            ), i

        # Verify block's own hash matches cryptographic computation
        expected_hash = compute_hash(block)
        if block["hash"] != expected_hash:
            return False, (
                f"Block {i} hash tampered or corrupted: expected {expected_hash[:16]}..., "
                f"found {block['hash'][:16]}..."
            ), i

        expected_prev_hash = block["hash"]

    return True, f"Chain verified successfully ({len(lines)} blocks intact)", len(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bayora Sandbox Hash-Chain Logger")
    parser.add_argument("--log", "-l", help="Message or JSON to log")
    parser.add_argument("--file", "-f", default=DEFAULT_LOG_PATH, help="Path to log file")
    parser.add_argument("--verify", "-v", action="store_true", help="Verify chain integrity")

    args = parser.parse_args()

    if args.verify:
        valid, msg, idx = verify_chain(args.file)
        if valid:
            print(f"[OK] {msg}")
            sys.exit(0)
        else:
            print(f"[ERROR] Verification failed: {msg}")
            sys.exit(1)
    elif args.log:
        try:
            payload = json.loads(args.log)
        except json.JSONDecodeError:
            payload = {"message": args.log}
        res = log_entry(payload, args.file)
        print(f"Logged block #{res['index']} with hash {res['hash']}")
    else:
        parser.print_help()
