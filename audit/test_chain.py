"""
Unit tests for Bayora Sandbox Tamper-Evident Hash Chain.
"""

import os
import json
import shutil
import tempfile
import unittest

from chain import log_entry, verify_chain, compute_hash, get_last_entry, GENESIS_HASH


class TestHashChain(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "test_log.jsonl")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_genesis_block_creation(self):
        """Verify genesis block has index 0 and 64-zero prev_hash."""
        entry = log_entry({"event": "genesis_test"}, log_path=self.log_path)
        self.assertEqual(entry["index"], 0)
        self.assertEqual(entry["prev_hash"], GENESIS_HASH)
        self.assertEqual(entry["event"], "genesis_test")
        self.assertIn("hash", entry)

        valid, msg, count = verify_chain(self.log_path)
        self.assertTrue(valid, msg)
        self.assertEqual(count, 1)

    def test_sequential_chain(self):
        """Verify adding multiple events preserves hash chain integrity."""
        b0 = log_entry({"step": 1}, log_path=self.log_path)
        b1 = log_entry({"step": 2}, log_path=self.log_path)
        b2 = log_entry({"step": 3}, log_path=self.log_path)

        self.assertEqual(b0["index"], 0)
        self.assertEqual(b1["index"], 1)
        self.assertEqual(b2["index"], 2)

        self.assertEqual(b1["prev_hash"], b0["hash"])
        self.assertEqual(b2["prev_hash"], b1["hash"])

        valid, msg, count = verify_chain(self.log_path)
        self.assertTrue(valid, msg)
        self.assertEqual(count, 3)

    def test_tamper_detection_data(self):
        """Verify modifying logged data is detected."""
        log_entry({"user": "alice", "action": "read"}, log_path=self.log_path)
        log_entry({"user": "bob", "action": "write"}, log_path=self.log_path)

        # Tamper with block 0 data on disk
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]

        lines[0]["action"] = "admin_takeover"
        lines[0]["data"]["action"] = "admin_takeover"

        with open(self.log_path, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(json.dumps(l) + "\n")

        valid, msg, failed_idx = verify_chain(self.log_path)
        self.assertFalse(valid)
        self.assertEqual(failed_idx, 0)
        self.assertIn("tampered", msg)

    def test_tamper_detection_hash_recalculation(self):
        """Verify modifying block 0 and fixing its hash still breaks block 1's prev_hash."""
        log_entry({"val": 10}, log_path=self.log_path)
        log_entry({"val": 20}, log_path=self.log_path)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]

        # Modify block 0 and recalculate its hash
        lines[0]["val"] = 999
        lines[0]["data"]["val"] = 999
        lines[0]["hash"] = compute_hash(lines[0])

        with open(self.log_path, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(json.dumps(l) + "\n")

        valid, msg, failed_idx = verify_chain(self.log_path)
        self.assertFalse(valid)
        self.assertEqual(failed_idx, 1)
        self.assertIn("prev_hash mismatch", msg)


if __name__ == "__main__":
    unittest.main()
