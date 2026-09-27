"""
Bayora Sandbox - Audit Trail Concurrency & Load Stress Test.
Spawns concurrent worker threads writing to the hash chain simultaneously,
verifying that file locking prevents race conditions, missing indices, or corrupted links.
"""

import os
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

from audit.chain import log_entry, verify_chain, get_last_entry


class TestAuditConcurrency(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "test_concurrent_audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_concurrent_multithreaded_writes(self):
        """Simultaneously write 50 blocks across 10 threads; verify chain integrity."""
        total_writes = 50
        num_workers = 10

        def worker_task(thread_id: int, item_id: int):
            payload = {
                "thread": thread_id,
                "seq": item_id,
                "event": f"concurrent_write_{thread_id}_{item_id}"
            }
            return log_entry(payload, log_path=self.log_path)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(worker_task, i % num_workers, i)
                for i in range(total_writes)
            ]
            results = [f.result() for f in as_completed(futures)]

        self.assertEqual(len(results), total_writes)

        # Cryptographically verify the resulting chain
        valid, msg, count = verify_chain(self.log_path)
        self.assertTrue(valid, f"Chain corrupted under concurrency: {msg}")
        self.assertEqual(count, total_writes)

        # Verify terminal block has index == total_writes - 1
        last = get_last_entry(self.log_path)
        self.assertIsNotNone(last)
        self.assertEqual(last["index"], total_writes - 1)


if __name__ == "__main__":
    unittest.main()
