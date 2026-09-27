#!/usr/bin/env python3
"""
Bayora Sandbox - Unified Test Runner.
Executes all unit, integration, isolation, and attack test suites across the repository.
"""

import sys
import time
import unittest


def main():
    print("=" * 65)
    print("  BAYORA SANDBOX - COMPLETE TEST SUITE RUNNER")
    print("=" * 65)
    t0 = time.time()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    modules = ["audit", "gateway", "isolation", "attacks"]
    for mod in modules:
        print(f"[*] Discovering test suites in '{mod}/'...")
        mod_suite = loader.discover(mod, pattern="test_*.py", top_level_dir=".")
        suite.addTests(mod_suite)

    print(f"\n[*] Executing {suite.countTestCases()} test cases...\n" + "-" * 65)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    elapsed = round(time.time() - t0, 3)

    print("-" * 65)
    if result.wasSuccessful():
        print(f"[SUCCESS] All tests passed cleanly in {elapsed}s.")
        sys.exit(0)
    else:
        print(f"[FAILURE] {len(result.failures)} failure(s), {len(result.errors)} error(s) in {elapsed}s.")
        sys.exit(1)


if __name__ == "__main__":
    main()
