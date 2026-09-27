#!/usr/bin/env python3
"""
Bayora Sandbox - Red-Team Attack Harness Alias (run_attack.py)
"""
import sys
import os

# Import implementation from run-attack.py
sys.path.insert(0, os.path.dirname(__file__))
import importlib.util

spec = importlib.util.spec_from_file_location("run_attack_module", os.path.join(os.path.dirname(__file__), "run-attack.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

if __name__ == "__main__":
    module.main()
