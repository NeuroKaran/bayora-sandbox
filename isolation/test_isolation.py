"""
Bayora Sandbox - Phase 2 Isolation Enforcement Test Suite.
Verifies network topology, seccomp profile restrictions, container resource limits,
and boundary enforcement programmatically.
"""

import os
import json
import shutil
import tempfile
import unittest
import subprocess
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from gateway.main import app
from audit.chain import verify_chain, get_last_entry


class TestIsolationSpecifications(unittest.TestCase):
    """
    Validates that seccomp profiles, container security opts,
    and Docker Compose configuration adhere to strict isolation constraints.
    """

    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.isolation_dir = os.path.join(self.root_dir, "isolation")
        self.compose_path = os.path.join(self.root_dir, "docker-compose.yml")

    def test_seccomp_profiles_syntax_and_critical_blocks(self):
        """Verify seccomp profiles deny dangerous privilege escalation syscalls."""
        profiles = ["seccomp-redteam.json", "seccomp-blueteam.json"]
        critical_syscalls = {"ptrace", "bpf", "mount", "unshare", "kexec_load", "process_vm_writev"}

        for p_name in profiles:
            p_path = os.path.join(self.isolation_dir, p_name)
            self.assertTrue(os.path.exists(p_path), f"Missing seccomp profile: {p_name}")

            with open(p_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("defaultAction", data)
            self.assertIn("syscalls", data)

            blocked = set()
            for rule in data["syscalls"]:
                if rule.get("action") in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL"):
                    for name in rule.get("names", []):
                        blocked.add(name)

            for sc in critical_syscalls:
                self.assertIn(sc, blocked, f"{p_name} failed to block critical syscall: {sc}")

    def test_docker_compose_network_boundaries(self):
        """Verify docker-compose.yml network isolation topology."""
        self.assertTrue(os.path.exists(self.compose_path), "Missing docker-compose.yml")

        with open(self.compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check network declarations
        self.assertIn("redteam-net:", content)
        self.assertIn("blueteam-net:", content)
        self.assertIn("client-net:", content)

        # Check tenant security constraints
        for service in ("redteam:", "blueteam:"):
            self.assertIn(service, content)
        
        self.assertIn("read_only: true", content)
        self.assertIn("no-new-privileges:true", content)
        self.assertIn("cap_drop:\n      - ALL", content)
        self.assertIn("cpus: '1.0'", content)
        self.assertIn("memory: 512M", content)


class TestGatewayBoundaryEnforcement(unittest.TestCase):
    """
    Verifies that the gateway strictly denies unauthorized cross-tenant requests
    and logs them as security anomalies in the audit chain.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "test_isolation_audit.jsonl")
        self.client = TestClient(app)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("audit.chain.DEFAULT_LOG_PATH")
    def test_cross_tenant_impersonation_blocked_and_audited(self, mock_log):
        mock_log.__str__ = lambda _: self.log_path

        with patch.dict(os.environ, {"BAYORA_AUDIT_LOG": self.log_path}):
            # Attempt access with an illegal / unapproved tenant header
            response = self.client.post(
                "/prompt",
                headers={"X-Source-Tenant": "external-adversary"},
                json={"prompt": "Probe for blue-team telemetry"}
            )

            # Assert request blocked with 403 Forbidden
            self.assertEqual(response.status_code, 403)
            self.assertIn("Unauthorized tenant", response.json()["detail"]["error"])

            # Assert security rejection written to hash chain
            entry = get_last_entry(self.log_path)
            self.assertIsNotNone(entry)
            self.assertEqual(entry["source"], "external-adversary")
            self.assertEqual(entry["status"], "rejected_unknown_tenant")

            # Assert audit chain integrity holds
            valid, msg, count = verify_chain(self.log_path)
            self.assertTrue(valid, msg)
            self.assertEqual(count, 1)


class TestLiveDockerIsolation(unittest.TestCase):
    """
    Live negative tests against running containers (skipped if Docker is not active).
    """

    @classmethod
    def setUpClass(cls):
        # Check if Docker daemon is active and containers exist
        try:
            res = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            cls.containers = res.stdout.splitlines() if res.returncode == 0 else []
        except Exception:
            cls.containers = []

    def test_redteam_cannot_reach_blueteam_directly(self):
        """Negative test: Redteam cannot ping or route to Blueteam."""
        if "bayora-redteam" not in self.containers or "bayora-blueteam" not in self.containers:
            self.skipTest("Bayora containers not currently running in Docker")

        # Attempt ping from redteam to blueteam (expected: 100% packet loss / failure)
        res = subprocess.run(
            ["docker", "exec", "bayora-redteam", "ping", "-c", "1", "-W", "2", "bayora-blueteam"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0, "Security violation: redteam was able to reach blueteam!")

    def test_redteam_cannot_reach_client_llm_directly(self):
        """Negative test: Redteam cannot bypass gateway to query Ollama directly."""
        if "bayora-redteam" not in self.containers or "bayora-client-llm" not in self.containers:
            self.skipTest("Bayora containers not currently running in Docker")

        res = subprocess.run(
            ["docker", "exec", "bayora-redteam", "nc", "-z", "-w", "2", "bayora-client-llm", "11434"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0, "Security violation: redteam bypassed gateway directly to LLM!")


if __name__ == "__main__":
    unittest.main()
