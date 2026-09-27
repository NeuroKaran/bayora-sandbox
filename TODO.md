# Bayora Sandbox Roadmap & TODOs 📋

Tracking progress against specifications defined in [PRD.md](PRD.md).

---

## Phase 0 — Repo & Environment Hygiene
- [x] `.gitignore` configured to ignore `.venv/`, `log.jsonl`, `*.chain`, `ollama-data/`, `.env`
- [x] `README.md` complete with problem statement, architecture diagram, setup steps, and verification commands
- [x] `TODO.md` aligned with PRD phases and known gaps
- [x] Root `requirements.txt` and `gateway/requirements.txt` pinned to exact versions
- [x] MIT `LICENSE` added
- [x] `audit/` packaged cleanly with `__init__.py` and tested

## Phase 1 — Core Services Running End to End
- [x] `llm-gateway` FastAPI service with `/health` and `/prompt` endpoints
- [x] Environment variable configuration for `OLLAMA_URL`, `MODEL_NAME`, and `BAYORA_AUDIT_LOG`
- [x] Clean module packaging for `audit` inside `gateway` Dockerfile (eliminating path hacks)
- [x] Multi-network `docker-compose.yml` (`redteam-net`, `blueteam-net`, `client-net`)
- [x] Automated model initialization / puller container for `qwen2.5:3b-instruct`
- [ ] Round-trip prompt verified under live Docker daemon execution

## Phase 2 — Isolation Enforcement
- [x] Add explicit `redteam` and `blueteam` worker containers to `docker-compose.yml`
- [x] Enforce seccomp profiles (`isolation/seccomp-blueteam.json`, `isolation/seccomp-redteam.json`)
- [x] Set strict cgroup limits (CPU: 1.0, RAM: 512MB) per tenant container
- [x] Execute containers rootless (`user: "10001:10001"`, `no-new-privileges:true`, `read_only:true`, `cap_drop: [ALL]`)
- [x] Automated negative test suite (`isolation/test_isolation.py`): programmatic assertion of network boundaries, seccomp filters, and gateway tenant rejections

## Phase 3 — Audit Trail Hardening
- [x] Append-only SHA-256 hash-chain logger (`audit/chain.py`)
- [x] Canonical JSON serialization (`sort_keys=True`, deterministic formatting)
- [x] Standalone verification CLI (`audit/verify.py`)
- [x] Automated unit test suite (`audit/test_chain.py`) covering genesis, sequential chaining, and tampering
- [x] Concurrency-safe file write locking with `threading.Lock` under high-load stress testing (`audit/test_concurrency.py`)
- [x] Architectural Decision Record & Log rotation strategy documented (`audit/storage-decision.md`)

## Phase 4 — Red-Team Attack Harness
- [x] Curated 10 adversarial payloads in `attacks/payloads.json` (AdvBench, JailbreakBench, Bayora Benchmark)
- [x] Automated attack runner (`attacks/run-attack.py` and `attacks/run_attack.py`) with tenant header dispatch and result logging
- [x] Cross-tenant session contamination test asserting zero state bleeding between blue-team and red-team
- [x] Automated markdown evaluation report generation (`attacks/attack-report.md`)
- [x] Unit test suite (`attacks/test_attacks.py`) asserting schema validity, IOC detection, and report formatting

## Phase 5 — Access Control & Secrets
- [x] Replace self-declared `X-Source-Tenant` header with cryptographic API keys (`X-Tenant-Key` & `Authorization: Bearer <key>`)
- [x] Secret injection via environment variables (`REDTEAM_API_KEY`, `BLUETEAM_API_KEY`) with `.env.example` template
- [x] Automatic detection and rejection of cross-tenant credential spoofing/mismatch
- [x] Cryptographic audit logging of all authentication failures and security rejections

## Phase 6 — Testing & CI
- [x] Unit test suites across all modules (`audit`, `gateway`, `isolation`, `attacks`)
- [x] Concurrency load stress test (`audit/test_concurrency.py`)
- [x] Unified test runner script (`run_tests.py`) executing 20 automated tests
- [x] GitHub Actions CI pipeline (`.github/workflows/ci.yml`) enforcing isolation, tamper-detection, and linting on push/PR

## Phase 7 — Observability & Anomaly Detection
- [x] Structured request/rejection metrics endpoint (`/metrics`)
- [x] Sliding-window burst attack anomaly detection trigger
- [x] Verification that observability metrics do not leak cross-tenant prompt data (`test_metrics_no_payload_leakage`)

## Phase 8 — Threat Model & Documentation
- [x] Complete `docs/threat-model.md` (trust boundaries, protected assets, non-goals, residual risks)
- [x] Complete `docs/architecture.md` (network packet flow and isolation mechanisms)

## Phase 9 — Deployment Readiness
- [x] Cloud VM deployment runbook (`docs/runbook.md`)
- [x] Credential rotation and broken audit chain disaster recovery runbooks

---

## Known Gaps & Explicit Assumptions
1. **Host Kernel Compromise**: Single-host Docker container isolation does not defend against a compromised Linux kernel or kernel zero-day escapes (explicitly out of scope per PRD).
2. **Timing Side Channels**: Micro-architectural timing side channels (e.g., KV-cache timing variations during Ollama inference) are not fully eliminated in software-only isolation.
3. **Tenant Auth in Early Phases**: `X-Source-Tenant` is treated as a developmental tag until Phase 5 cryptographic token enforcement is implemented.
