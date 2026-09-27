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
- [x] Concurrency-safe file write locking with `threading.Lock`
- [ ] Multi-process / inter-container file locking (fcntl / flock for shared volumes)
- [ ] Documented rotation strategy & hash-pinned daily archives

## Phase 4 — Red-Team Attack Harness
- [ ] Curate 10–15 adversarial prompts in `attacks/payloads.json` (AdvBench & JailbreakBench)
- [ ] Implement `attacks/run-attack.py` with tenant header dispatch and result logging
- [ ] Cross-session state leakage / contamination test
- [ ] Automated markdown / JSON test summary report generator

## Phase 5 — Access Control & Secrets
- [ ] Replace self-declared `X-Source-Tenant` header with cryptographic API keys or signed bearer tokens
- [ ] Secret injection via Docker secrets / environment variables
- [ ] Audit log rejected authentication attempts as security anomalies

## Phase 6 — Testing & CI
- [x] Audit hash chain unit tests (`audit/test_chain.py`)
- [ ] Gateway unit & integration tests with `httpx` / `pytest`
- [ ] GitHub Actions CI workflow (`.github/workflows/ci.yml`) running linting, unit tests, and tamper verification
- [ ] Automated negative isolation test in CI

## Phase 7 — Observability & Anomaly Detection
- [ ] Structured request/rejection metrics endpoint (`/metrics`)
- [ ] Anomaly detection trigger on burst tenant authorization rejections
- [ ] Audit verification that observability metrics do not leak cross-tenant prompt data

## Phase 8 — Threat Model & Documentation
- [ ] Complete `docs/threat-model.md` (trust boundaries, protected assets, non-goals, residual risks)
- [ ] Complete `docs/architecture.md` (network packet flow and isolation mechanisms)

## Phase 9 — Deployment Readiness
- [ ] Cloud VM deployment runbook
- [ ] Reverse-proxy TLS termination configuration (Caddy / Nginx)
- [ ] Disaster recovery runbook: responding to broken audit chains

---

## Known Gaps & Explicit Assumptions
1. **Host Kernel Compromise**: Single-host Docker container isolation does not defend against a compromised Linux kernel or kernel zero-day escapes (explicitly out of scope per PRD).
2. **Timing Side Channels**: Micro-architectural timing side channels (e.g., KV-cache timing variations during Ollama inference) are not fully eliminated in software-only isolation.
3. **Tenant Auth in Early Phases**: `X-Source-Tenant` is treated as a developmental tag until Phase 5 cryptographic token enforcement is implemented.
