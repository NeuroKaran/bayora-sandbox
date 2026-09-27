# PRD: Bayora Sandbox — Secure Adversarial AI Safety Testing Infrastructure

## Status
Draft — hackathon prototype exists (gateway skeleton, hash-chain audit logger). This document defines the path from prototype to production-ready.

## 1. Problem Statement

Bayora's red team, blue team, and client LLM must run concurrently in a shared environment while remaining isolated from each other. Specifically:

- Red-team attack payloads must not be observable by the blue team before a test concludes.
- Blue-team defensive logic must not be exposed to or inferable by red-team tooling.
- The client LLM must remain clean and uncontaminated across sessions.
- Safety findings must not be invalidated by environmental leakage or cross-tenant interference.

## 2. Goals

- G1: Strong, provable isolation between red-team, blue-team, and client-LLM workloads.
- G2: Tamper-evident, independently verifiable audit trail of all evaluation activity.
- G3: A working system deployable on standard cloud infrastructure with no proprietary hardware dependency.
- G4: A written, specific threat model — what is protected, what is not, and under what conditions guarantees fail.
- G5: Observability that detects cross-boundary access without becoming its own leakage channel.

## 3. Non-Goals (for this version)

- NG1: Training or fine-tuning any model. The client LLM is treated as a black box under test.
- NG2: Full multi-tenant SaaS product (billing, org management, user accounts). This is infrastructure, not a hosted product — yet.
- NG3: Defending against a fully compromised host kernel. Out of scope; documented as an explicit assumption in the threat model.
- NG4: Exotic side channels (e.g. full KV-cache timing side-channel closure) beyond basic mitigation and honest disclosure in the threat model.

## 4. Current State (baseline)

- `gateway/` — FastAPI service, proxies prompts to Ollama, tags requests by `X-Source-Tenant` header, logs every call.
- `audit/chain.py` — hash-chained JSONL logger (`sha256(prev_hash + canonical_json(entry))`).
- `docker-compose.yml` (partial) — `client-llm` (Ollama) on an `internal: true` network, reachable only via `llm-gateway`.
- No isolation enforcement yet beyond network topology (no seccomp, no cgroup limits, no verified chain-integrity check, no red/blue containers, no CI, no auth on the gateway itself).

## 5. Architecture Summary

```
 redteam-net          blueteam-net
      |                    |
      +------ llm-gateway--+
                 |
            client-net (internal only)
                 |
             client-llm (Ollama)
```

- `llm-gateway` is the single chokepoint. It is the only service on all three networks.
- `client-llm` has no route to anything except the gateway.
- Every call through the gateway is written to the hash chain before the response is returned.

## 6. Build Phases

Each phase has a concrete deliverable and an explicit "done" condition. Phases are ordered by dependency, not by importance — do not skip ahead if a dependency is unmet.

---

### Phase 0 — Repo & Environment Hygiene
**Deliverable:** Clean, cloneable repo any collaborator (or future you) can stand up in under 10 minutes.

- [ ] `.gitignore` covers `.venv/`, `log.jsonl`, `__pycache__/`, `ollama-data/`, `.env`
- [ ] `README.md` has: problem statement, architecture diagram (ASCII is fine), setup steps, how to run the attack demo
- [ ] `TODO.md` exists and is kept current — known gaps, explicitly listed
- [ ] `requirements.txt` (root, for local dev) and per-service `requirements.txt` (for Docker builds) both pinned to exact versions
- [ ] `LICENSE` chosen

**Done when:** a fresh clone + `docker compose up` gets a working stack with no manual fixes.

---

### Phase 1 — Core Services Running End to End
**Deliverable:** `client-llm`, `llm-gateway` reachable and functional through Docker Compose.

- [ ] Ollama container pulls and serves `qwen2.5:3b-instruct` (or documented alternative)
- [ ] Gateway container builds, copies in `audit/chain.py` correctly (resolve the `sys.path` hack from prototype — package it properly or mount as a shared volume/module)
- [ ] `/health` endpoint returns 200
- [ ] `/prompt` endpoint round-trips a real prompt through Ollama and returns a response
- [ ] Every call produces exactly one audit log entry, with correct `prev_hash` chaining

**Done when:** `curl -X POST llm-gateway/prompt -H "X-Source-Tenant: red-team" -d '{"prompt": "hello"}'` returns a real model response and a new line appears in `log.jsonl`.

---

### Phase 2 — Isolation Enforcement
**Deliverable:** Red-team and blue-team containers exist, cannot see or reach each other, and this is independently testable.

- [ ] `redteam` and `blueteam` containers added to compose, each only on their respective network + reachable to `llm-gateway`, never to each other
- [ ] Seccomp profile per container — deny `ptrace`, `mount`, other high-risk syscalls not needed for the workload
- [ ] cgroup limits set (CPU, memory) per container — ties to resource-governance goal (G1) and prevents timing/DoS side effects between tenants
- [ ] Rootless container execution where possible
- [ ] Explicit negative test: attempt `redteam` → `blueteam` network call, confirm it fails and is logged as a rejected/blocked event

**Done when:** an automated test script (Phase 6) can assert isolation programmatically, not just "we tried it once and it worked."

---

### Phase 3 — Audit Trail Hardening
**Deliverable:** Audit log is genuinely tamper-evident and independently verifiable, not just hash-chained in theory.

- [ ] `audit/verify.py` — walks the full chain, recomputes each hash, reports the first broken link if any
- [ ] Canonical JSON serialization locked down (`sort_keys=True`, fixed float precision) so hash verification is reproducible across machines
- [ ] Concurrency-safe writes confirmed under load (multiple simultaneous requests do not corrupt the chain)
- [ ] Log rotation / archival strategy defined (even if just "append-only file, rotated daily, old files hash-pinned into the new file's first entry")
- [ ] Decide and document: is single-writer-local-file sufficient, or does this need to move to an append-only store (e.g. a write-once object store, or a simple Merkle log service)? Document the decision and why.

**Done when:** deliberately editing a line in `log.jsonl` and running `verify.py` correctly identifies the tampered entry.

---

### Phase 4 — Red-Team Attack Harness
**Deliverable:** Repeatable, scripted attack runs against the sandbox using real payloads.

- [ ] `attacks/payloads.json` — curated subset (5–15) from AdvBench / JailbreakBench, with source attribution
- [ ] `attacks/run_attack.py` — fires each payload through the gateway as `red-team`, records model response + whether isolation held
- [ ] Cross-session contamination test: fire sequential prompts from different declared tenants, verify no conversation state leaks between them
- [ ] Results summarized in a simple report (pass/fail per payload, plus latency)

**Done when:** running the harness produces a reproducible report without manual steps.

---

### Phase 5 — Access Control & Secrets
**Deliverable:** The gateway itself is not an open door — tenant identity is enforced, not just self-declared.

- [ ] Replace the self-declared `X-Source-Tenant` header with real auth (API keys or mTLS certs per tenant, minimum viable: signed tokens issued per container at startup)
- [ ] Any secrets (API keys, model paths, cert material) loaded via environment/secret file, never hardcoded, never committed
- [ ] Principle of least privilege reviewed for every container: does it have any capability it doesn't strictly need?

**Done when:** a request with a forged or missing tenant credential is rejected and logged as a security event, not silently trusted.

---

### Phase 6 — Testing & CI
**Deliverable:** Automated verification that isolation and audit properties hold on every change.

- [ ] Unit tests: `chain.py` (hash correctness, tamper detection), gateway request handling
- [ ] Integration test: full compose stack up, isolation negative-tests (Phase 2) run automatically, attack harness (Phase 4) runs automatically
- [ ] CI pipeline (GitHub Actions or equivalent): runs on every push, fails the build if isolation or chain-integrity tests fail
- [ ] Basic load test: confirm cgroup limits actually prevent one tenant from starving another under concurrent load

**Done when:** a pull request that reintroduces a cross-tenant leak fails CI automatically, without a human needing to notice it.

---

### Phase 7 — Observability & Anomaly Detection
**Deliverable:** Cross-boundary attempts and unusual activity are visible without the monitoring layer itself becoming a leakage channel.

- [ ] Structured metrics (request counts, latency, rejection counts) exposed per tenant
- [ ] Alerting rule for repeated rejected cross-tenant attempts (possible active attack, not just noise)
- [ ] Confirm the observability layer itself cannot be used to infer blue-team logic or red-team payloads (e.g. aggregate metrics only, no raw payload exposure across tenant boundaries)

**Done when:** a deliberate cross-boundary attempt shows up in monitoring within seconds, and a review of what the monitoring layer exposes confirms no cross-tenant data leaks through it.

---

### Phase 8 — Threat Model & Documentation
**Deliverable:** `docs/threat-model.md` finalized as a first-class artifact, not an afterthought.

- [ ] What the architecture protects against (with evidence — link to the specific test in Phase 2/6 that proves it)
- [ ] What it explicitly does not protect against (named, not vague — e.g. "no defense against a compromised host kernel," "KV-cache timing side channels not closed, only rate-limited")
- [ ] Conditions under which guarantees could fail
- [ ] Future improvements required for stronger guarantees
- [ ] `docs/architecture.md` finalized with accurate diagram matching actual deployed topology

**Done when:** someone unfamiliar with the project can read this doc alone and understand exactly where the trust boundary is and isn't.

---

### Phase 9 — Deployment Readiness
**Deliverable:** Runs on standard cloud infrastructure, not just a laptop.

- [ ] Compose stack ported to a deployment target (single VM with Docker, or a minimal Kubernetes manifest — pick one, document why)
- [ ] TLS termination for the gateway if exposed beyond localhost
- [ ] Resource limits validated against real cloud instance sizing (not just local defaults)
- [ ] Runbook: how to deploy, how to rotate credentials, how to respond if the audit chain shows tampering

**Done when:** the system can be stood up on a fresh cloud VM from the repo alone, following only the runbook.

---

## 7. Acceptance Criteria (project-level)

The project is "production-ready" when:
1. Isolation between tenants is enforced and covered by automated tests (not manual spot-checks).
2. The audit log's tamper-evidence is independently verifiable by a script, not just asserted in docs.
3. A real attack run against the sandbox produces a reproducible, logged result.
4. The threat model names specific unprotected risks rather than claiming general security.
5. CI blocks any change that breaks isolation or chain integrity.
6. The stack deploys to a real cloud VM from a clean clone.

## 8. Tech Stack

- **Runtime:** Docker / Docker Compose (rootless where possible)
- **Model serving:** Ollama, `qwen2.5:3b-instruct` (swap-in capable for larger models given more compute)
- **Gateway:** Python 3.11, FastAPI, Uvicorn
- **Audit:** stdlib `hashlib` + `json`, JSONL storage
- **Isolation:** Linux seccomp profiles, network namespaces via Docker networks, cgroup limits
- **Attack payloads:** AdvBench, JailbreakBench (subset, attributed)
- **CI:** GitHub Actions (or equivalent)

## 9. Known Risks / Open Questions

- Single-host deployment does not defend against a compromised host kernel — assumption, not a gap to silently ignore.
- Local single-writer audit log may not scale to a distributed setup; Phase 3 decision needs revisiting if this moves to multi-host.
- Self-declared tenant identity (pre–Phase 5) is not secure by itself — do not demo or deploy this as if it were, before Phase 5 lands.
- Small local model (3B params) has weaker safety behavior than production-grade LLMs — results from the attack harness characterize the sandbox's isolation properties, not the model's own safety quality. Keep these framed separately in any write-up.

## 10. Future Work (explicitly out of scope for this version)

- KV-cache and other exotic LLM-specific side-channel closure
- Multi-node / distributed deployment
- Full RBAC and multi-org support
- Formal verification of isolation guarantees