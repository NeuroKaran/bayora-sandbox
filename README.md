# Bayora Sandbox 🛡️

**Secure Adversarial AI Safety Testing Infrastructure**

Bayora Sandbox provides a cryptographically observable, multi-tenant isolated execution environment for evaluating adversarial attacks against language models, red-teaming AI agents, and verifying containment without cross-tenant contamination.

---

## 1. Problem Statement

Evaluating autonomous AI agents and language models against adversarial attacks requires running concurrent workloads across distinct trust boundaries:
- **Red Team**: Executes untrusted payloads, prompt injections, and jailbreaks. Red-team activity must not leak to or be observable by the blue team before tests conclude.
- **Blue Team**: Operates detection mechanisms, safety filters, and mitigation harnesses without exposing defensive heuristics to red-team probing.
- **Client LLM**: Must remain an uncontaminated black box under test across sessions with zero cross-tenant memory or state bleeding.
- **Audit & Governance**: Requires an append-only, tamper-evident cryptographic record guaranteeing non-repudiation and verifiable test reproducibility.

---

## 2. Architecture

```
       redteam-net                    blueteam-net
  (172.28.10.0/24)                 (172.28.20.0/24)
            │                                │
            ▼                                ▼
       ┌──────────┐                     ┌──────────┐
       │ red-team │                     │blue-team │
       └────┬─────┘                     └────┬─────┘
            │                                │
            └──────────────► ┌──────────────┐ ◄────────┘
                             │ llm-gateway  │ (Port 8000)
                             └──────┬───────┘
                                    │
                                    │ client-net (internal: true)
                                    │ (172.28.30.0/24)
                                    ▼
                             ┌──────────────┐
                             │  client-llm  │ (Ollama / Qwen2.5:3b)
                             └──────────────┘
                                    ▲
                                    │
                             ┌──────────────┐
                             │ Hash-Chain   │ (audit/chain.py)
                             │ Audit Trail  │ (audit/log.jsonl)
                             └──────────────┘
```

### Architectural Guarantees
1. **Single Chokepoint**: `llm-gateway` is the only service attached to all networks.
2. **Strict Network Isolation**: `client-llm` is placed on an isolated internal network (`client-net`) with zero external internet access and no direct route from `red-team` or `blue-team`.
3. **Pre-Response Cryptographic Audit**: Every prompt and completion passing through `llm-gateway` is appended to the SHA-256 hash-chain (`audit/log.jsonl`) before the HTTP response is returned.

---

## 3. Directory Structure

```text
bayora-sandbox/
├── PRD.md                  # Complete product requirements & phased roadmap
├── README.md               # Quickstart, architecture, and operation guide
├── TODO.md                 # Live roadmap tracking implementation status
├── LICENSE                 # MIT License
├── requirements.txt        # Pinned root dependencies (FastAPI, uvicorn, requests)
├── docker-compose.yml      # Multi-network sandbox topology
│
├── gateway/                # LLM Gateway Service
│   ├── Dockerfile          # Container specification
│   ├── main.py             # FastAPI proxy, tenant tagging, audit hook
│   └── requirements.txt    # Service dependencies
│
├── audit/                  # Cryptographic Tamper-Evident Audit System
│   ├── __init__.py         # Package exports
│   ├── chain.py            # SHA-256 hash-chain logger & verification
│   ├── verify.py           # Standalone verification CLI
│   ├── test_chain.py       # Comprehensive unit tests
│   └── log.jsonl           # Append-only hash chain log (git-ignored)
│
├── attacks/                # Red-Team Attack Harness
│   ├── payloads.json       # Curated adversarial payloads (AdvBench / Jailbreak)
│   └── run-attack.py       # Automated attack runner & reporting
│
├── isolation/              # OS-Level & Container Hardening
│   ├── seccomp-blueteam.json
│   ├── seccomp-redteam.json
│   └── network-notes.md
│
└── docs/                   # System Documentation
    ├── architecture.md     # Detailed network & security topology
    └── threat-model.md     # Assets, threats, mitigations, and non-goals
```

---

## 4. Quickstart

### Prerequisites
- Docker & Docker Compose (v2.20+)
- Python 3.11+ (for local development and verification)

### Running with Docker Compose

1. **Start the complete sandbox stack:**
   ```bash
   docker compose up --build
   ```

2. **Verify gateway health:**
   ```bash
   curl http://localhost:8000/health
   ```
   *Expected response:*
   ```json
   {"status": "healthy", "timestamp": 1790520000.0}
   ```

3. **Dispatch a prompt through the Gateway:**
   ```bash
   curl -X POST http://localhost:8000/prompt \
     -H "Content-Type: application/json" \
     -H "X-Source-Tenant: red-team" \
     -d '{"prompt": "Explain the principle of least privilege in container security."}'
   ```

4. **Verify the tamper-evident audit log:**
   ```bash
   python audit/verify.py
   ```

---

## 5. Local Development (Without Docker)

1. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Run audit hash-chain unit tests:**
   ```powershell
   python -m unittest audit/test_chain.py
   ```

3. **Run gateway locally:**
   ```powershell
   uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --reload
   ```

---

## 6. Security Guarantees & Verification

- **Genesis Block**: Initiates with 64 zero-bytes (`0`*64).
- **Block Integrity**: `hash = SHA256(prev_hash + canonical_json(block_payload))`.
- **Tamper Detection**: Any modification to historical entries, ordering, or timestamps breaks subsequent hashes and is flagged immediately by `python audit/verify.py`.
