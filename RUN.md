# Bayora Sandbox — Execution & Operator Guide (`RUN.md`) 🚀

This guide provides end-to-end instructions for running, testing, and evaluating the **Bayora Sandbox** environment both with **Docker Compose** (full containerized isolation) and **Locally** (rapid development mode).

---

## 1. Prerequisites

- **Python:** 3.11 or 3.12
- **Docker & Docker Compose:** Version 2.20+ *(required for container network & seccomp isolation)*
- **Ollama:** Version 0.3+ *(if running locally outside Docker)*
  - Default Model: `qwen2.5-coder:3b` (or `lfm2.5-thinking:1.2b`)

---

## 2. Environment Configuration

The repository uses [`.env`](.env) for runtime configuration. A template is provided in [`.env.example`](.env.example).

Create or inspect your [`.env`](.env) file:

```ini
# Target client model served by Ollama
MODEL_NAME=qwen2.5-coder:3b

# Ollama Endpoint
# - For Docker Compose: http://client-llm:11434/api/generate
# - For Local Host dev: http://localhost:11434/api/generate
OLLAMA_URL=http://client-llm:11434/api/generate

# Gateway Port & Host
GATEWAY_PORT=8000
GATEWAY_HOST=0.0.0.0

# Audit Hash Chain File
BAYORA_AUDIT_LOG=audit/log.jsonl

# Allowed Tenants
ALLOWED_TENANTS=red-team,blue-team

# Phase 5 Cryptographic Tenant Keys
REDTEAM_API_KEY=bayora-redteam-live-secret-key-9f8a2
BLUETEAM_API_KEY=bayora-blueteam-live-secret-key-3c7d1
```

---

## 3. Method 1: Running with Docker Compose (Recommended)

This mode stands up the complete multi-tenant zero-trust topology:
- `bayora-client-llm` (Ollama black-box on air-gapped `client-net`)
- `bayora-model-init` (Auto-pulls `qwen2.5-coder:3b`)
- `bayora-llm-gateway` (FastAPI single chokepoint + SHA-256 auditor)
- `bayora-redteam` (Restricted container with seccomp filter on `redteam-net`)
- `bayora-blueteam` (Restricted container with seccomp filter on `blueteam-net`)

### Step 1: Start the Entire Stack
```bash
docker compose up --build -d
```

### Step 2: Verify Service Status
```bash
docker compose ps
```
*All services should show `Up` or `running` (with `bayora-model-init` exiting cleanly once model weights are confirmed).*

### Step 3: Check Gateway Health
```bash
curl http://localhost:8000/health
```
**Expected Output:**
```json
{
  "status": "healthy",
  "model": "qwen2.5-coder:3b",
  "ollama_url": "http://client-llm:11434/api/generate",
  "timestamp": 1790520000.0
}
```

### Step 4: Dispatch an Authorized Prompt via cURL
```bash
curl -X POST http://localhost:8000/prompt \
  -H "Content-Type: application/json" \
  -H "X-Source-Tenant: red-team" \
  -H "X-Tenant-Key: bayora-redteam-live-secret-key-9f8a2" \
  -d '{"prompt": "Write a 1-line Python function to compute SHA-256."}'
```

### Step 5: Test Security Rejection (Cross-Tenant Spoofing Attempt)
Try presenting a Red-Team key while claiming to be Blue-Team:
```bash
curl -X POST http://localhost:8000/prompt \
  -H "Content-Type: application/json" \
  -H "X-Source-Tenant: blue-team" \
  -H "X-Tenant-Key: bayora-redteam-live-secret-key-9f8a2" \
  -d '{"prompt": "Probe internal rules."}'
```
**Expected Response:** `HTTP 403 Forbidden` (`Credential belongs to 'red-team', but header claimed 'blue-team'`). This rejection is automatically logged as a security anomaly in the audit chain.

### Step 6: Run the Red-Team Adversarial Attack Harness Inside the Container
Execute the evaluation suite from within the isolated Red-Team container:
```bash
docker exec -it bayora-redteam python3 /home/sandboxuser/workspace/attacks/run-attack.py --gateway http://llm-gateway:8000
```

### Step 7: Verify Cryptographic Audit Chain on the Host
```bash
python audit/verify.py
```
**Expected Output:**
```text
======================================================
  BAYORA SANDBOX - AUDIT HASH CHAIN VERIFIER
======================================================
[*] Target Log: .../audit/log.jsonl
[*] Found N recorded block(s).
------------------------------------------------------------
...
[SUCCESS] Integrity Check Passed: Chain verified successfully (N blocks intact)
```

### Step 8: View Real-Time Observability & Anomaly Metrics
```bash
curl http://localhost:8000/metrics
```

---

## 4. Method 2: Running Locally Without Docker (Fast Dev Mode)

For development or environments where the Docker daemon is inactive.

### Step 1: Install Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 2: Configure `.env` for Local Host
In [`.env`](.env), change `OLLAMA_URL` to point to your local Ollama instance:
```ini
OLLAMA_URL=http://localhost:11434/api/generate
```

*(Ensure Ollama is running locally: `ollama run qwen2.5-coder:3b`)*

### Step 3: Launch the Gateway
```powershell
uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 4: Run the Red-Team Attack Suite
In a separate terminal:
```powershell
python attacks/run-attack.py --gateway http://localhost:8000
```
This generates a full markdown evaluation report in [`attacks/attack-report.md`](attacks/attack-report.md).

### Step 5: Verify the Audit Log
```powershell
python audit/verify.py
```

---

## 5. Running the Complete Automated Test Suite

Bayora Sandbox includes a unified test runner executing 22 unit, integration, and security tests across all modules:

```powershell
python run_tests.py
```

### What `run_tests.py` Validates:
1. **`audit/` (5 tests):**
   - Genesis block invariant (`0`*64 prev_hash)
   - Sequential block linking & SHA-256 digest computation
   - Data modification tampering detection
   - Out-of-order block injection detection
   - 50-thread concurrent write load stress test (`test_concurrency.py`)
2. **`gateway/` (8 tests):**
   - `/health` endpoint status
   - Request body validation
   - Cryptographic tenant API key authentication
   - Cross-tenant credential mismatch rejection
   - Upstream model round-trip & latency logging
   - Pre-response audit block commitment
   - `/metrics` telemetry output
   - Sliding-window burst attack anomaly alerts & zero payload leakage
3. **`isolation/` (5 tests):**
   - Seccomp JSON profile validation (blocks `ptrace`, `bpf`, `mount`, `unshare`, etc.)
   - Docker Compose multi-bridge network topology & cgroup limits
   - Cross-tenant unauthorized access rejection
   - Live container ping & netcat boundary probe tests
4. **`attacks/` (4 tests):**
   - Payload schema compliance & source attribution (AdvBench / JailbreakBench)
   - Model refusal containment detection
   - Indicator of Compromise (IOC) capture
   - Markdown report generation

---

## 6. Testing Tamper-Evidence (Deliberate Tamper Test)

To prove that the audit chain detects manual tampering or log doctoring:

1. View the verified log:
   ```powershell
   python audit/verify.py
   ```
2. Open [`audit/log.jsonl`](audit/log.jsonl) in an editor and alter any character (e.g., change `"status": "ok"` to `"status": "tampered"` in Block #0).
3. Re-run the verifier:
   ```powershell
   python audit/verify.py
   ```
   **Output:**
   ```text
   [FAIL] Tampering / Corruption Detected at Block #0: Block 0 hash tampered or corrupted!
   ```
4. Restore the line or delete [`audit/log.jsonl`](audit/log.jsonl) to start a clean genesis chain.

---

## 7. Useful Diagnostic Commands

| Action | Command |
| :--- | :--- |
| **View Live Container Logs** | `docker compose logs -f llm-gateway` |
| **Inspect Model Service Logs** | `docker compose logs -f client-llm` |
| **Open Red-Team Shell** | `docker exec -it bayora-redteam /bin/sh` |
| **Open Blue-Team Shell** | `docker exec -it bayora-blueteam /bin/sh` |
| **Verify Audit Chain** | `python audit/verify.py` |
| **Run All 22 Unit Tests** | `python run_tests.py` |
| **Run Attack Suite** | `python attacks/run-attack.py` |
| **Stop All Containers** | `docker compose down` |
| **Purge Volumes & Reset State** | `docker compose down -v` |
