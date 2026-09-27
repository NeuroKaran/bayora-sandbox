# Bayora Sandbox: System Architecture Specification 🏛️

**Document Status:** Final (Phase 8 Baseline)  
**Applicability:** Production Engineering & Operations  

---

## 1. Top-Level Architectural Model

Bayora Sandbox is a multi-tier, zero-trust execution sandbox designed for executing untrusted adversarial tests against language models. The system enforces strict physical-like network isolation and cryptographic non-repudiation on standard cloud infrastructure.

```
       ┌────────────────────────┐                   ┌────────────────────────┐
       │     bayora-redteam     │                   │    bayora-blueteam     │
       │  (Adversarial Runner)  │                   │   (Defense Scanners)   │
       │   UID: 10001 (Alpine)  │                   │   UID: 10001 (Alpine)  │
       │  Read-Only / Cap: None │                   │  Read-Only / Cap: None │
       │  Seccomp Syscall Drop  │                   │  Seccomp Syscall Drop  │
       └───────────┬────────────┘                   └───────────┬────────────┘
                   │                                            │
   bayora-redteam-net (172.28.10.0/24)          bayora-blueteam-net (172.28.20.0/24)
                   │                                            │
                   └─────────────────────┐ ┌────────────────────┘
                                         ▼ ▼
                          ┌────────────────────────────────┐
                          │       bayora-llm-gateway       │
                          │   FastAPI Chokepoint (Port 8000)│
                          │ - Multi-Tenant Token Auth      │
                          │ - Header Spoofing Detection    │
                          │ - Telemetry & Anomaly Alerts   │
                          │ - Pre-Response Audit Logger    │
                          └──────────────┬─────────────────┘
                                         │
                         bayora-client-net (172.28.30.0/24)
                         (internal: true - Zero WAN Access)
                                         │
                                         ▼
                          ┌────────────────────────────────┐
                          │       bayora-client-llm        │
                          │   Ollama Black-Box Container   │
                          │     qwen2.5-coder:3b Model     │
                          │   stateless / air-gapped       │
                          └────────────────────────────────┘
                                         │
                          ┌──────────────┴─────────────────┐
                          │   Append-Only Audit Chain      │
                          │  audit/log.jsonl (SHA-256)     │
                          │  - Genesis: 64 zero bytes      │
                          │  - Atomic write lock           │
                          │  - Independent CLI verifier    │
                          └────────────────────────────────┘
```

---

## 2. Microservice Topology & Responsibilities

### 1. `bayora-llm-gateway`
- **Role:** Central gateway, sole multi-homed container connected to all three networks.
- **Port:** Exposed to host on `8000:8000` (or configured via `${GATEWAY_PORT}`).
- **Key Responsibilities:**
  1. Authenticates tenant tokens (`X-Tenant-Key` or `Authorization: Bearer <token>`).
  2. Rejects cross-tenant mismatches (e.g. Red-Team key declaring Blue-Team identity).
  3. Records all requests, completions, latencies, and security rejections into the audit chain before returning HTTP responses.
  4. Exposes `/health` and `/metrics` (zero prompt or payload data leakage).

### 2. `bayora-client-llm`
- **Role:** Model execution runtime (Ollama serving `qwen2.5-coder:3b`).
- **Network:** Bound exclusively to `client-net` (`172.28.30.0/24`).
- **Containment:** Zero access to `redteam-net` or `blueteam-net`. Completely isolated from public WAN when `internal: true` is active.

### 3. `bayora-redteam` & `bayora-blueteam`
- **Role:** Isolated tenant workers.
- **Containment:**
  - Non-root UID/GID: `10001:10001`.
  - Dropped Linux Capabilities: `cap_drop: [ALL]`.
  - Read-Only root filesystem with restricted tmpfs.
  - Seccomp profiles blocking `ptrace`, `bpf`, `mount`, `unshare`, and kernel modification.
  - Cgroup limits: 1.0 CPU, 512MB RAM.

---

## 3. Cryptographic Audit Log Protocol

Every transaction passing through the gateway is serialized into an immutable block:

```json
{
  "index": 1,
  "timestamp": 1790520000.123,
  "prev_hash": "3b234cfd4306f035a67dfea336318b6ee966836898550648250e6d904c00ce1a",
  "hash": "6a7101cdb448284570e6ede933a343c7f1c3581fb42fcca01f2c5716c5731943",
  "source": "red-team",
  "model": "qwen2.5-coder:3b",
  "request": "Ignore previous guidelines.",
  "response": "I cannot fulfill this request.",
  "latency": 0.421,
  "status": "ok"
}
```

### Cryptographic Invariants:
1. **Genesis Block:** Block #0 must have `prev_hash == "0"*64`.
2. **Canonical Hash Calculation:**
   $$\text{hash}_i = \text{SHA256}(\text{CanonicalJSON}(\text{block}_i \setminus \{\text{hash}\}))$$
3. **Link Continuity:**
   $$\text{block}_i[\text{"prev\_hash"}] == \text{block}_{i-1}[\text{"hash"}]$$
4. **Sequential Indexing:**
   $$\text{block}_i[\text{"index"}] == i$$

---

## 4. Anomaly Detection & Observability

The `/metrics` endpoint exposes real-time operational telemetry without cross-tenant information bleeding:
- **Tenant Counters:** Total requests and error counts per tenant.
- **Latency Tracker:** Cumulative inference latency per tenant.
- **Sliding-Window Rejection Rate:** Tracks unauthorized / forged requests over a 60-second window.
- **Security Anomaly Alert:** If an adversary fires $\ge 5$ unauthorized attempts within 60s, `security_anomaly_alert` trips `true`, signalling an active credential bruteforce or injection probe.
