# Bayora Sandbox: Threat Model & Security Posture 🛡️

**Document Status:** Final (Phase 8 Baseline)  
**Classification:** Security Architecture Reference  
**Applicability:** Single-Host Multi-Tenant Evaluation Environments  

---

## 1. System Overview & Trust Boundaries

Bayora Sandbox hosts adversarial evaluation workloads across three distinct trust domains running on shared compute:
1. **Red-Team Domain** (`bayora-redteam`, `172.28.10.0/24`): Untrusted. Originates known exploits, jailbreaks, prompt injections, and breakout probes.
2. **Blue-Team Domain** (`bayora-blueteam`, `172.28.20.0/24`): Semi-trusted. Operates defensive filters, evaluation telemetry, and benchmark scanners.
3. **Model & Core Domain** (`bayora-client-llm`, `172.28.30.0/24`): Air-gapped black box under test.
4. **Security Chokepoint & Auditor** (`bayora-llm-gateway`): Trusted intermediary spanning all networks.

```
       [Red-Team Container]                [Blue-Team Container]
         (Untrusted Actor)                   (Defensive Assessor)
        IP: 172.28.10.0/24                   IP: 172.28.20.0/24
                 │                                    │
                 │ (Blocked direct inter-bridge)      │
                 x - - - - - - - - - - - - - - - - - -x
                 │                                    │
    HTTP + Token │                                    │ HTTP + Token
                 ▼                                    ▼
         ┌────────────────────────────────────────────────────┐
         │             bayora-llm-gateway                     │
         │  - Cryptographic Tenant Auth (API Keys)            │
         │  - Cross-Tenant Mismatch Rejection                 │
         │  - SHA-256 Pre-Response Hash-Chain Logger          │
         │  - Anomaly Burst Rate Limiting                     │
         └─────────────────────────┬──────────────────────────┘
                                   │
                    HTTP Internal  │ (No WAN egress)
                    172.28.30.0/24 │
                                   ▼
                         ┌────────────────────┐
                         │ bayora-client-llm  │
                         │ (Ollama Black-Box) │
                         └────────────────────┘
```

---

## 2. Protected Assets

| Asset | Confidentiality | Integrity | Availability | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Blue-Team Defensive Logic** | **CRITICAL** | HIGH | MEDIUM | Heuristics and active canary tokens must never leak to red team. |
| **Red-Team Exploit Payloads** | **CRITICAL** | HIGH | MEDIUM | Payloads must not be prematurely observable by defense. |
| **Client Model Parameters & State** | HIGH | **CRITICAL** | HIGH | Model weights and runtime conversation memory must remain uncontaminated across sessions. |
| **Audit Hash-Chain Log** | MEDIUM | **CRITICAL** | **CRITICAL** | Append-only, verifiable record proving evaluation integrity and non-repudiation. |
| **Host Kernel & Compute** | **CRITICAL** | **CRITICAL** | **CRITICAL** | Host operating system must remain completely uncompromised. |

---

## 3. What the Architecture Protects Against (With Test Evidence)

### Threat 1: Lateral Cross-Tenant Network Movement
- **Threat:** Red-team container attempts to scan, probe, or communicate directly with blue-team tools or the client model.
- **Mitigation:** Independent user-defined Docker bridge networks (`redteam-net`, `blueteam-net`, `client-net`). The Linux kernel drops inter-bridge packets via Docker's default isolation iptables chains. Docker embedded DNS (`127.0.0.11`) responds with `NXDOMAIN` across unshared networks.
- **Verification Evidence:** [`isolation/test_isolation.py:TestLiveDockerIsolation`](file:///c:/Users/karan/Hackathon/bayora-sandbox/isolation/test_isolation.py) and [`TestIsolationSpecifications.test_docker_compose_network_boundaries`](file:///c:/Users/karan/Hackathon/bayora-sandbox/isolation/test_isolation.py).

### Threat 2: Tenant Identity Forgery & Impersonation
- **Threat:** Red-team attacker adds `X-Source-Tenant: blue-team` header to access defensive telemetry or bypass rules.
- **Mitigation:** Cryptographic API keys (`X-Tenant-Key` or `Authorization: Bearer <key>`) mapped strictly to authorized tenants. Any mismatch between presented key and claimed header immediately raises HTTP 403, and the security event is written to the cryptographic audit chain.
- **Verification Evidence:** [`gateway/test_gateway.py:test_cross_tenant_credential_mismatch_rejected`](file:///c:/Users/karan/Hackathon/bayora-sandbox/gateway/test_gateway.py).

### Threat 3: Audit Log Tampering, Truncation, or Repudiation
- **Threat:** Malicious process alters historical benchmark results or deletes records of failed jailbreaks.
- **Mitigation:** Append-only SHA-256 hash-chaining (`hash = SHA256(prev_hash + canonical_json(block))`). Any modified byte breaks the entire subsequent chain. Verification is automated via standalone CLI.
- **Verification Evidence:** [`audit/test_chain.py:test_tamper_detection_data`](file:///c:/Users/karan/Hackathon/bayora-sandbox/audit/test_chain.py) and [`test_tamper_detection_hash_recalculation`](file:///c:/Users/karan/Hackathon/bayora-sandbox/audit/test_chain.py).

### Threat 4: Container Breakout & Privilege Escalation
- **Threat:** Payload executes kernel exploit or attempts to load kernel modules from within tenant container.
- **Mitigation:** Containers run with non-root user (`UID 10001`), stripped SUID/SGID bits, `read_only: true` rootfs, `no-new-privileges:true`, `cap_drop: [ALL]`, and custom Seccomp profile blocking `ptrace`, `bpf`, `mount`, `unshare`, `kexec_load`, etc.
- **Verification Evidence:** [`isolation/test_isolation.py:test_seccomp_profiles_syntax_and_critical_blocks`](file:///c:/Users/karan/Hackathon/bayora-sandbox/isolation/test_isolation.py).

### Threat 5: Cross-Session State Bleeding
- **Threat:** Model retains conversation context from blue-team session that leaks into subsequent red-team queries.
- **Mitigation:** Stateless generation calls per prompt; automated canary-token contamination tests assert zero state retention between sessions.
- **Verification Evidence:** [`attacks/test_attacks.py`](file:///c:/Users/karan/Hackathon/bayora-sandbox/attacks/test_attacks.py) and [`attacks/run-attack.py:run_cross_session_contamination_test`](file:///c:/Users/karan/Hackathon/bayora-sandbox/attacks/run-attack.py).

---

## 4. What the Architecture Explicitly Does NOT Protect Against (Residual Risks)

1. **Compromised Host Kernel (Out of Scope per PRD NG3):**
   - Single-host Docker containerization relies on a shared Linux kernel. If the host kernel itself is backdoored or suffers an unpatched zero-day privilege escalation that bypasses seccomp and namespaces, isolation guarantees fail.
   - *Requirement for stronger guarantee:* Hardware-virtualized microVMs (AWS Firecracker / Kata Containers) with dedicated guest kernels.

2. **Micro-Architectural Side Channels (KV-Cache Timing) (Out of Scope per PRD NG4):**
   - Hardware-level timing variations in GPU/CPU memory access during LLM attention or token generation can theoretically leak sequence lengths. These are rate-limited and logged, but hardware-level timing side channels are not cryptographically closed in software.

3. **Untrusted Host Root Administrators:**
   - Any actor with root privileges on the Docker host machine can inspect memory or write to local files out-of-band. Audit integrity in this version protects against tenant-level and application-level tampering, but not host-root compromise. (Phase 9 addresses this via remote S3 WORM replication).

---

## 5. Conditions Under Which Guarantees Fail

| Guarantee | Failure Condition | Blast Radius | Recovery Action |
| :--- | :--- | :--- | :--- |
| **Network Boundary** | Container started with `--net=host` or privileged mode | Attacker can reach all interfaces | Docker daemon enforcement policy blocks privileged containers |
| **Audit Non-Repudiation** | Local disk corrupted or physical drive loss | Inability to verify historical blocks | Restore from daily hash-pinned external archive |
| **Tenant Access Control** | `REDTEAM_API_KEY` leaked to adversary | Adversary can dispatch prompts as red-team | Rotate key in `.env` and restart gateway container |
