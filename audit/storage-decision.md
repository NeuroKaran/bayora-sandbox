# Architectural Decision Record (ADR): Audit Log Storage & Verification Strategy 📜

## Status
Accepted — Phase 3 Deliverable

## Context
Bayora Sandbox requires a tamper-evident, independently verifiable audit trail that records all evaluations, prompt interactions, model completions, and security rejections. In multi-tenant environments, the audit log guarantees non-repudiation and proves that neither the red team nor blue team altered evaluation artifacts or findings.

We evaluated two architectural patterns for log durability:
1. **Local Single-Writer Append-Only File with Cryptographic Hash-Chain (Selected)**
2. **Distributed Merkle Tree / Write-Once Remote Object Store (Future / Phase 9)**

---

## Decision
For the current single-host Docker Compose deployment, we select **Option 1: Local Single-Writer Append-Only Hash Chain** (`audit/log.jsonl`) managed exclusively by the `llm-gateway` process.

### Rationale
1. **Single Chokepoint Architecture**: The `llm-gateway` is the only service connected to all three networks (`redteam-net`, `blueteam-net`, `client-net`). Tenant workloads (`bayora-redteam` and `bayora-blueteam`) have no direct filesystem write access to the audit directory; they communicate strictly over HTTP.
2. **Zero Proprietary Hardware/Cloud Dependency**: Fulfills PRD Goal G3 (runs out-of-the-box on standard developer laptops and cloud VMs without requiring AWS S3 Object Lock, GCP Retention Policies, or specialized hardware security modules).
3. **Provable Tamper Evidence**: Each block includes `prev_hash = SHA256(previous_block)` and canonical JSON sorting (`sort_keys=True`). Any out-of-band modification or truncation is deterministically detected by `audit/verify.py`.
4. **Thread-Safe In-Memory Chaining**: Concurrency is locked per-process via `threading.Lock()` guaranteeing strictly ordered sequential block indices (`index = 0, 1, 2...`).

---

## Log Rotation & Archival Strategy

1. **Daily Rotation**: Log files are partitioned daily: `audit/log-YYYY-MM-DD.jsonl`.
2. **Cross-Day Hash Pinning**: The genesis block (`index = 0`) of day `N+1` pins the terminal hash of day `N` in its `prev_hash` field instead of the zero-hash (`0`*64):
   $$\text{prev\_hash}_{N+1, 0} = \text{hash}_{N, \text{final}}$$
   This maintains cryptographic continuity indefinitely across rotated files without unbounded log growth.
3. **Offline Anchoring**: Terminal daily hashes can be committed to Git or external transparency logs for public proof of existence.

---

## Future Evolution (Phase 9 & Production Multi-Host)
When migrating to a multi-node Kubernetes cluster with multiple gateway replicas:
- Transition from local append-only files to an RFC 6962 compliant Merkle Tree service (e.g., Sigstore Trillian or AWS S3 Object Lock in WORM compliance mode).
- Replace symmetric SHA-256 chaining with asymmetric digital signatures (Ed25519) on each block header.
