# Bayora Sandbox: Network Isolation Architecture & Threat Mitigation 🌐

## 1. Network Topology Overview

Bayora Sandbox enforces strict network-layer isolation through Docker user-defined bridge networks with dedicated IPAM subnets:

| Network Name | Subnet | Connected Services | Egress Policy |
| :--- | :--- | :--- | :--- |
| **`redteam-net`** | `172.28.10.0/24` | `redteam`, `llm-gateway` | Gateway only; no route to blue-team or model |
| **`blueteam-net`** | `172.28.20.0/24` | `blueteam`, `llm-gateway` | Gateway only; no route to red-team or model |
| **`client-net`** | `172.28.30.0/24` | `client-llm`, `model-init`, `llm-gateway` | Air-gapped internal route; reachable only by gateway |

---

## 2. Kernel & Bridge Isolation Mechanisms

### A. Docker Embedded DNS Scoping
Docker's internal DNS resolver (`127.0.0.11`) isolates name discovery strictly by network membership:
- `redteam` container querying `blueteam` or `client-llm` receives `NXDOMAIN`.
- Service discovery across tenant boundaries is cryptographically and logically suppressed.

### B. Linux `iptables` Inter-Bridge Filtering
When Docker creates multiple bridge networks, it installs default filtering rules in the `DOCKER-ISOLATION-STAGE-1` and `DOCKER-ISOLATION-STAGE-2` chains:
```text
Chain DOCKER-ISOLATION-STAGE-1:
- Packets arriving on br-redteam destined for br-blueteam are jumped to DOCKER-ISOLATION-STAGE-2
Chain DOCKER-ISOLATION-STAGE-2:
- Packets originating from another bridge interface are instantly DROPPED
```
Even if an attacker within `redteam` statically routes packets to `172.28.20.0/24` or `172.28.30.0/24`, the host kernel drops the packets at layer 3 before traversing the bridge boundary.

---

## 3. Negative Test Verification Matrix

| Source | Destination | Protocol / Port | Expected Result | Enforcement Layer |
| :--- | :--- | :--- | :--- | :--- |
| `redteam` | `blueteam` | ICMP Ping | **BLOCKED (100% packet loss)** | Docker Isolation Chain |
| `redteam` | `blueteam` | TCP 80/any | **BLOCKED (Connection refused/timeout)** | Bridge isolation |
| `redteam` | `client-llm` | TCP 11434 | **BLOCKED (Name resolution failed / drop)** | Embedded DNS + Network routing |
| `redteam` | `llm-gateway` | TCP 8000 | **ALLOWED (HTTP 200/403)** | Shared bridge (`redteam-net`) |
| `blueteam` | `redteam` | ICMP / TCP | **BLOCKED (100% packet loss)** | Docker Isolation Chain |
| `blueteam` | `client-llm` | TCP 11434 | **BLOCKED (Direct access prohibited)** | Embedded DNS + Network routing |
| `blueteam` | `llm-gateway` | TCP 8000 | **ALLOWED (HTTP 200/403)** | Shared bridge (`blueteam-net`) |

---

## 4. Container Hardening Specifications (Defense-in-Depth)

Beyond network-layer partitioning, all tenant workloads execute with:
1. **Non-Root User Execution**: `user: "10001:10001"` prevents root privilege escalation within the container filesystem.
2. **Dropped Capabilities**: `cap_drop: [ALL]` removes `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE`, blocking raw socket spoofing or ARP cache poisoning.
3. **Read-Only Root Filesystem**: `read_only: true` prevents file-based persistence or weaponized binaries from being staged in system paths.
4. **Seccomp Syscall Filtering**: Restricts kernel attack surface via `isolation/seccomp-redteam.json`.
5. **Cgroup Resource Caps**: Strict `cpus: '1.0'` and `memory: 512M` limits prevent noisy-neighbor DoS attacks against the gateway.
