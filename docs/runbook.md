# Bayora Sandbox: Cloud VM Deployment & Operations Runbook 🚀

**Applicability:** Production Deployment & Security Operations (Phase 9)  

---

## 1. Cloud VM Prerequisites

### Recommended Instance Sizing
- **Cloud Provider:** AWS (e.g. `t3.xlarge` / `g4dn.xlarge`), GCP (`e2-standard-4`), or Azure (`Standard_D4s_v5`).
- **CPU:** 4 vCPUs minimum.
- **RAM:** 16 GB minimum.
- **Disk:** 50 GB NVMe / SSD.
- **OS:** Ubuntu 22.04 LTS or Ubuntu 24.04 LTS.

### Host Package Setup
```bash
# Update OS packages
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker Engine & Compose plugin
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Grant current user docker access
sudo usermod -aG docker $USER
newgrp docker
```

---

## 2. Standing Up Bayora Sandbox

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bayora-ai/bayora-sandbox.git
   cd bayora-sandbox
   ```

2. **Configure production environment:**
   ```bash
   cp .env.example .env
   # Edit .env with secure production keys
   nano .env
   ```

3. **Start the complete multi-tenant stack:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify container health:**
   ```bash
   docker compose ps
   curl -s http://localhost:8000/health | jq .
   ```

---

## 3. Running Adversarial Evaluations & Verifications

1. **Execute the attack runner from inside the Red-Team container:**
   ```bash
   docker exec -it bayora-redteam python3 /home/sandboxuser/workspace/attacks/run-attack.py --gateway http://llm-gateway:8000
   ```

2. **Inspect and verify cryptographic audit log on the host:**
   ```bash
   python3 audit/verify.py
   ```

3. **Monitor telemetry & active anomaly alerts:**
   ```bash
   curl -s http://localhost:8000/metrics | jq .
   ```

---

## 4. Operational Procedures & Runbooks

### Procedure A: Tenant Credential Rotation
If a tenant key is exposed or rotated periodically:
1. Generate new 32-byte cryptographically secure random token:
   ```bash
   openssl rand -hex 24
   ```
2. Update `.env` with new keys (`REDTEAM_API_KEY` / `BLUETEAM_API_KEY`).
3. Reload gateway and tenant containers with zero downtime:
   ```bash
   docker compose up -d --no-deps llm-gateway redteam blueteam
   ```

### Procedure B: Responding to Broken Audit Chains
If `python3 audit/verify.py` flags an integrity mismatch:
1. **Isolate:** Stop the gateway immediately to halt further appends:
   ```bash
   docker compose stop llm-gateway
   ```
2. **Diagnose:** Note the broken block index reported by the verifier:
   ```bash
   python3 audit/verify.py --log audit/log.jsonl
   ```
3. **Forensics:** Diff the corrupted block with offline backups or filesystem journal logs.
4. **Archive & Reset:** Quarantine corrupted log:
   ```bash
   mv audit/log.jsonl audit/log-compromised-$(date +%s).jsonl
   ```
5. **Restart:** Restart the stack; `llm-gateway` will re-initialize a new genesis block.
