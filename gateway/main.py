import os
import sys
import time
import threading
from typing import Optional
import requests
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

# Packaging-friendly audit import: works whether installed via pip, in PYTHONPATH, or local fallback
try:
    from audit.chain import log_entry
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from audit.chain import log_entry

app = FastAPI(
    title="Bayora Gateway",
    description="Isolated LLM Gateway and Tamper-Evident Security Intermediary"
)

# Auto-load .env for local development if present
env_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
if os.path.exists(env_file):
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except Exception:
        pass

# Configuration from environment
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://client-llm:11434/api/generate")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:3b")
ALLOWED_TENANTS = {t.strip().lower() for t in os.getenv("ALLOWED_TENANTS", "red-team,blue-team").split(",") if t.strip()}

# Tenant Authentication Secrets (Phase 5 Access Control)
TENANT_API_KEYS = {
    "red-team": os.getenv("REDTEAM_API_KEY", "bayora-redteam-live-secret-key-9f8a2"),
    "blue-team": os.getenv("BLUETEAM_API_KEY", "bayora-blueteam-live-secret-key-3c7d1")
}


class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Text prompt to dispatch to the model")
    model: Optional[str] = Field(default=None, description="Optional override for target model")


class PromptResponse(BaseModel):
    response: str
    model: str
    status: str
    latency: float


# Phase 7: Structured Metrics & Anomaly Tracking (No raw payload leakage)
metrics_lock = threading.Lock()
metrics_data = {
    "requests_total": {"red-team": {"ok": 0, "error": 0}, "blue-team": {"ok": 0, "error": 0}},
    "rejections_total": {},
    "latency_seconds_sum": {"red-team": 0.0, "blue-team": 0.0},
    "rejection_timestamps": []  # List of timestamps for sliding window anomaly detection
}


def record_metric_request(tenant: str, status: str, latency: float):
    with metrics_lock:
        if tenant not in metrics_data["requests_total"]:
            metrics_data["requests_total"][tenant] = {"ok": 0, "error": 0}
        key = "ok" if status == "ok" else "error"
        metrics_data["requests_total"][tenant][key] += 1
        if tenant not in metrics_data["latency_seconds_sum"]:
            metrics_data["latency_seconds_sum"][tenant] = 0.0
        metrics_data["latency_seconds_sum"][tenant] += latency


def record_metric_rejection(source: str, reason: str):
    now = time.time()
    with metrics_lock:
        rej_key = f"{source}:{reason}"
        metrics_data["rejections_total"][rej_key] = metrics_data["rejections_total"].get(rej_key, 0) + 1
        metrics_data["rejection_timestamps"].append(now)
        # Prune older than 60s
        metrics_data["rejection_timestamps"] = [
            t for t in metrics_data["rejection_timestamps"] if now - t <= 60
        ]


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model": MODEL_NAME,
        "ollama_url": OLLAMA_URL,
        "timestamp": time.time()
    }


@app.get("/metrics")
def get_metrics():
    """
    Exposes aggregated telemetry without cross-tenant payload or prompt leakage.
    Detects security anomalies when rejection rate spikes.
    """
    now = time.time()
    with metrics_lock:
        recent_rejections = len([t for t in metrics_data["rejection_timestamps"] if now - t <= 60])
        active_alert = recent_rejections >= 5

        summary = {
            "timestamp": now,
            "requests_total": metrics_data["requests_total"],
            "rejections_total": metrics_data["rejections_total"],
            "latency_seconds_sum": metrics_data["latency_seconds_sum"],
            "rejections_last_60s": recent_rejections,
            "security_anomaly_alert": active_alert,
            "alert_message": "CRITICAL: High burst of unauthorized cross-tenant attempts detected!" if active_alert else "Normal"
        }
    return summary


@app.post("/prompt", response_model=PromptResponse)
async def prompt(req: Request):
    # Support both structured JSON bodies and raw JSON
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "Invalid JSON body"})

    prompt_text = body.get("prompt")
    if not prompt_text:
        raise HTTPException(status_code=400, detail={"error": "Field 'prompt' is required"})

    # Phase 5: Authenticate tenant via API key or Bearer token
    auth_header = req.headers.get("Authorization", "").strip()
    bearer_token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
    tenant_key = req.headers.get("X-Tenant-Key", "").strip() or bearer_token
    declared_tenant = req.headers.get("X-Source-Tenant", "").strip().lower()

    # Determine tenant identity from presented cryptographic credential
    authenticated_tenant = None
    for t_name, t_secret in TENANT_API_KEYS.items():
        if t_secret and tenant_key == t_secret:
            authenticated_tenant = t_name
            break

    # Guard against cross-tenant header forgery (e.g. red-team key with X-Source-Tenant: blue-team)
    if declared_tenant and authenticated_tenant and declared_tenant != authenticated_tenant:
        record_metric_rejection(declared_tenant, "rejected_tenant_mismatch")
        log_entry({
            "source": declared_tenant,
            "authenticated_as": authenticated_tenant,
            "prompt": prompt_text,
            "status": "rejected_tenant_mismatch",
            "timestamp": time.time()
        })
        raise HTTPException(
            status_code=403,
            detail={"error": f"Credential belongs to '{authenticated_tenant}', but header claimed '{declared_tenant}'"}
        )

    # Resolve effective tenant
    effective_tenant = authenticated_tenant or declared_tenant

    # Enforce access control: reject missing, forged, or unapproved credentials
    if not effective_tenant or effective_tenant not in ALLOWED_TENANTS:
        record_metric_rejection(declared_tenant or "unauthenticated", "rejected_unknown_tenant")
        log_entry({
            "source": declared_tenant or "unauthenticated",
            "prompt": prompt_text,
            "status": "rejected_unknown_tenant",
            "timestamp": time.time()
        })
        raise HTTPException(
            status_code=403,
            detail={"error": f"Unauthorized tenant '{declared_tenant or 'unspecified'}'. Allowed: {list(ALLOWED_TENANTS)}"}
        )

    # If tenant has a registered key, verify that a valid key was provided
    expected_key = TENANT_API_KEYS.get(effective_tenant)
    if expected_key and tenant_key != expected_key:
        record_metric_rejection(effective_tenant, "rejected_invalid_key")
        log_entry({
            "source": effective_tenant,
            "prompt": prompt_text,
            "status": "rejected_invalid_key",
            "timestamp": time.time()
        })
        raise HTTPException(
            status_code=401 if not tenant_key else 403,
            detail={"error": f"Invalid or missing API key for tenant '{effective_tenant}'"}
        )

    source = effective_tenant

    target_model = body.get("model") or MODEL_NAME
    t0 = time.time()

    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": target_model,
                "prompt": prompt_text,
                "stream": False
            },
            timeout=60
        )
        r.raise_for_status()
        response_text = r.json().get("response", "")
        status_code = "ok"
    except requests.RequestException as e:
        response_text = "No response"
        status_code = f"upstream_error: {e}"

    latency = time.time() - t0
    record_metric_request(source, status_code, latency)

    # Tamper-evident audit log appended before returning response to client
    log_entry({
        "source": source,
        "model": target_model,
        "request": prompt_text,
        "response": response_text,
        "latency": latency,
        "status": status_code,
        "timestamp": time.time()
    })

    if status_code != "ok":
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream model error", "status": status_code}
        )

    return PromptResponse(
        response=response_text,
        model=target_model,
        status=status_code,
        latency=latency
    )