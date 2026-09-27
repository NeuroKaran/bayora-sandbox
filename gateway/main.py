import os
import sys
import time
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
ALLOWED_TENANTS = set(os.getenv("ALLOWED_TENANTS", "red-team,blue-team").split(","))


class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Text prompt to dispatch to the model")
    model: Optional[str] = Field(default=None, description="Optional override for target model")


class PromptResponse(BaseModel):
    response: str
    model: str
    status: str
    latency: float


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model": MODEL_NAME,
        "ollama_url": OLLAMA_URL,
        "timestamp": time.time()
    }


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

    source = req.headers.get("X-Source-Tenant", "unknown").strip().lower()
    if source not in ALLOWED_TENANTS:
        log_entry({
            "source": source,
            "prompt": prompt_text,
            "status": "rejected_unknown_tenant",
            "timestamp": time.time()
        })
        raise HTTPException(
            status_code=403,
            detail={"error": f"Unauthorized tenant '{source}'. Allowed tenants: {list(ALLOWED_TENANTS)}"}
        )

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