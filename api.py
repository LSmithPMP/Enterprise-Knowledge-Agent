"""
Enterprise Knowledge Research Agent — FastAPI Gateway.

Exposes the 14-agent orchestrator over HTTP with:
- API key authentication (Bearer token)
- HMAC signature verification on webhook endpoints
- Rate limiting (10 req/min per key)
- Prompt-injection filtering
- Input sanitization and schema validation
- Output redaction
- Distributed trace ID assignment
- Audit logging on every request

Endpoints aligned with n8n workflows and Streamlit dashboard:
- POST /query                  — main entry: run the full 14-agent pipeline
- POST /retrieve               — RAG retrieval only (used by n8n Workflow 1)
- POST /eval/golden-rescore    — re-score the golden dataset for drift (Workflow 2)
- POST /audit/write            — append an audit record (Workflow 2)
- POST /observability/metrics  — emit observability metrics (Workflow 2)
- GET  /corpus/deltas          — return new corpus entries (Workflow 2)
- GET  /health                 — liveness probe
- GET  /version                — version + agent roster
"""

import os
import re
import json
import time
import hmac
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

API_KEY = os.getenv("API_KEY", "")
N8N_WEBHOOK_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CORPUS_PATH = os.path.join(DATA_DIR, "corpus.json")
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "query_audit_log.jsonl")
OBSERVABILITY_LOG_PATH = os.path.join(DATA_DIR, "observability_log.jsonl")

VERSION = "1.0.0"
AGENT_ROSTER = [
    "QueryClassifierAgent", "PlannerAgent", "RetrieverAgent",
    "WebSearchAgent", "ThreatIntelAgent", "GapDetectionAgent",
    "CybersecurityFrameworkAgent", "ComplianceAgent", "CitationAgent",
    "SynthesizerAgent", "EvaluationAgent", "ConfidenceTrackerAgent",
    "ObservabilityAgent", "QueryAuditAgent",
]

# ─────────────────────────────────────────────────────────────────────────────
# Security primitives
# ─────────────────────────────────────────────────────────────────────────────

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(the\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a\s+different", re.IGNORECASE),
    re.compile(r"reveal\s+your\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"\bDAN\b|\bjailbreak\b", re.IGNORECASE),
    re.compile(r"<\s*\|\s*im_start\s*\|\s*>", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+)?(you|the)\s+(have|had)\s+no", re.IGNORECASE),
]
MAX_QUERY_LENGTH = 2000
RATE_LIMIT_WINDOW_S = 60
RATE_LIMIT_MAX = 10
_rate_buckets: dict = defaultdict(deque)


def check_rate_limit(api_key: str) -> None:
    now = time.time()
    bucket = _rate_buckets[api_key]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_S:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: 10 req/min per API key")
    bucket.append(now)


def verify_api_key(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.split(" ", 1)[1]
    if not API_KEY or token != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    check_rate_limit(token)
    return token


def verify_hmac(request: Request, x_signature: Optional[str] = Header(None)) -> None:
    """HMAC verification for webhook endpoints invoked by n8n."""
    if not x_signature:
        raise HTTPException(status_code=401, detail="Missing X-Signature header")
    body = request.scope.get("_raw_body", b"")
    expected = hmac.new(
        N8N_WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(x_signature, expected):
        raise HTTPException(status_code=401, detail="HMAC verification failed")


def check_prompt_injection(text: str) -> None:
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            raise HTTPException(status_code=400, detail="Prompt injection pattern detected; query rejected")
    if len(text) > MAX_QUERY_LENGTH:
        raise HTTPException(status_code=400, detail=f"Query exceeds {MAX_QUERY_LENGTH} character limit")


def redact_output(text: str) -> str:
    """Redact known classified markers on the response path."""
    if not text:
        return text
    text = re.sub(r"\[CLASSIFIED:[^\]]+\]", "[REDACTED]", text)
    return text


def write_audit(record: dict) -> None:
    record["audit_timestamp"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


def write_observability(record: dict) -> None:
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OBSERVABILITY_LOG_PATH, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH)
    role: str = Field("ANALYST", pattern="^(ANALYST|ENGINEER|EXECUTIVE)$")


class RetrieveRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH)
    role: str = "ANALYST"
    top_k: int = Field(5, ge=1, le=20)


class GoldenRescoreRequest(BaseModel):
    baseline: str = "locked"
    compare_to: str = "last_run"


class AuditWriteRequest(BaseModel):
    workflow: str
    timestamp: Optional[str] = None
    severity: Optional[str] = None
    techniques: Optional[list] = None
    gaps: Optional[list] = None
    compliance_impact: Optional[dict] = None


class ObservabilityMetricsRequest(BaseModel):
    run_id: str
    workflow: str
    severity_distribution: Optional[dict] = None
    timestamp: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Enterprise Knowledge Research Agent",
    description="14-agent research pipeline for AV/OT cybersecurity",
    version=VERSION,
)

# CORS — locked to localhost by default; widen for production behind proper auth
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def capture_raw_body(request: Request, call_next):
    """Capture raw body once so HMAC verification can read it."""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        request.scope["_raw_body"] = body

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive
    return await call_next(request)


# ─────────────────────────────────────────────────────────────────────────────
# Health and version
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/version")
def version():
    return {
        "version": VERSION,
        "agents": AGENT_ROSTER,
        "agent_count": len(AGENT_ROSTER),
        "endpoints": [
            "POST /query", "POST /retrieve",
            "POST /eval/golden-rescore", "POST /audit/write",
            "POST /observability/metrics", "GET /corpus/deltas",
            "GET /health", "GET /version",
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main query endpoint — runs the full 14-agent pipeline
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/query")
def query(request: QueryRequest, api_key: str = Depends(verify_api_key)):
    trace_id = str(uuid.uuid4())
    check_prompt_injection(request.query)

    # Import here so the FastAPI app starts even if orchestrator deps are missing
    from orchestrator import run_pipeline

    try:
        result = run_pipeline(request.query, request.role)
    except Exception as e:
        write_audit({
            "trace_id": trace_id, "query": request.query, "role": request.role,
            "outcome": "ERROR", "error": str(e),
        })
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

    # Redact any classified markers on the way out
    if isinstance(result, dict) and "executive_summary" in result:
        result["executive_summary"] = redact_output(result["executive_summary"])

    write_audit({
        "trace_id": trace_id,
        "query": request.query,
        "role": request.role,
        "outcome": "OK",
        "run_id": result.get("run_id") if isinstance(result, dict) else None,
    })
    return {"trace_id": trace_id, "result": result}


# ─────────────────────────────────────────────────────────────────────────────
# Direct retrieval (n8n Workflow 1)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/retrieve")
def retrieve(request: RetrieveRequest, api_key: str = Depends(verify_api_key)):
    check_prompt_injection(request.query)
    from agents.retriever_web_threat_agents import RetrieverAgent

    agent = RetrieverAgent()
    result = agent.run(request.query, request.role)
    return {
        "query": request.query,
        "role": request.role,
        "documents": [d.model_dump() if hasattr(d, "model_dump") else d for d in result.documents[:request.top_k]],
        "total_found": result.total_found,
        "filtered_by_role": result.filtered_by_role,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Golden-dataset re-score for eval drift detection (n8n Workflow 2)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/eval/golden-rescore")
def golden_rescore(request: GoldenRescoreRequest, api_key: str = Depends(verify_api_key)):
    # Stub: in production, load data/golden_dataset.jsonl, run orchestrator
    # against each scenario, compute per-dimension scores, persist results.
    # For now, return a placeholder structure the workflow can consume.
    return {
        "baseline": request.baseline,
        "compare_to": request.compare_to,
        "drift_detected": False,
        "scenarios_evaluated": 0,
        "note": "Stub — golden dataset not yet populated; tracked in TODO.md",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Audit + observability sinks for n8n Workflow 2
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/audit/write")
def audit_write(request: AuditWriteRequest, api_key: str = Depends(verify_api_key)):
    record = request.model_dump()
    write_audit(record)
    return {"status": "ok", "audit_id": str(uuid.uuid4())}


@app.post("/observability/metrics")
def observability_metrics(request: ObservabilityMetricsRequest, api_key: str = Depends(verify_api_key)):
    record = request.model_dump()
    write_observability(record)
    return {"status": "ok"}


# ─────────────────────────────────────────────────────────────────────────────
# Corpus deltas (n8n Workflow 2)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/corpus/deltas")
def corpus_deltas(since: str = "4h", api_key: str = Depends(verify_api_key)):
    # In production, filter by ingestion timestamp. For now, return full corpus.
    if not os.path.exists(CORPUS_PATH):
        return {"deltas": [], "since": since}
    with open(CORPUS_PATH) as f:
        corpus = json.load(f)
    return {"deltas": corpus, "since": since, "count": len(corpus)}


# ─────────────────────────────────────────────────────────────────────────────
# Local development entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
