"""
main.py — FastAPI Backend
────────────────────────────────────────────────────────────────────────────────
Phase 6 — REST API
Skill references: fastapi-pro, api-patterns, pydantic-models-py

8 endpoints (from master prompt — do NOT add/remove):
  GET  /api/health
  GET  /api/flows
  GET  /api/flows/{flow_id}
  GET  /api/flows/{flow_id}/explain
  GET  /api/alerts
  GET  /api/stats
  POST /api/predict
  GET  /api/model/performance

All responses follow the locked contract:
  { "status": "success", "data": {}, "meta": { "timestamp": "ISO8601", "model_version": "1.0" } }

Run:  uvicorn src.api.main:app --reload --port 8000
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
REPORTS_DIR = Path("artifacts/reports")
MODELS_DIR = Path("artifacts/models")
RESULTS_FILE = REPORTS_DIR / "live_results.json"
FEATURE_COLS_PATH = MODELS_DIR / "feature_cols.json"

# ── App Setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IDS — Intrusion Detection System API",
    description="ML-based IDS with RF + IF ensemble. Research prototype.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # development only — not for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy-loaded predictor ─────────────────────────────────────────────────────
_predictor = None

def get_predictor():
    global _predictor
    if _predictor is None:
        try:
            from src.pipeline.predictor import Predictor
            feature_cols = _load_feature_cols()
            _predictor = Predictor(feature_cols=feature_cols)
        except FileNotFoundError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Models not trained yet. Run training first. ({e})",
            )
    return _predictor

def _load_feature_cols() -> list[str]:
    if FEATURE_COLS_PATH.exists():
        with open(FEATURE_COLS_PATH) as f:
            return json.load(f)
    return []

def _load_flows() -> list[dict]:
    if not RESULTS_FILE.exists():
        return []
    with open(RESULTS_FILE) as f:
        return json.load(f)

def _load_reports() -> dict:
    reports = {}
    for name in ("baseline", "engineered", "ensemble"):
        path = REPORTS_DIR / f"{name}.json"
        if path.exists():
            with open(path) as f:
                reports[name] = json.load(f)
    return reports


# ── Response Helpers ──────────────────────────────────────────────────────────
def success_response(data: Any) -> dict:
    return {
        "status": "success",
        "data": data,
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_version": "1.0",
        },
    }


# ── Pydantic Models ───────────────────────────────────────────────────────────
class PredictRequest(BaseModel):
    """Manual prediction from raw feature dict. Used for testing."""
    features: dict[str, float] = Field(..., description="Feature name → value map")
    src_ip: str = Field(default="unknown")
    dst_ip: str = Field(default="unknown")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    """System status — check if models are loaded."""
    models_ready = (MODELS_DIR / "rf_model.pkl").exists() and (MODELS_DIR / "if_model.pkl").exists()
    return success_response({
        "status": "healthy" if models_ready else "models_not_trained",
        "models_ready": models_ready,
        "flows_stored": len(_load_flows()),
    })


@app.get("/api/flows")
def get_flows(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
):
    """Paginated list of all analyzed flows."""
    flows = _load_flows()
    total = len(flows)
    start = (page - 1) * page_size
    end = start + page_size
    return success_response({
        "flows": flows[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    })


@app.get("/api/flows/{flow_id}")
def get_flow(flow_id: str):
    """Single flow details + all features."""
    flows = _load_flows()
    for flow in flows:
        if flow.get("flow_id") == flow_id:
            return success_response(flow)
    raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")


@app.get("/api/flows/{flow_id}/explain")
def explain_flow(flow_id: str):
    """SHAP top-5 features for a specific flow + plain English summary."""
    flows = _load_flows()
    for flow in flows:
        if flow.get("flow_id") == flow_id:
            top_features = flow.get("top_features", [])
            from src.explainability.shap_explainer import plain_english_explanation
            return success_response({
                "flow_id": flow_id,
                "decision": flow.get("decision"),
                "top_features": top_features,
                "plain_english": plain_english_explanation(top_features),
            })
    raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")


@app.get("/api/alerts")
def get_alerts(decision: Optional[str] = Query(default=None)):
    """Only flagged flows (ATTACK or SUSPICIOUS). Optionally filter by decision."""
    flows = _load_flows()
    alerts = [f for f in flows if f.get("decision") in ("ATTACK", "SUSPICIOUS")]
    if decision:
        alerts = [f for f in alerts if f.get("decision") == decision.upper()]
    return success_response({
        "alerts": alerts,
        "count": len(alerts),
    })


@app.get("/api/stats")
def get_stats():
    """Summary counts — total, attacks, suspicious, normal, FP rate estimate."""
    flows = _load_flows()
    total = len(flows)
    attacks = sum(1 for f in flows if f.get("decision") == "ATTACK")
    suspicious = sum(1 for f in flows if f.get("decision") == "SUSPICIOUS")
    normal = sum(1 for f in flows if f.get("decision") == "NORMAL")
    avg_confidence = (
        round(sum(f.get("rf_confidence", 0) for f in flows) / total, 4)
        if total > 0 else 0.0
    )
    return success_response({
        "total_flows": total,
        "attacks": attacks,
        "suspicious": suspicious,
        "normal": normal,
        "attack_rate": round(attacks / total, 4) if total > 0 else 0,
        "avg_rf_confidence": avg_confidence,
    })


@app.post("/api/predict")
def predict(request: PredictRequest):
    """Manual prediction from a feature dict (for testing/demo)."""
    predictor = get_predictor()
    feature_cols = _load_feature_cols()

    if not feature_cols:
        raise HTTPException(
            status_code=503,
            detail="Feature columns not found. Train models first.",
        )

    # Build feature vector in correct column order
    x = np.array([request.features.get(col, 0.0) for col in feature_cols], dtype=float)

    record = predictor.predict_single(
        x,
        src_ip=request.src_ip,
        dst_ip=request.dst_ip,
        raw_features=request.features,
    )

    from dataclasses import asdict
    return success_response(asdict(record))


@app.get("/api/model/performance")
def model_performance():
    """Experiment comparison table — baseline vs engineered vs ensemble."""
    reports = _load_reports()
    if not reports:
        raise HTTPException(
            status_code=503,
            detail="No experiment reports found. Run training first.",
        )

    comparison = {}
    for name, report in reports.items():
        comparison[name] = {
            "f1": report.get("f1"),
            "roc_auc": report.get("roc_auc"),
            "fp_rate": report.get("fp_rate"),
            "confusion_matrix": report.get("confusion_matrix"),
        }

    return success_response({
        "experiments": comparison,
        "best_model": max(comparison, key=lambda k: comparison[k].get("f1") or 0),
    })
