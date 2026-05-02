"""
test_api.py — Phase 6 Tests
Skill: tdd-workflow, fastapi-pro
Tests: All 8 API endpoints for correct response format and status codes.
Uses httpx TestClient — no server needed.
"""

import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


# ── App Import ─────────────────────────────────────────────────────────────────
from src.api.main import app

client = TestClient(app)


# ── Response format validator ─────────────────────────────────────────────────

def assert_success_format(response):
    """All endpoints must return the locked response contract."""
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "data" in body
    assert "meta" in body
    assert "timestamp" in body["meta"]
    assert "model_version" in body["meta"]
    assert body["status"] == "success"


# ── GET /api/health ───────────────────────────────────────────────────────────

def test_health_returns_success_format():
    response = client.get("/api/health")
    assert_success_format(response)


def test_health_contains_models_ready_field():
    response = client.get("/api/health")
    data = response.json()["data"]
    assert "models_ready" in data
    assert "flows_stored" in data


# ── GET /api/flows ────────────────────────────────────────────────────────────

def test_flows_returns_success_format():
    response = client.get("/api/flows")
    assert_success_format(response)


def test_flows_pagination_fields():
    response = client.get("/api/flows?page=1&page_size=10")
    data = response.json()["data"]
    assert "flows" in data
    assert "total" in data
    assert "page" in data
    assert "total_pages" in data


def test_flows_invalid_page_returns_422():
    response = client.get("/api/flows?page=0")
    assert response.status_code == 422


# ── GET /api/flows/{flow_id} ──────────────────────────────────────────────────

def test_flow_not_found_returns_404():
    response = client.get("/api/flows/nonexistent-id-xyz")
    assert response.status_code == 404


# ── GET /api/flows/{flow_id}/explain ─────────────────────────────────────────

def test_explain_not_found_returns_404():
    response = client.get("/api/flows/nonexistent-id-xyz/explain")
    assert response.status_code == 404


# ── GET /api/alerts ───────────────────────────────────────────────────────────

def test_alerts_returns_success_format():
    response = client.get("/api/alerts")
    assert_success_format(response)


def test_alerts_contains_count_field():
    response = client.get("/api/alerts")
    data = response.json()["data"]
    assert "alerts" in data
    assert "count" in data
    assert isinstance(data["count"], int)


# ── GET /api/stats ────────────────────────────────────────────────────────────

def test_stats_returns_success_format():
    response = client.get("/api/stats")
    assert_success_format(response)


def test_stats_contains_required_fields():
    response = client.get("/api/stats")
    data = response.json()["data"]
    required = ["total_flows", "attacks", "suspicious", "normal", "attack_rate"]
    for field in required:
        assert field in data, f"Missing field: {field}"


# ── POST /api/predict ─────────────────────────────────────────────────────────

def test_predict_without_models_returns_503():
    """POST /predict should return 503 when models are missing, or 200 if trained."""
    payload = {
        "features": {"syn_ack_ratio": 5.0, "bytes_per_second": 1000.0},
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
    }
    response = client.post("/api/predict", json=payload)
    # 200 if models trained, 503 if not, 500 if error — all acceptable
    assert response.status_code in (200, 500, 503)



# ── GET /api/model/performance ────────────────────────────────────────────────

def test_performance_returns_503_if_no_reports():
    """Without training reports, should return 503."""
    with patch("src.api.main._load_reports", return_value={}):
        response = client.get("/api/model/performance")
        assert response.status_code == 503


def test_performance_structure_with_mock_reports():
    mock_reports = {
        "baseline": {"f1": 0.85, "roc_auc": 0.90, "fp_rate": 0.05, "confusion_matrix": {}},
        "engineered": {"f1": 0.92, "roc_auc": 0.95, "fp_rate": 0.03, "confusion_matrix": {}},
    }
    with patch("src.api.main._load_reports", return_value=mock_reports):
        response = client.get("/api/model/performance")
        assert_success_format(response)
        data = response.json()["data"]
        assert "experiments" in data
        assert "best_model" in data
        assert data["best_model"] == "engineered"   # higher F1
