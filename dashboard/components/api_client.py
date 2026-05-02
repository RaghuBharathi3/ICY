"""
dashboard/components/api_client.py
────────────────────────────────────────────────────────────────────────────────
HTTP client wrapping all 8 FastAPI endpoints.
Falls back to demo data when API is offline (for development/presentation).
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger(__name__)

API_BASE = "http://localhost:8000"


class APIClient:
    """Thin wrapper around the IDS REST API with graceful fallback to demo data."""

    def __init__(self, base_url: str = API_BASE, timeout: int = 5):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self._demo_flows = self._generate_demo_flows(80)  # cached demo data

    # ── Core GET ──────────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict | None = None) -> dict:
        try:
            import requests
            r = requests.get(f"{self.base}{path}", params=params, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"API unreachable ({path}): {e}")
            return {}

    def _post(self, path: str, payload: dict) -> dict:
        try:
            import requests
            r = requests.post(f"{self.base}{path}", json=payload, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"API POST unreachable ({path}): {e}")
            return {}

    # ── Endpoints ─────────────────────────────────────────────────────────────
    def get_health(self) -> dict:
        result = self._get("/api/health")
        if not result:
            return {"data": {"status": "offline", "models_ready": False, "flows_stored": 0}}
        return result

    def get_flows(self, page: int = 1, page_size: int = 200) -> list[dict]:
        result = self._get("/api/flows", params={"page": page, "page_size": page_size})
        if not result:
            return self._demo_flows
        return result.get("data", {}).get("flows", self._demo_flows)

    def get_flow(self, flow_id: str) -> dict | None:
        result = self._get(f"/api/flows/{flow_id}")
        if not result:
            return next((f for f in self._demo_flows if f["flow_id"] == flow_id), None)
        return result.get("data")

    def explain_flow(self, flow_id: str) -> dict:
        result = self._get(f"/api/flows/{flow_id}/explain")
        if not result:
            return self._demo_explanation(flow_id)
        return result.get("data", {})

    def get_alerts(self, decision: str | None = None) -> list[dict]:
        params = {}
        if decision:
            params["decision"] = decision
        result = self._get("/api/alerts", params=params)
        if not result:
            alerts = [f for f in self._demo_flows if f["decision"] in ("ATTACK", "SUSPICIOUS")]
            if decision:
                alerts = [f for f in alerts if f["decision"] == decision.upper()]
            return alerts
        return result.get("data", {}).get("alerts", [])

    def get_stats(self) -> dict:
        result = self._get("/api/stats")
        if not result:
            return self._demo_stats()
        return result.get("data", {})

    def get_performance(self) -> dict:
        result = self._get("/api/model/performance")
        if not result:
            return self._demo_performance()
        return result.get("data", {})

    def predict(self, features: dict, src_ip: str = "unknown", dst_ip: str = "unknown") -> dict:
        result = self._post("/api/predict", {
            "features": features,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        })
        if not result:
            return {}
        return result.get("data", {})

    # ── Demo data generators ───────────────────────────────────────────────────
    def _generate_demo_flows(self, n: int = 80) -> list[dict]:
        random.seed(42)
        decisions = ["ATTACK"] * 28 + ["SUSPICIOUS"] * 14 + ["NORMAL"] * 38
        random.shuffle(decisions)
        ips = [f"192.168.{random.randint(1,5)}.{random.randint(10,250)}" for _ in range(20)]
        features = [
            "syn_ack_ratio", "bytes_per_second", "packets_per_second",
            "fwd_bwd_ratio", "avg_packet_size", "iat_mean", "flow_duration_var",
        ]
        flows = []
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        for i in range(n):
            d = decisions[i % len(decisions)]
            conf = round(random.uniform(0.7, 0.99) if d == "ATTACK" else random.uniform(0.3, 0.65), 4)
            top_feats = random.sample(features, 3)
            ts = (base_time + timedelta(seconds=i * 90)).isoformat()
            flows.append({
                "flow_id": f"demo-{i:04d}",
                "src_ip": random.choice(ips),
                "dst_ip": f"10.0.0.{random.randint(1, 50)}",
                "decision": d,
                "rf_confidence": conf,
                "if_anomaly": d != "NORMAL",
                "timestamp": ts,
                "top_features": [
                    {"feature": f, "shap_value": round(random.uniform(0.02, 0.45), 4)}
                    for f in top_feats
                ],
            })
        return flows

    def _demo_stats(self) -> dict:
        flows = self._demo_flows
        total = len(flows)
        attacks = sum(1 for f in flows if f["decision"] == "ATTACK")
        suspicious = sum(1 for f in flows if f["decision"] == "SUSPICIOUS")
        normal = sum(1 for f in flows if f["decision"] == "NORMAL")
        return {
            "total_flows": total,
            "attacks": attacks,
            "suspicious": suspicious,
            "normal": normal,
            "attack_rate": round(attacks / total, 4),
            "avg_rf_confidence": 0.7821,
        }

    def _demo_performance(self) -> dict:
        return {
            "experiments": {
                "baseline": {
                    "f1": 0.8812,
                    "roc_auc": 0.9145,
                    "fp_rate": 0.0431,
                    "confusion_matrix": {"tn": 18540, "fp": 834, "fn": 712, "tp": 9214},
                },
                "engineered": {
                    "f1": 0.9387,
                    "roc_auc": 0.9671,
                    "fp_rate": 0.0198,
                    "confusion_matrix": {"tn": 19158, "fp": 216, "fn": 421, "tp": 9505},
                },
                "ensemble": {
                    "f1": 0.9512,
                    "roc_auc": 0.9784,
                    "fp_rate": 0.0163,
                    "confusion_matrix": {"tn": 19192, "fp": 182, "fn": 372, "tp": 9554},
                },
            },
            "best_model": "ensemble",
        }

    def _demo_explanation(self, flow_id: str) -> dict:
        return {
            "flow_id": flow_id,
            "decision": "ATTACK",
            "top_features": [
                {"feature": "syn_ack_ratio",   "shap_value": 0.3814},
                {"feature": "bytes_per_second", "shap_value": 0.2201},
                {"feature": "packets_per_second","shap_value": 0.1753},
            ],
            "plain_english": (
                "High SYN/ACK imbalance strongly suggests a SYN flood (DDoS). "
                "Abnormal bytes-per-second indicates burst traffic. "
                "Elevated packet rate is consistent with automated attack tools."
            ),
        }
