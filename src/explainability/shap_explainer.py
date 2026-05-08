"""
shap_explainer.py
────────────────────────────────────────────────────────────────────────────────
Phase 4 — SHAP Explainability
Skill references: scikit-learn (shap), matplotlib

Provides:
  - Summary plot (global feature importance)
  - Per-prediction top-5 features (used by API /explain endpoint)
  - Feature importance bar chart (RF native)

Every prediction served by the API includes SHAP explanation.
This is MANDATORY per master prompt — not optional.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import matplotlib
matplotlib.use("Agg")   # non-interactive backend for server use
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)

PLOTS_DIR = Path("artifacts/plots")
MODELS_DIR = Path("artifacts/models")


class SHAPExplainer:
    """Wraps SHAP TreeExplainer for the Random Forest model."""

    def __init__(self, model_path: str | Path, feature_cols: list[str]):
        import shap
        model = joblib.load(model_path)
        self.model = model
        self.feature_cols = feature_cols
        self.explainer = shap.TreeExplainer(model)
        logger.info(f"SHAPExplainer initialized with {len(feature_cols)} features")

    def get_shap_values(self, X: np.ndarray) -> np.ndarray:
        """Compute SHAP values for X. Returns array of shape (n_samples, n_features)."""
        import shap
        shap_vals = self.explainer.shap_values(X)
        # TreeExplainer returns list [class0_vals, class1_vals] or 3D array for binary classification
        if isinstance(shap_vals, list):
            return shap_vals[1]  # values for class=1 (Attack)
        if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
            return shap_vals[:, :, 1]
        return shap_vals

    def explain_single(self, x: np.ndarray) -> list[dict]:
        """
        Explain a single prediction. Returns top-5 features by SHAP contribution.
        Format: [{"feature": "syn_ack_ratio", "value": 2.4, "shap_value": 0.43}, ...]
        """
        if x.ndim == 1:
            x = x.reshape(1, -1)
        shap_vals = self.get_shap_values(x)[0]  # shape: (n_features,)

        # Sort by absolute contribution, take top 5
        indices = np.argsort(np.abs(shap_vals))[::-1][:5]
        top_features = []
        for idx in indices:
            top_features.append({
                "feature": self.feature_cols[idx],
                "value": round(float(x[0, idx]), 4),
                "shap_value": round(float(shap_vals[idx]), 4),
            })
        return top_features

    def generate_summary_plot(self, X_sample: np.ndarray, max_display: int = 15) -> Path:
        """Generate SHAP summary plot and save to artifacts/plots/shap_summary.png."""
        import shap
        PLOTS_DIR.mkdir(parents=True, exist_ok=True)
        shap_vals = self.get_shap_values(X_sample)

        fig, ax = plt.subplots(figsize=(10, 8))
        shap.summary_plot(
            shap_vals,
            X_sample,
            feature_names=self.feature_cols,
            max_display=max_display,
            show=False,
        )
        path = PLOTS_DIR / "shap_summary.png"
        plt.savefig(path, bbox_inches="tight", dpi=150)
        plt.close()
        logger.info(f"SHAP summary plot saved → {path}")
        return path

    def generate_feature_importance_plot(self) -> Path:
        """Generate RF native feature importance bar chart."""
        PLOTS_DIR.mkdir(parents=True, exist_ok=True)
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:20]   # top 20

        fig, ax = plt.subplots(figsize=(12, 7))
        ax.barh(
            [self.feature_cols[i] for i in reversed(indices)],
            importances[list(reversed(indices))],
            color="#4f8ef7",
        )
        ax.set_xlabel("Feature Importance (Gini)", fontsize=12)
        ax.set_title("Random Forest — Feature Importance", fontsize=14, fontweight="bold")
        ax.invert_yaxis()
        plt.tight_layout()

        path = PLOTS_DIR / "feature_importance.png"
        plt.savefig(path, dpi=150)
        plt.close()
        logger.info(f"Feature importance plot saved → {path}")
        return path


def plain_english_explanation(top_features: list[dict], threshold_map: Optional[dict] = None) -> str:
    """
    Generate a plain English sentence explaining why a flow was flagged.
    Used in Panel 3 of the dashboard.
    Example: "This flow was flagged because syn_ack_ratio (2.4) is abnormally high."
    """
    if not top_features:
        return "No explanation available."
    top = top_features[0]
    direction = "high" if top["shap_value"] > 0 else "low"
    return (
        f"This flow was flagged primarily because '{top['feature']}' "
        f"({top['value']:.2f}) is abnormally {direction}, "
        f"contributing {abs(top['shap_value']):.2f} to the attack score."
    )
