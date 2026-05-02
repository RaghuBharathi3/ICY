"""
train_if.py
────────────────────────────────────────────────────────────────────────────────
Phase 3 — Isolation Forest Training
Skill references: scikit-learn, ml-pipeline-workflow

Role: Secondary anomaly detection layer.
Detects behavioral anomalies that the supervised RF might miss.
contamination=0.1 → ~10% of flows expected to be anomalous.
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

MODELS_DIR = Path("artifacts/models")


def train_isolation_forest(
    X_train: np.ndarray,
    contamination: float = 0.1,
    n_estimators: int = 100,
    random_state: int = 42,
) -> IsolationForest:
    """
    Train Isolation Forest on training features.
    IF is unsupervised — does NOT use labels.
    contamination: expected proportion of anomalies in the dataset.
    """
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    logger.info(f"Training Isolation Forest on {X_train.shape[0]} samples (contamination={contamination})...")
    model.fit(X_train)
    logger.info("Isolation Forest training complete.")
    return model


def get_anomaly_scores(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """
    Return raw anomaly scores (decision_function).
    Lower score = more anomalous.
    score < 0 → anomaly, score > 0 → normal
    """
    return model.decision_function(X)


def save_if_model(model: IsolationForest) -> Path:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / "if_model.pkl"
    joblib.dump(model, path)
    logger.info(f"Isolation Forest saved → {path}")
    return path


def run_isolation_forest_training(data_dir: str | Path = "data/raw") -> IsolationForest:
    """Train IF on engineered features and save artifact."""
    from src.pipeline.preprocessor import full_pipeline
    data = full_pipeline(data_dir, apply_engineering=True, use_smote=False)
    model = train_isolation_forest(data["X_train"])
    save_if_model(model)
    return model
