"""
config.py
────────────────────────────────────────────────────────────────────────────────
Central configuration — single source of truth for ALL data paths,
training hyperparameters, and output directories.

Usage:
    from config import CFG
    data_dir = CFG.DATA_RAW

This module is intentionally import-safe (no heavy dependencies).
"""

from __future__ import annotations

from pathlib import Path


class CFG:
    # ── Root ─────────────────────────────────────────────────────────────────
    PROJECT_ROOT: Path = Path(__file__).parent.resolve()

    # ── Data paths ───────────────────────────────────────────────────────────
    # Canonical ML-ready CSVs (used by all training experiments)
    DATA_RAW: Path = PROJECT_ROOT / "data" / "raw"

    # Raw per-flow CSVs (GeneratedLabelledFlows — optional, adds ~2x data)
    # Set to None to disable merging. The pipeline skips this if empty.
    DATA_RAW_FLOWS = None

    # Processed / watch-folder inference
    DATA_PROCESSED: Path = PROJECT_ROOT / "data" / "processed"
    DATA_WATCH: Path = PROJECT_ROOT / "data" / "watch"

    # ── Artifact paths ───────────────────────────────────────────────────────
    ARTIFACTS_DIR: Path = PROJECT_ROOT / "artifacts"
    MODELS_DIR: Path = ARTIFACTS_DIR / "models"
    REPORTS_DIR: Path = ARTIFACTS_DIR / "reports"
    PLOTS_DIR: Path = ARTIFACTS_DIR / "plots"
    EDA_DIR: Path = ARTIFACTS_DIR / "eda"

    # Model file names
    MODEL_BASELINE: Path = MODELS_DIR / "rf_baseline.pkl"
    MODEL_RF: Path = MODELS_DIR / "rf_model.pkl"
    MODEL_IF: Path = MODELS_DIR / "if_model.pkl"
    FEATURE_COLS: Path = MODELS_DIR / "feature_cols.json"

    # ── Training hyperparameters ─────────────────────────────────────────────
    # Random Forest
    RF_N_ESTIMATORS: int = 100
    RF_RANDOM_STATE: int = 42
    RF_CLASS_WEIGHT: str = "balanced"

    # Isolation Forest — contamination controls the FP/FN trade-off
    # Lower → fewer anomalies flagged → lower FP rate for ensemble
    # 0.05 = expect ~5% of traffic to be anomalous (conservative, real-world-ish)
    IF_CONTAMINATION: float = 0.05
    IF_N_ESTIMATORS: int = 100
    IF_RANDOM_STATE: int = 42

    # Data split
    TEST_SIZE: float = 0.20
    SPLIT_RANDOM_STATE: int = 42

    # SMOTE
    SMOTE_RANDOM_STATE: int = 42

    # ── EDA ──────────────────────────────────────────────────────────────────
    EDA_TOP_FEATURES: int = 40    # features shown in correlation heatmap
    EDA_VARIANCE_TOP_N: int = 30  # features in variance chart

    # ── API ──────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # ── Dashboard ────────────────────────────────────────────────────────────
    DASHBOARD_PORT: int = 8501

    # ── Labels ───────────────────────────────────────────────────────────────
    BENIGN_LABEL: str = "BENIGN"
    BINARY_MAP: dict = {"BENIGN": 0}   # everything else → 1 (Attack)

    @classmethod
    def ensure_dirs(cls):
        """Create all output directories if they don't exist."""
        for d in [
            cls.MODELS_DIR, cls.REPORTS_DIR, cls.PLOTS_DIR,
            cls.EDA_DIR, cls.DATA_PROCESSED, cls.DATA_WATCH,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def summary(cls) -> str:
        """Human-readable config summary."""
        lines = [
            "IDS Pipeline Configuration",
            "=" * 50,
            f"  Data (raw)       : {cls.DATA_RAW}",
            f"  Data (raw_flows) : {cls.DATA_RAW_FLOWS}",
            f"  Models dir       : {cls.MODELS_DIR}",
            f"  Reports dir      : {cls.REPORTS_DIR}",
            f"  RF estimators    : {cls.RF_N_ESTIMATORS}",
            f"  IF contamination : {cls.IF_CONTAMINATION}",
            f"  Test split       : {cls.TEST_SIZE}",
            f"  API port         : {cls.API_PORT}",
            "=" * 50,
        ]
        return "\n".join(lines)


if __name__ == "__main__":
    print(CFG.summary())
