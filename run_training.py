"""
run_training.py
────────────────────────────────────────────────────────────────────────────────
Master training orchestrator — runs all 3 experiments in order.
Skill references: ml-pipeline-workflow, mlops-engineer, concise-planning

Usage:
  python run_training.py                       # all 3 experiments
  python run_training.py --exp baseline        # just baseline
  python run_training.py --exp engineered      # just experiment 2
  python run_training.py --exp ensemble        # just experiment 3
  python run_training.py --data data/raw       # custom data path

Order (from master prompt):
  Exp 1: Baseline   → raw features, no SMOTE → saves baseline.json + rf_baseline.pkl
  Exp 2: Engineered → 7 custom features + SMOTE → saves engineered.json + rf_model.pkl
  Exp 3: Ensemble   → Exp 2 RF + Isolation Forest → saves ensemble.json + if_model.pkl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("artifacts/training.log", mode="a", encoding="utf-8"),
    ],
)
# Force stdout to UTF-8 on Windows to avoid CP1252 errors
import io
if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
logger = logging.getLogger(__name__)


def ensure_dirs():
    for d in ["artifacts/models", "artifacts/reports", "artifacts/plots"]:
        Path(d).mkdir(parents=True, exist_ok=True)


def run_baseline(data_dir: str, extra_dirs: list | None = None) -> dict:
    logger.info("=" * 60)
    logger.info("EXPERIMENT 1 -- BASELINE")
    logger.info("  Raw CICIDS2017 features, no engineering, no SMOTE")
    logger.info("=" * 60)
    from src.models.train_rf import run_experiment_1_baseline
    metrics = run_experiment_1_baseline(data_dir, extra_dirs=extra_dirs)
    logger.info(f"[DONE] Baseline    F1={metrics['f1']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}")
    return metrics


def run_engineered(data_dir: str, extra_dirs: list | None = None):
    logger.info("=" * 60)
    logger.info("EXPERIMENT 2 -- ENGINEERED + SMOTE")
    logger.info("  7 custom features + SMOTE class balancing")
    logger.info("=" * 60)
    from src.models.train_rf import run_experiment_2_engineered
    rf_model, metrics = run_experiment_2_engineered(data_dir, extra_dirs=extra_dirs)
    logger.info(f"[DONE] Engineered  F1={metrics['f1']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}")
    return rf_model, metrics


def run_ensemble(data_dir: str, rf_model, extra_dirs: list | None = None) -> dict:
    logger.info("=" * 60)
    logger.info("EXPERIMENT 3 -- ENSEMBLE (RF + Isolation Forest)")
    logger.info("  Combines supervised RF + unsupervised anomaly layer")
    logger.info("=" * 60)
    from src.models.ensemble import run_experiment_3_ensemble
    metrics = run_experiment_3_ensemble(data_dir, rf_model, extra_dirs=extra_dirs)
    logger.info(f"[DONE] Ensemble    F1={metrics['f1']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}")
    return metrics


def save_feature_cols(data_dir: str, extra_dirs: list | None = None):
    """Save feature column names for the API to load at inference time."""
    from src.pipeline.preprocessor import full_pipeline
    logger.info("Saving feature column list...")
    data = full_pipeline(data_dir, apply_engineering=True, use_smote=False, extra_dirs=extra_dirs)
    cols_path = Path("artifacts/models/feature_cols.json")
    with open(cols_path, "w") as f:
        json.dump(data["feature_cols"], f)
    logger.info(f"Feature cols saved → {cols_path} ({len(data['feature_cols'])} features)")


def print_summary(results: dict):
    logger.info("")
    logger.info("+" + "=" * 58 + "+")
    logger.info("|" + "   TRAINING COMPLETE -- SUMMARY".center(58) + "|")
    logger.info("+" + "=" * 58 + "+")
    for name, m in results.items():
        if m:
            logger.info(
                f"|  {name:<12}  F1={m['f1']:.4f}  ROC={m['roc_auc']:.4f}  FP={m['fp_rate']:.4f}  |"
            )
    logger.info("+" + "=" * 58 + "+")

    if results:
        best = max(results.items(), key=lambda x: x[1].get("f1", 0) if x[1] else 0)
        logger.info(f"\nBest model: {best[0].upper()} (F1={best[1]['f1']:.4f})")

    logger.info("\nNext steps:")
    logger.info("  1. Start API:       uvicorn src.api.main:app --reload --port 8000")
    logger.info("  2. Start dashboard: streamlit run dashboard/app.py --server.port 8501")
    logger.info("  3. Open browser:    http://localhost:8501")


def main():
    parser = argparse.ArgumentParser(description="IDS Training Orchestrator")
    parser.add_argument("--data", default="data/raw", help="Path to ML-ready CICIDS2017 CSV directory")
    parser.add_argument("--raw-flows", default="",
                        dest="raw_flows",
                        help="Path to raw per-flow CSV directory (GeneratedLabelledFlows). "
                             "Set to '' to disable. Default: data/raw_flows")
    parser.add_argument("--exp", choices=["baseline","engineered","ensemble","all"],
                        default="all", help="Which experiment(s) to run")
    args = parser.parse_args()

    data_dir = args.data
    if not Path(data_dir).exists() or not list(Path(data_dir).glob("*.csv")):
        logger.error(f"No CSV files found in '{data_dir}'.")
        logger.error("Download CICIDS2017 CSVs and place them in data/raw/")
        logger.error("  URL: https://www.unb.ca/cic/datasets/ids-2017.html")
        sys.exit(1)

    # Collect extra dirs (raw per-flow exports)
    extra_dirs: list | None = None
    if args.raw_flows:
        rf_path = Path(args.raw_flows)
        if rf_path.exists() and list(rf_path.glob("*.csv")):
            extra_dirs = [str(rf_path)]
            logger.info(f"Raw flow CSVs found at '{rf_path}' — will merge into training data.")
        else:
            logger.info(f"Raw flow dir '{args.raw_flows}' not found or empty — skipping.")

    ensure_dirs()
    t0 = time.time()
    results = {}

    try:
        rf_model = None

        if args.exp in ("all", "baseline"):
            results["baseline"] = run_baseline(data_dir, extra_dirs)

        if args.exp in ("all", "engineered"):
            rf_model, metrics = run_engineered(data_dir, extra_dirs)
            results["engineered"] = metrics

        if args.exp in ("all", "ensemble"):
            if rf_model is None:
                # Load existing RF if not just trained
                import joblib
                rf_path = Path("artifacts/models/rf_model.pkl")
                if rf_path.exists():
                    rf_model = joblib.load(rf_path)
                    logger.info(f"Loaded existing RF from {rf_path}")
                else:
                    logger.warning("No RF model found. Run engineered experiment first.")
                    logger.info("Running engineered experiment now...")
                    rf_model, metrics = run_engineered(data_dir, extra_dirs)
                    results["engineered"] = metrics

            results["ensemble"] = run_ensemble(data_dir, rf_model, extra_dirs)

        # Always save feature columns after training
        save_feature_cols(data_dir, extra_dirs)

        elapsed = time.time() - t0
        logger.info(f"\n  Total training time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
        print_summary(results)

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
