"""
watcher.py
────────────────────────────────────────────────────────────────────────────────
Phase 5 — Semi-Real-Time Watch Folder Pipeline
Skill references: backend-architect, async-python-patterns

Watches data/watch/ for new .csv files.
On detection:
  1. Load CSV → preprocess → engineer features
  2. Run RF + IF ensemble prediction
  3. Save results to artifacts/reports/live_results.json

Usage:
  python -m src.pipeline.watcher

Drop any CICIDS2017-formatted CSV into data/watch/ to trigger detection.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from pathlib import Path

import numpy as np
import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.pipeline.preprocessor import (
    clean,
    engineer_features,
    filter_labels,
)

logger = logging.getLogger(__name__)

WATCH_DIR = Path("data/watch")
RESULTS_FILE = Path("artifacts/reports/live_results.json")
MODELS_DIR = Path("artifacts/models")
SCALER_PATH = MODELS_DIR / "scaler.pkl"
FEATURE_COLS_PATH = MODELS_DIR / "feature_cols.json"

# In-memory store of all processed flows (cleared on restart)
_flow_store: list[dict] = []


def _load_predictor():
    """Load predictor once. Fails loudly if models not trained yet."""
    import joblib
    from src.pipeline.predictor import Predictor
    feature_cols = []
    if FEATURE_COLS_PATH.exists():
        with open(FEATURE_COLS_PATH) as f:
            feature_cols = json.load(f)
    return Predictor(feature_cols=feature_cols)


def _process_csv(path: Path, predictor) -> list[dict]:
    """Process a single CSV file through the full inference pipeline."""
    logger.info(f"Processing: {path.name}")
    try:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()

        # Store IP info before stripping
        src_ips = df.get("Source IP", pd.Series(["unknown"] * len(df))).values
        dst_ips = df.get("Destination IP", pd.Series(["unknown"] * len(df))).values

        # Run through cleaning + feature engineering
        if "Label" in df.columns:
            df = filter_labels(df)
        df = clean(df)
        df = engineer_features(df)

        # Scale if scaler exists
        if SCALER_PATH.exists():
            import joblib
            scaler = joblib.load(SCALER_PATH)
            target_col = "target" if "target" in df.columns else None
            feature_cols = [c for c in df.columns if c != "target"]
            X = scaler.transform(df[feature_cols].values)
        else:
            target_col = "target" if "target" in df.columns else None
            feature_cols = [c for c in df.columns if c != target_col]
            X = df[feature_cols].values

        results = []
        for i in range(len(X)):
            record = predictor.predict_single(
                X[i],
                src_ip=str(src_ips[i]) if i < len(src_ips) else "unknown",
                dst_ip=str(dst_ips[i]) if i < len(dst_ips) else "unknown",
            )
            results.append(asdict(record))

        attacks = sum(1 for r in results if r["decision"] == "ATTACK")
        suspicious = sum(1 for r in results if r["decision"] == "SUSPICIOUS")
        logger.info(f"Processed {len(results)} flows: {attacks} ATTACK, {suspicious} SUSPICIOUS")
        return results

    except Exception as e:
        logger.error(f"Failed to process {path.name}: {e}", exc_info=True)
        return []


class CSVHandler(FileSystemEventHandler):
    """Watchdog handler — triggers on new .csv files in watch folder."""

    def __init__(self):
        self.predictor = _load_predictor()

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() != ".csv":
            return

        logger.info(f"New file detected: {path.name}")
        time.sleep(0.5)   # brief wait to ensure file write is complete

        results = _process_csv(path, self.predictor)
        _flow_store.extend(results)

        # Persist to JSON for API to read
        RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(RESULTS_FILE, "w") as f:
            json.dump(_flow_store, f, indent=2, default=str)

        logger.info(f"Results written → {RESULTS_FILE} (total: {len(_flow_store)} flows)")


def start_watcher(watch_dir: str | Path = WATCH_DIR):
    """Start the watch folder observer. Blocks until Ctrl+C."""
    watch_dir = Path(watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    handler = CSVHandler()
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive=False)
    observer.start()
    logger.info(f"Watching {watch_dir} for new CSV files... (Ctrl+C to stop)")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Watcher stopped.")
    observer.join()


if __name__ == "__main__":
    start_watcher()
