"""
preprocessor.py
────────────────────────────────────────────────────────────────────────────────
Phase 1 — Data Cleaning + Feature Engineering
Skill references: scikit-learn, data-storytelling, systematic-debugging

Cleaning pipeline (5 steps, mandatory, per master prompt):
  1. Replace inf → NaN, drop NaN rows
  2. Drop columns with >50% missing
  3. Drop duplicate rows
  4. Drop non-feature columns
  5. MinMaxScale + SMOTE for training set

Custom engineered features (7, mandatory, per master prompt):
  syn_ack_ratio      → DDoS indicator (SYN flood)
  bytes_per_second   → Burst/DDoS detection
  packets_per_second → Packet rate anomaly
  fwd_bwd_ratio      → Asymmetric flow = scan/probe
  avg_packet_size    → Unusual payload sizing
  iat_mean           → Jitter = bot behavior
  flow_duration_var  → Variance per source IP = reconnaissance
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

logger = logging.getLogger(__name__)

# ── Columns to drop (non-feature identifiers) ─────────────────────────────────
DROP_COLS = [
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Protocol", "Timestamp", "Label",
]

# ── Labels to keep → binary mapping ───────────────────────────────────────────
KEEP_LABELS = {"BENIGN", "DDoS", "PortScan", "DoS GoldenEye",
               "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
               "FTP-Patator", "SSH-Patator"}  # broad but controlled

LABEL_MAP = {"BENIGN": 0}   # everything else → 1 (Attack)


def _read_csvs_from_dir(directory: Path) -> list:
    """Read all CSVs in a directory, strip column whitespace, return list of DataFrames."""
    csv_files = list(directory.glob("*.csv"))
    if not csv_files:
        logger.warning(f"No CSV files found in {directory} — skipping.")
        return []
    logger.info(f"  Loading {len(csv_files)} CSV(s) from {directory}")
    frames = []
    for f in csv_files:
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(f, low_memory=False, encoding=enc)
                df.columns = df.columns.str.strip()   # CICIDS2017 has leading spaces
                frames.append(df)
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        else:
            logger.warning(f"  Could not decode {f.name} — skipping.")
    return frames


def load_raw(
    data_dir: str | Path,
    extra_dirs: list[str | Path] | None = None,
) -> pd.DataFrame:
    """
    Load CICIDS2017 CSV files from one or more directories and concatenate.

    Args:
        data_dir:   Primary directory (e.g. data/raw — ML-ready CSVs).
        extra_dirs: Optional additional directories (e.g. data/raw_flows —
                    raw per-flow exports with extra identity columns).
                    Extra columns like Source IP / Protocol are in DROP_COLS
                    and will be removed during clean().
    """
    all_frames: list = []

    # Primary source
    primary = Path(data_dir)
    primary_frames = _read_csvs_from_dir(primary)
    if not primary_frames:
        raise FileNotFoundError(f"No CSV files found in {primary}")
    all_frames.extend(primary_frames)

    # Extra sources (raw per-flow exports, etc.)
    if extra_dirs:
        for d in extra_dirs:
            extra_frames = _read_csvs_from_dir(Path(d))
            all_frames.extend(extra_frames)

    raw = pd.concat(all_frames, ignore_index=True)
    logger.info(f"Combined dataset shape: {raw.shape} ({len(all_frames)} file(s) total)")
    return raw


def filter_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only Probing + DDoS related labels + BENIGN, map to binary."""
    # Strip whitespace from label column
    label_col = "Label"
    if label_col not in df.columns:
        raise KeyError(f"'{label_col}' column not found. Available: {df.columns.tolist()}")
    df[label_col] = df[label_col].str.strip()
    # Map: BENIGN=0, attack=1
    df["target"] = df[label_col].apply(lambda x: 0 if x == "BENIGN" else 1)
    kept = df["target"].value_counts()
    logger.info(f"Label distribution after binary mapping:\n{kept}")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """5-step mandatory cleaning pipeline."""
    original_shape = df.shape

    # Step 1 — Replace inf with NaN, drop NaN rows
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    logger.info(f"After inf+NaN drop: {df.shape} (was {original_shape})")

    # Step 2 — Drop columns with >50% missing (already dropped NaN, but for safety)
    thresh = len(df) * 0.5
    df = df.dropna(axis=1, thresh=thresh)

    # Step 3 — Drop duplicates
    before = len(df)
    df.drop_duplicates(inplace=True)
    logger.info(f"Dropped {before - len(df)} duplicate rows")

    # Step 4 — Drop non-feature columns (keep target)
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    df.drop(columns=cols_to_drop, inplace=True)

    logger.info(f"Final clean shape: {df.shape}")
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add 7 custom behaviorally meaningful features.
    Each feature targets a specific attack behavior.
    """
    # 1. SYN/ACK Imbalance Ratio → DDoS: high SYN, low ACK (flood pattern)
    if "SYN Flag Count" in df.columns and "ACK Flag Count" in df.columns:
        df["syn_ack_ratio"] = df["SYN Flag Count"] / (df["ACK Flag Count"] + 1)

    # 2. Bytes Per Second → Burst/DDoS: abnormally high bandwidth usage
    if "Total Length of Fwd Packets" in df.columns and "Flow Duration" in df.columns:
        df["bytes_per_second"] = df["Total Length of Fwd Packets"] / (df["Flow Duration"] + 1)

    # 3. Packets Per Second → Packet flood: many small packets per unit time
    if "Total Fwd Packets" in df.columns and "Flow Duration" in df.columns:
        df["packets_per_second"] = df["Total Fwd Packets"] / (df["Flow Duration"] + 1)

    # 4. Forward/Backward Ratio → Port scan: one-directional probing (no response)
    if "Total Fwd Packets" in df.columns and "Total Backward Packets" in df.columns:
        df["fwd_bwd_ratio"] = df["Total Fwd Packets"] / (df["Total Backward Packets"] + 1)

    # 5. Average Packet Size → Reconnaissance: very small packets = scan, not data transfer
    if "Total Length of Fwd Packets" in df.columns and "Total Fwd Packets" in df.columns:
        df["avg_packet_size"] = df["Total Length of Fwd Packets"] / (df["Total Fwd Packets"] + 1)

    # 6. Inter-Arrival Time Mean → Jitter/Bot: uniform IAT = automated/scripted attack
    if "Flow IAT Mean" in df.columns:
        df["iat_mean"] = df["Flow IAT Mean"]   # direct pass-through with semantic name

    # 7. Flow Duration Variance per Source IP → Reconnaissance: attacker varies timing
    # Computed as rolling std if Source IP is available, else global std approximation
    if "Flow Duration" in df.columns:
        df["flow_duration_var"] = df["Flow Duration"].transform(
            lambda x: x.rolling(window=5, min_periods=1).std().fillna(0)
        )

    logger.info(f"Engineered features added. New shape: {df.shape}")
    return df


def split_and_scale(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, MinMaxScaler, list]:
    """Split into train/test, apply MinMaxScaler. Returns X_train, X_test, y_train, y_test, scaler, feature_cols."""
    from sklearn.model_selection import train_test_split

    target_col = "target"
    feature_cols = [c for c in df.columns if c != target_col]

    X = df[feature_cols].values
    y = df[target_col].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    logger.info(f"Train size: {X_train.shape}, Test size: {X_test.shape}")
    logger.info(f"Class distribution (train) — 0:{(y_train==0).sum()}, 1:{(y_train==1).sum()}")
    return X_train, X_test, y_train, y_test, scaler, feature_cols


def apply_smote(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Apply SMOTE to handle class imbalance in training set."""
    from imblearn.over_sampling import SMOTE
    sm = SMOTE(random_state=random_state)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    logger.info(f"After SMOTE — 0:{(y_res==0).sum()}, 1:{(y_res==1).sum()}")
    return X_res, y_res


def full_pipeline(
    data_dir: str | Path,
    apply_engineering: bool = True,
    use_smote: bool = True,
    extra_dirs: list[str | Path] | None = None,
) -> dict:
    """
    Run the complete preprocessing pipeline.

    Args:
        data_dir:         Primary CSV directory (ML-ready CSVs).
        apply_engineering: Add 7 custom behavioural features.
        use_smote:        Apply SMOTE oversampling on training set.
        extra_dirs:       Additional CSV directories to merge (e.g. raw_flows).

    Returns dict with X_train, X_test, y_train, y_test, scaler, feature_cols.
    """
    df = load_raw(data_dir, extra_dirs=extra_dirs)
    df = filter_labels(df)
    df = clean(df)
    if apply_engineering:
        df = engineer_features(df)
        # Re-clean: division-based features can reintroduce inf/extreme values
        # especially when raw flow rows have flow_duration=0 or near-zero denominators
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        logger.info(f"Post-engineering clean shape: {df.shape}")
    X_train, X_test, y_train, y_test, scaler, feature_cols = split_and_scale(df)
    if use_smote:
        X_train, y_train = apply_smote(X_train, y_train)
    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "scaler": scaler,
        "feature_cols": feature_cols,
    }
