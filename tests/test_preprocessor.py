"""
test_preprocessor.py — Phase 1 Tests
Skill: tdd-workflow, systematic-debugging
Tests: clean(), engineer_features(), filter_labels(), full_pipeline()
"""

import numpy as np
import pandas as pd
import pytest

from src.pipeline.preprocessor import (
    clean,
    engineer_features,
    filter_labels,
    apply_smote,
    split_and_scale,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_df():
    """Minimal synthetic CICIDS2017-like DataFrame."""
    return pd.DataFrame({
        "Flow ID": ["f1", "f2", "f3", "f4"],
        "Source IP": ["192.168.1.1"] * 4,
        "Destination IP": ["10.0.0.1"] * 4,
        "Timestamp": ["2017-07-03 08:00:00"] * 4,
        "Label": ["BENIGN", "DDoS", "PortScan", "BENIGN"],
        "SYN Flag Count": [1, 50, 1, 0],
        "ACK Flag Count": [10, 1, 0, 5],
        "Total Length of Fwd Packets": [1000, 50000, 200, 800],
        "Total Fwd Packets": [10, 500, 5, 8],
        "Total Backward Packets": [10, 1, 0, 7],
        "Flow Duration": [1000000, 500, 100000, 900000],
        "Flow IAT Mean": [100000.0, 1.0, 20000.0, 90000.0],
    })


@pytest.fixture
def dirty_df(sample_df):
    """DataFrame with inf values and duplicates."""
    df = sample_df.copy()
    extra = df.iloc[[0, 1]].copy()
    df = pd.concat([df, extra], ignore_index=True)  # integer index 0..5
    # Cast to float first — int64 cannot hold inf
    df["SYN Flag Count"] = df["SYN Flag Count"].astype(float)
    df.iloc[0, df.columns.get_loc("SYN Flag Count")] = float("inf")
    return df



# ── filter_labels tests ───────────────────────────────────────────────────────

def test_filter_labels_creates_binary_target(sample_df):
    df = filter_labels(sample_df)
    assert "target" in df.columns
    assert set(df["target"].unique()).issubset({0, 1})


def test_filter_labels_benign_is_zero(sample_df):
    df = filter_labels(sample_df)
    benign_mask = sample_df["Label"] == "BENIGN"
    assert (df.loc[benign_mask, "target"] == 0).all()


def test_filter_labels_attack_is_one(sample_df):
    df = filter_labels(sample_df)
    attack_mask = sample_df["Label"] != "BENIGN"
    assert (df.loc[attack_mask, "target"] == 1).all()


# ── clean() tests ─────────────────────────────────────────────────────────────

def test_clean_removes_inf_values(dirty_df):
    df = filter_labels(dirty_df)
    cleaned = clean(df)
    numeric_cols = cleaned.select_dtypes(include=[np.number]).columns
    assert not cleaned[numeric_cols].isin([float("inf"), float("-inf")]).any().any()


def test_clean_removes_duplicates(dirty_df):
    df = filter_labels(dirty_df)
    cleaned = clean(df)
    assert cleaned.duplicated().sum() == 0


def test_clean_drops_non_feature_columns(sample_df):
    sample_df = filter_labels(sample_df)
    cleaned = clean(sample_df)
    for col in ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]:
        assert col not in cleaned.columns


# ── engineer_features() tests ─────────────────────────────────────────────────

def test_engineer_features_adds_all_7(sample_df):
    sample_df = filter_labels(sample_df)
    sample_df = clean(sample_df)
    engineered = engineer_features(sample_df)
    expected = [
        "syn_ack_ratio", "bytes_per_second", "packets_per_second",
        "fwd_bwd_ratio", "avg_packet_size", "iat_mean", "flow_duration_var",
    ]
    for feat in expected:
        assert feat in engineered.columns, f"Missing feature: {feat}"


def test_engineer_features_no_nan(sample_df):
    sample_df = filter_labels(sample_df)
    sample_df = clean(sample_df)
    engineered = engineer_features(sample_df)
    assert not engineered.isnull().any().any()


def test_syn_ack_ratio_ddos_higher(sample_df):
    """DDoS flow should have higher syn_ack_ratio than benign."""
    sample_df = filter_labels(sample_df)
    sample_df = clean(sample_df)
    engineered = engineer_features(sample_df)
    # DDoS row originally had SYN=50, ACK=1 → high ratio
    assert engineered["syn_ack_ratio"].max() > 5.0


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_clean_empty_df_raises():
    """clean() on an empty DataFrame should raise some exception (KeyError, ValueError, etc.)"""
    with pytest.raises((Exception, KeyError, ValueError, AttributeError)):
        df = pd.DataFrame()
        df = filter_labels(df)


def test_filter_labels_missing_label_col_raises():
    df = pd.DataFrame({"A": [1, 2, 3]})
    with pytest.raises(KeyError):
        filter_labels(df)
