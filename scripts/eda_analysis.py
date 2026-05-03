"""
scripts/eda_analysis.py
────────────────────────────────────────────────────────────────────────────────
Exploratory Data Analysis for CICIDS2017 dataset.

Usage:
    python scripts/eda_analysis.py
    python scripts/eda_analysis.py --data data/raw --out artifacts/eda

Outputs (all written to --out directory):
    label_distribution.csv   - per-file and global label counts
    feature_stats.csv        - per-feature mean/std/min/max/null%
    class_balance.png        - attack vs benign bar chart
    attack_breakdown.png     - per-attack-type bar chart
    correlation_heatmap.png  - top-40 feature correlation matrix
    missing_values.csv       - columns with any missing/inf values
    eda_summary.txt          - human-readable summary report
"""

from __future__ import annotations

import argparse
import logging
import io
import sys
from pathlib import Path

# ── Force UTF-8 stdout on Windows (avoids CP1252 UnicodeEncodeError) ─────────
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.dpi": 120,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "font.family": "DejaVu Sans",
})
PALETTE = "#2563eb"
ATTACK_COLOR = "#dc2626"
BENIGN_COLOR = "#16a34a"


def _read_all_csvs(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns:
        combined  - full concatenated DataFrame
        per_file  - label counts per CSV file
    """
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    logger.info(f"Found {len(csv_files)} CSV files in {data_dir}")
    frames = []
    per_file_rows = []

    for f in csv_files:
        logger.info(f"  Loading {f.name} ({f.stat().st_size / 1e6:.1f} MB) ...")
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(f, low_memory=False, encoding=enc)
                df.columns = df.columns.str.strip()
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        else:
            logger.warning(f"  Could not decode {f.name} — skipping.")
            continue

        if "Label" in df.columns:
            df["Label"] = df["Label"].str.strip()
            df["Label"] = df["Label"].str.replace(r'[^\x00-\x7F]+', '-', regex=True)
            counts = df["Label"].value_counts().to_dict()
        else:
            counts = {"NO_LABEL": len(df)}

        counts["_file"] = f.name
        counts["_total_rows"] = len(df)
        per_file_rows.append(counts)
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    per_file = pd.DataFrame(per_file_rows).fillna(0)
    logger.info(f"Combined shape: {combined.shape}")
    return combined, per_file


def analyse_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Return global label counts with attack/benign annotation."""
    if "Label" not in df.columns:
        logger.warning("No 'Label' column found.")
        return pd.DataFrame()
    df["Label"] = df["Label"].str.strip()
    counts = df["Label"].value_counts().reset_index()
    counts.columns = ["Label", "Count"]
    counts["Type"] = counts["Label"].apply(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")
    counts["Pct"] = (counts["Count"] / counts["Count"].sum() * 100).round(2)
    return counts


def analyse_features(df: pd.DataFrame) -> pd.DataFrame:
    """Per-feature descriptive stats including null% and inf count."""
    numeric = df.select_dtypes(include=[np.number])
    stats = numeric.describe().T  # columns: count, mean, std, min, 25%, 50%, 75%, max
    stats["null_pct"] = (df.isnull().sum() / len(df) * 100).reindex(stats.index).fillna(0).round(2)
    stats["inf_count"] = numeric.apply(lambda c: np.isinf(c).sum())
    stats = stats.rename(columns={"50%": "median"})
    return stats.reset_index().rename(columns={"index": "feature"})


def plot_class_balance(label_counts: pd.DataFrame, out_dir: Path):
    """Bar chart: Benign vs Attack total counts."""
    summary = label_counts.groupby("Type")["Count"].sum().reset_index()
    colors = [BENIGN_COLOR if t == "BENIGN" else ATTACK_COLOR for t in summary["Type"]]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(summary["Type"], summary["Count"] / 1e6, color=colors, edgecolor="white", linewidth=0.8)
    ax.set_title("Class Balance: Benign vs Attack")
    ax.set_ylabel("Samples (millions)")
    ax.set_xlabel("Class")
    for bar, (_, row) in zip(bars, summary.iterrows()):
        pct = row["Count"] / summary["Count"].sum() * 100
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{pct:.1f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = out_dir / "class_balance.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved: {out}")


def plot_attack_breakdown(label_counts: pd.DataFrame, out_dir: Path):
    """Horizontal bar chart of attack type distribution (excluding BENIGN)."""
    attacks = label_counts[label_counts["Type"] == "ATTACK"].sort_values("Count", ascending=True)
    if attacks.empty:
        logger.info("No attack labels found — skipping attack breakdown plot.")
        return

    fig, ax = plt.subplots(figsize=(9, max(4, len(attacks) * 0.55)))
    bars = ax.barh(attacks["Label"], attacks["Count"] / 1e3, color=ATTACK_COLOR,
                   alpha=0.85, edgecolor="white", linewidth=0.5)
    ax.set_title("Attack Type Distribution")
    ax.set_xlabel("Samples (thousands)")
    for bar, (_, row) in zip(bars, attacks.iterrows()):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                f"{int(row['Count']):,}", va="center", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = out_dir / "attack_breakdown.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved: {out}")


def plot_correlation_heatmap(df: pd.DataFrame, out_dir: Path, top_n: int = 40):
    """Correlation heatmap of top-N most variable numeric features."""
    numeric = df.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan).dropna(axis=1, how="all")
    # Select top-N by variance to keep the plot readable
    variances = numeric.var().nlargest(top_n)
    subset = numeric[variances.index]
    corr = subset.corr()

    fig, ax = plt.subplots(figsize=(16, 14))
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(
        corr, mask=mask, cmap="RdBu_r", center=0,
        vmin=-1, vmax=1, linewidths=0.3, linecolor="white",
        ax=ax, cbar_kws={"shrink": 0.6, "label": "Pearson r"},
        xticklabels=True, yticklabels=True,
        annot=False,
    )
    ax.set_title(f"Feature Correlation Heatmap (top {top_n} by variance)", pad=14)
    ax.tick_params(axis="x", labelsize=6, rotation=90)
    ax.tick_params(axis="y", labelsize=6)
    fig.tight_layout()
    out = out_dir / "correlation_heatmap.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved: {out}")


def plot_feature_importance_proxy(df: pd.DataFrame, out_dir: Path):
    """Variance-ranked feature importance proxy (no model needed)."""
    numeric = df.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    variances = numeric.var().dropna().nlargest(30).sort_values()
    fig, ax = plt.subplots(figsize=(9, 8))
    ax.barh(variances.index, variances.values, color=PALETTE, alpha=0.8, edgecolor="white")
    ax.set_title("Top 30 Features by Variance (proxy for importance)")
    ax.set_xlabel("Variance")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = out_dir / "feature_variance.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved: {out}")


def generate_summary_report(
    df: pd.DataFrame,
    label_counts: pd.DataFrame,
    feature_stats: pd.DataFrame,
    out_dir: Path,
) -> str:
    """Write a human-readable EDA summary text file."""
    total = len(df)
    n_features = df.select_dtypes(include=[np.number]).shape[1]
    n_files = 8  # CICIDS2017

    benign = label_counts[label_counts["Type"] == "BENIGN"]["Count"].sum()
    attack = label_counts[label_counts["Type"] == "ATTACK"]["Count"].sum()
    imbalance_ratio = benign / attack if attack > 0 else float("inf")

    null_cols = feature_stats[feature_stats["null_pct"] > 0]["feature"].tolist()
    inf_cols = feature_stats[feature_stats["inf_count"] > 0]["feature"].tolist()

    lines = [
        "=" * 72,
        "  CICIDS2017 — EDA SUMMARY REPORT",
        "=" * 72,
        "",
        "DATASET OVERVIEW",
        "-" * 40,
        f"  Source files   : {n_files} daily PCAP-derived CSVs",
        f"  Total rows     : {total:,}",
        f"  Numeric features: {n_features}",
        "",
        "CLASS DISTRIBUTION",
        "-" * 40,
        f"  BENIGN         : {benign:,} ({benign/total*100:.1f}%)",
        f"  ATTACK         : {attack:,} ({attack/total*100:.1f}%)",
        f"  Imbalance ratio: {imbalance_ratio:.1f}:1 (Benign:Attack)",
        "",
        "ATTACK TYPE BREAKDOWN",
        "-" * 40,
    ]
    for _, row in label_counts[label_counts["Type"] == "ATTACK"].sort_values("Count", ascending=False).iterrows():
        lines.append(f"  {row['Label']:<40} {int(row['Count']):>10,}  ({row['Pct']:.2f}%)")

    lines += [
        "",
        "DATA QUALITY",
        "-" * 40,
        f"  Columns with null values  : {len(null_cols)}",
        f"  Columns with inf values   : {len(inf_cols)}",
    ]
    if inf_cols:
        lines.append(f"  Inf columns: {', '.join(inf_cols[:10])}{'...' if len(inf_cols) > 10 else ''}")

    lines += [
        "",
        "PIPELINE RECOMMENDATION",
        "-" * 40,
        "  1. Replace inf → NaN, drop NaN rows (already in preprocessor.py)",
        "  2. Drop duplicate rows (already in preprocessor.py)",
        "  3. Apply MinMaxScaler (already in preprocessor.py)",
        "  4. SMOTE on training set for class balancing (Exp 2+)",
        "  5. Use data/raw/ as canonical source (archive/ = duplicate, safe to delete)",
        "",
        "DUPLICATE DATA NOTE",
        "-" * 40,
        "  Three identical copies of the 8 CSVs were found:",
        "    - ids-ml-project/data/raw/           (CANONICAL — used by pipeline)",
        "    - CIC-IDS-2017/CSVS/MachineLearningCSV/MachineLearningCVE/  (DUPLICATE)",
        "    - CIC-IDS-2017/CSVS/archive/          (DUPLICATE)",
        "  Recommendation: Delete the two duplicate folders to reclaim ~1.76 GB.",
        "",
        "=" * 72,
    ]

    report = "\n".join(lines)
    out_path = out_dir / "eda_summary.txt"
    out_path.write_text(report, encoding="utf-8")
    logger.info(f"Saved: {out_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="CICIDS2017 Exploratory Data Analysis")
    parser.add_argument("--data", default="data/raw", help="Path to CSV directory")
    parser.add_argument("--out", default="artifacts/eda", help="Output directory for plots/reports")
    args = parser.parse_args()

    data_dir = Path(args.data)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    logger.info("=" * 60)
    logger.info("PHASE 1 — Loading data")
    logger.info("=" * 60)
    df, per_file = _read_all_csvs(data_dir)

    # 2. Label analysis
    logger.info("=" * 60)
    logger.info("PHASE 2 — Label distribution")
    logger.info("=" * 60)
    label_counts = analyse_labels(df)
    if not label_counts.empty:
        label_counts.to_csv(out_dir / "label_distribution.csv", index=False)
        logger.info(f"Labels:\n{label_counts.to_string(index=False)}")
    per_file.to_csv(out_dir / "per_file_labels.csv", index=False)

    # 3. Feature statistics
    logger.info("=" * 60)
    logger.info("PHASE 3 — Feature statistics")
    logger.info("=" * 60)
    feature_stats = analyse_features(df)
    feature_stats.to_csv(out_dir / "feature_stats.csv", index=False)
    missing = feature_stats[feature_stats["null_pct"] > 0][["feature", "null_pct", "inf_count"]]
    missing.to_csv(out_dir / "missing_values.csv", index=False)
    logger.info(f"Feature stats saved ({len(feature_stats)} features)")
    logger.info(f"Columns with nulls: {len(missing)}")

    # 4. Plots
    logger.info("=" * 60)
    logger.info("PHASE 4 — Generating plots")
    logger.info("=" * 60)
    if not label_counts.empty:
        plot_class_balance(label_counts, out_dir)
        plot_attack_breakdown(label_counts, out_dir)
    plot_correlation_heatmap(df, out_dir)
    plot_feature_importance_proxy(df, out_dir)

    # 5. Summary report
    logger.info("=" * 60)
    logger.info("PHASE 5 — Summary report")
    logger.info("=" * 60)
    report = generate_summary_report(df, label_counts, feature_stats, out_dir)
    print("\n" + report)

    logger.info(f"\nAll outputs saved to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
