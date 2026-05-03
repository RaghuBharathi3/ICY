"""
scripts/cleanup_duplicates.py
────────────────────────────────────────────────────────────────────────────────
Safely removes the two duplicate CSV directories to reclaim ~1.76 GB of disk.

CANONICAL source: ids-ml-project/data/raw/  (NOT deleted)
DELETED:
  - CIC-IDS-2017/CSVS/MachineLearningCSV/MachineLearningCVE/
  - CIC-IDS-2017/CSVS/archive/

Usage:
    python scripts/cleanup_duplicates.py           # dry-run (shows what would be deleted)
    python scripts/cleanup_duplicates.py --confirm # actually delete

Safety:
  - Verifies file count and total size match canonical before deleting
  - Dry-run by default
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import shutil
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ── Canonical source (DO NOT DELETE) ──────────────────────────────────────────
CANONICAL = Path(r"C:\Users\Windows\Documents\ICY\ids-ml-project\data\raw")

# ── Duplicate directories (SAFE TO DELETE) ────────────────────────────────────
DUPLICATES = [
    Path(r"C:\Users\Windows\Documents\ICY\CIC-IDS-2017\CSVS\MachineLearningCSV\MachineLearningCVE"),
    Path(r"C:\Users\Windows\Documents\ICY\CIC-IDS-2017\CSVS\archive"),
]


def _dir_stats(directory: Path) -> tuple[int, int, list[str]]:
    """Return (file_count, total_bytes, sorted_filenames)."""
    files = sorted(directory.glob("*.csv"))
    total = sum(f.stat().st_size for f in files)
    return len(files), total, [f.name for f in files]


def verify_duplicate(canonical: Path, duplicate: Path) -> bool:
    """
    Verify that `duplicate` matches `canonical` by:
      - Same number of CSV files
      - Same filenames
      - Same total size (byte-exact match is ~guaranteed if sizes match for CICIDS2017)
    """
    if not duplicate.exists():
        logger.info(f"  {duplicate} does not exist — skipping.")
        return False

    c_count, c_size, c_names = _dir_stats(canonical)
    d_count, d_size, d_names = _dir_stats(duplicate)

    ok = True
    if c_count != d_count:
        logger.warning(f"  File count mismatch: canonical={c_count}, dup={d_count}")
        ok = False
    if c_size != d_size:
        logger.warning(f"  Size mismatch: canonical={c_size:,}B, dup={d_size:,}B")
        ok = False
    if c_names != d_names:
        logger.warning(f"  Filename mismatch: {set(c_names) ^ set(d_names)}")
        ok = False

    if ok:
        logger.info(f"  VERIFIED: {duplicate.name}/ matches canonical ({d_count} files, {d_size/1e6:.1f} MB)")
    return ok


def delete_duplicate(directory: Path, confirm: bool = False):
    """Remove duplicate directory."""
    _, size, _ = _dir_stats(directory)
    if not confirm:
        logger.info(f"  [DRY RUN] Would delete: {directory}  ({size/1e6:.1f} MB)")
        return

    logger.info(f"  Deleting: {directory}  ({size/1e6:.1f} MB) ...")
    shutil.rmtree(directory)
    logger.info(f"  Deleted: {directory}")


def main():
    parser = argparse.ArgumentParser(description="Remove duplicate CICIDS2017 CSV directories")
    parser.add_argument(
        "--confirm", action="store_true",
        help="Actually delete the duplicates. Without this flag, runs in dry-run mode."
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("CICIDS2017 Duplicate Cleanup")
    logger.info("=" * 60)

    if not CANONICAL.exists():
        logger.error(f"Canonical directory not found: {CANONICAL}")
        sys.exit(1)

    c_count, c_size, _ = _dir_stats(CANONICAL)
    logger.info(f"Canonical: {CANONICAL}")
    logger.info(f"  {c_count} files, {c_size/1e9:.2f} GB — THIS WILL NOT BE DELETED\n")

    total_freed = 0
    to_delete = []

    for dup in DUPLICATES:
        logger.info(f"Checking: {dup}")
        if verify_duplicate(CANONICAL, dup):
            _, size, _ = _dir_stats(dup)
            total_freed += size
            to_delete.append(dup)
        else:
            logger.warning(f"  Skipping {dup} — does not match canonical.")

    if not to_delete:
        logger.info("No duplicates found or verified. Nothing to do.")
        return

    logger.info("")
    logger.info(f"Duplicates confirmed: {len(to_delete)}")
    logger.info(f"Space to be freed  : {total_freed/1e9:.2f} GB")

    if not args.confirm:
        logger.info("")
        logger.info("[DRY RUN] No files deleted.")
        logger.info("Re-run with --confirm to actually delete:")
        logger.info("  python scripts/cleanup_duplicates.py --confirm")
        return

    logger.info("")
    logger.info("DELETING ...")
    for dup in to_delete:
        delete_duplicate(dup, confirm=True)

    logger.info("")
    logger.info(f"Done. Freed {total_freed/1e9:.2f} GB.")


if __name__ == "__main__":
    main()
