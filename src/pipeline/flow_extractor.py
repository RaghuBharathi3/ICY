"""
flow_extractor.py
────────────────────────────────────────────────────────────────────────────────
Phase 5 — PCAP → CSV Conversion Wrapper (CICFlowMeter)
Skill references: backend-architect, bash-linux

CICFlowMeter is a Java tool that converts raw PCAP files to flow-based CSVs
in CICIDS2017-compatible format. This wrapper invokes it via subprocess.

Prerequisites:
  - CICFlowMeter installed: https://github.com/ahlashkari/CICFlowMeter
  - JAVA_HOME set, cfm.bat / cfm.sh on PATH
  - Or: skip PCAP processing and drop pre-extracted CSVs into data/watch/

NOTE: The watch folder also accepts pre-extracted CSVs directly.
If you don't have CICFlowMeter, drop CICIDS2017 CSVs into data/watch/ instead.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to CICFlowMeter executable — adjust to your installation
# On Windows: cfm.bat, on Linux/Mac: cfm.sh
CICFLOWMETER_CMD = "cfm"   # must be on PATH


def pcap_to_csv(pcap_path: str | Path, output_dir: str | Path) -> Path:
    """
    Convert a PCAP file to CICIDS2017-format CSV using CICFlowMeter.

    Args:
        pcap_path: Path to input .pcap file
        output_dir: Directory to write output CSV

    Returns:
        Path to the generated CSV file

    Raises:
        FileNotFoundError: If CICFlowMeter is not installed
        subprocess.CalledProcessError: If conversion fails
    """
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    logger.info(f"Converting {pcap_path.name} → CSV via CICFlowMeter...")

    try:
        result = subprocess.run(
            [CICFLOWMETER_CMD, str(pcap_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=300,   # 5 minute timeout for large PCAPs
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                CICFLOWMETER_CMD,
                output=result.stdout,
                stderr=result.stderr,
            )
    except FileNotFoundError:
        raise FileNotFoundError(
            "CICFlowMeter not found. Install from: https://github.com/ahlashkari/CICFlowMeter\n"
            "Alternatively, drop pre-extracted CICIDS2017-format CSVs into data/watch/ directly."
        )

    # CICFlowMeter names output as: {pcap_name}_Flow.csv
    expected_csv = output_dir / f"{pcap_path.stem}_Flow.csv"
    if not expected_csv.exists():
        # Look for any CSV created in the output dir
        csvs = list(output_dir.glob("*.csv"))
        if csvs:
            return csvs[-1]
        raise FileNotFoundError(f"CICFlowMeter did not produce a CSV in {output_dir}")

    logger.info(f"Conversion complete → {expected_csv}")
    return expected_csv


def is_cicflowmeter_available() -> bool:
    """Check if CICFlowMeter is installed and on PATH."""
    try:
        subprocess.run(
            [CICFLOWMETER_CMD, "--help"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
