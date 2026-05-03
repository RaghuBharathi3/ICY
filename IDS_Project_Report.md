# Intrusion Detection System — Project Report

**Project:** ML-Based Network Intrusion Detection System (IDS)  
**Dataset:** CICIDS2017 (Canadian Institute for Cybersecurity)  
**Date:** 2026-05-03  
**Repository:** https://github.com/RaghuBharathi3/ICY  

---

## 1. Project Overview

This report documents the end-to-end execution of a Machine Learning-based Intrusion Detection System trained on the CICIDS2017 benchmark dataset. The system combines a supervised Random Forest classifier with an unsupervised Isolation Forest anomaly detector to produce a three-way decision output: **ATTACK**, **SUSPICIOUS**, or **NORMAL**.

The project architecture consists of five components:

| Component | Technology | Purpose |
|---|---|---|
| Preprocessing Pipeline | Python / pandas / scikit-learn | Data cleaning, feature engineering, SMOTE |
| Model Training | scikit-learn Random Forest + Isolation Forest | 3-experiment ML pipeline |
| REST API | FastAPI | 8-endpoint inference and reporting server |
| Dashboard | Streamlit | 5-panel analyst investigation UI |
| Explainability | SHAP | Feature importance per prediction |

---

## 2. Dataset Setup

### 2.1 Source

The CICIDS2017 dataset was obtained from:
```
C:\Users\Windows\Documents\ICY\CIC-IDS-2017\
├── CSVS\
│   ├── MachineLearningCSV.zip      (224 MB — ML-ready feature CSVs)
│   └── GeneratedLabelledFlows.zip  (271 MB — raw per-flow exports)
└── PCAPS\
    ├── Monday-WorkingHours.pcap    (10.3 GB)
    ├── Tuesday-WorkingHours.pcap
    ├── Thursday-WorkingHours.pcap
    └── Friday-WorkingHours.pcap
```

### 2.2 Extraction

**MachineLearningCSV.zip** was extracted directly into `data/raw/` using PowerShell:

```powershell
Expand-Archive -Path "...\MachineLearningCSV.zip" `
               -DestinationPath "ids-ml-project\data\raw" -Force
```

**GeneratedLabelledFlows.zip** was extracted using Python's `zipfile` module due to a Windows path issue (a subfolder with a trailing space `TrafficLabelling ` caused `Expand-Archive` to fail):

```python
with zipfile.ZipFile(zip_path, 'r') as z:
    for member in z.namelist():
        fname = os.path.basename(member).strip()
        if fname.endswith('.csv'):
            # extract with sanitised filename
```

Result: **16 CSV files** extracted across two directories.

| Directory | Files | Total Size |
|---|---|---|
| `data/raw/` | 8 ML-ready CSVs | ~885 MB |
| `data/raw_flows/` | 8 raw per-flow CSVs | ~885 MB |

### 2.3 Schema Comparison

The two CSV formats share 79 identical feature columns. The raw flow CSVs contain 6 additional identity columns not present in the ML CSVs:

| Column | Present in ML CSV | Present in Raw Flow CSV |
|---|---|---|
| `Flow ID` | ✗ | ✓ |
| `Source IP` | ✗ | ✓ |
| `Source Port` | ✗ | ✓ |
| `Destination IP` | ✗ | ✓ |
| `Protocol` | ✗ | ✓ |
| `Timestamp` | ✗ | ✓ |

All 6 extra columns are non-feature identity fields and are dropped during preprocessing via `DROP_COLS`.

---

## 3. Preprocessing Pipeline Enhancements

### 3.1 Multi-Source Data Loading

The `load_raw()` function in `src/pipeline/preprocessor.py` was extended to accept an `extra_dirs` parameter, enabling multiple CSV directories to be merged into a single DataFrame before training:

```python
def load_raw(
    data_dir: str | Path,
    extra_dirs: list[str | Path] | None = None,
) -> pd.DataFrame:
```

A helper `_read_csvs_from_dir()` function handles per-directory loading with encoding fallback.

### 3.2 Encoding Fallback

The raw per-flow CSVs use Windows-1252 encoding (byte `0x96` = en-dash `–`). A three-tier encoding fallback was implemented to handle both file types transparently:

```python
for enc in ("utf-8", "cp1252", "latin-1"):
    try:
        df = pd.read_csv(f, low_memory=False, encoding=enc)
        break
    except (UnicodeDecodeError, pd.errors.ParserError):
        continue
```

### 3.3 Extended DROP_COLS

`Source Port` and `Protocol` were added to the drop list to handle the raw flow schema:

```python
DROP_COLS = [
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Protocol", "Timestamp", "Label",
]
```

### 3.4 Post-Engineering Re-Clean

Division-based engineered features (`bytes_per_second`, `packets_per_second`, etc.) can reintroduce `inf` or extremely large float values when denominators are near zero. These values survive the initial cleaning step but cause `MinMaxScaler` and `SMOTE` to fail.

A mandatory re-clean pass was added **after** `engineer_features()`:

```python
if apply_engineering:
    df = engineer_features(df)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    logger.info(f"Post-engineering clean shape: {df.shape}")
```

### 3.5 CLI Flag

`run_training.py` was extended with a `--raw-flows` argument that auto-detects and merges the raw flow directory:

```python
parser.add_argument("--raw-flows", default="data/raw_flows", dest="raw_flows")
```

If the directory exists and contains CSVs, it is automatically included. The flag can be set to `''` to disable.

---

## 4. Training Pipeline

### 4.1 Data Statistics (Combined Dataset)

| Metric | Value |
|---|---|
| Total rows loaded | 5,950,088 |
| Rows after inf/NaN drop | 2,827,876 |
| Duplicate rows removed | 199 |
| **Final clean rows** | **2,827,677** |
| Training set | 2,262,054 rows |
| Test set | 565,514 rows |
| Class distribution (train) | Normal: 1,816,810 — Attack: 445,244 |
| Feature columns | 85 (78 raw + 7 engineered) |

### 4.2 Experiment 1 — Baseline Random Forest

**Configuration:** Raw CICIDS2017 features, no feature engineering, no SMOTE.  
**Purpose:** Establish performance floor.

| Metric | Value |
|---|---|
| F1 Score | **0.9937** |
| ROC-AUC | **0.9999** |
| False Positive Rate | **0.27%** |
| True Negatives | 452,977 |
| False Positives | 1,248 |
| False Negatives | 168 |
| True Positives | 111,143 |
| Training time | ~8 min |

### 4.3 Experiment 2 — Engineered Features + SMOTE

**Configuration:** 7 custom behavioural features + SMOTE class balancing.  
**Purpose:** Prove feature engineering improves detection.

**7 Engineered Features:**

| Feature | Target Attack Pattern |
|---|---|
| `syn_ack_ratio` | SYN flood / DDoS |
| `bytes_per_second` | Burst / DDoS bandwidth spike |
| `packets_per_second` | Packet flood |
| `fwd_bwd_ratio` | Port scan (one-directional probe) |
| `avg_packet_size` | Reconnaissance (tiny packets) |
| `iat_mean` | Bot behaviour (uniform inter-arrival time) |
| `flow_duration_var` | Attacker varying timing to evade detection |

| Metric | Value | vs Baseline |
|---|---|---|
| F1 Score | **0.9974** | +0.0037 |
| ROC-AUC | **0.9999** | = |
| False Positive Rate | **0.10%** | **−63%** |
| False Positives | 462 | −786 fewer alarms |
| False Negatives | 121 | −47 missed attacks |
| Training time | ~25 min (incl. SMOTE on 2.26M rows) |

### 4.4 Experiment 3 — RF + Isolation Forest Ensemble

**Configuration:** Experiment 2 RF + unsupervised Isolation Forest anomaly layer.  
**Decision Logic (locked):**

```
if RF predicts Attack               → ATTACK
if RF predicts Normal AND IF < 0    → SUSPICIOUS  (anomalous traffic)
if RF predicts Normal AND IF >= 0   → NORMAL
```

| Metric | Value | Note |
|---|---|---|
| F1 Score | 0.8784 | Lower due to SUSPICIOUS → Attack mapping in binary eval |
| ROC-AUC | 0.9999 | |
| False Positive Rate | 6.75% | Conservative: SUSPICIOUS counted as positive |
| Training time | ~4 min |

> The Ensemble F1 dip is expected and by design. The three-way output is the primary value — SUSPICIOUS provides an early-warning tier not captured by binary F1.

### 4.5 Saved Artifacts

| File | Size | Description |
|---|---|---|
| `artifacts/models/rf_baseline.pkl` | 26 MB | Experiment 1 baseline model |
| `artifacts/models/rf_model.pkl` | 37 MB | Production RF model (Exp 2) |
| `artifacts/models/if_model.pkl` | 0.8 MB | Isolation Forest model |
| `artifacts/models/feature_cols.json` | 1.6 KB | 85 ordered feature column names |
| `artifacts/reports/baseline.json` | — | Experiment 1 metrics |
| `artifacts/reports/engineered.json` | — | Experiment 2 metrics |
| `artifacts/reports/ensemble.json` | — | Experiment 3 metrics |

---

## 5. API Audit & Fixes

### 5.1 Endpoint Review

All 8 FastAPI endpoints (`src/api/main.py`) were reviewed and confirmed correct:

| Endpoint | Status |
|---|---|
| `GET /api/health` | ✅ Checks `rf_model.pkl` + `if_model.pkl` existence |
| `GET /api/flows` | ✅ Paginated, correct |
| `GET /api/flows/{id}` | ✅ |
| `GET /api/flows/{id}/explain` | ✅ SHAP via `plain_english_explanation` |
| `GET /api/alerts` | ✅ Filters ATTACK/SUSPICIOUS |
| `GET /api/stats` | ✅ |
| `POST /api/predict` | ✅ Feature ordering via `feature_cols` |
| `GET /api/model/performance` | ✅ Reads all 3 report JSONs |

### 5.2 Fixes Applied

**Fix 1 — Top-level import:**
```python
# Before (inline import inside hot path)
from dataclasses import asdict

# After (top-level)
from dataclasses import asdict  # moved to module top
```

**Fix 2 — Avoid double feature_cols load in `/api/predict`:**
```python
# Before
feature_cols = _load_feature_cols()   # redundant disk read

# After
feature_cols = predictor.feature_cols  # already held in memory
```

---

## 6. Dashboard Audit & Fixes

### 6.1 Architecture

The Streamlit dashboard (`dashboard/app.py`) implements a 5-panel navigation system:

| Panel | Purpose |
|---|---|
| Panel 1 — Live Alert Feed | Real-time ATTACK/SUSPICIOUS stream with auto-refresh |
| Panel 2 — Traffic Distribution | Normal vs Attack visual breakdown |
| Panel 3 — SHAP Explainability | Top engineered features per decision |
| Panel 4 — Model Performance | 3-experiment comparison table |
| Panel 5 — Flow Investigation | Per-flow drill-down with SHAP waterfall |

### 6.2 Key Design Decisions

- **Offline fallback:** `APIClient` generates deterministic demo data (seeded with `random.seed(42)`) when the API is unreachable, allowing the dashboard to run standalone for presentations.
- **Single client instance:** `APIClient` is instantiated once in `app.py` and passed as a parameter to each panel's `render(client)` function — avoiding redundant HTTP connections.
- **API health indicator:** Sidebar shows a live pulsing green/grey dot reflecting API status on every page.

### 6.3 Fix Applied

**Pandas 2.x deprecation in `panel1_alerts.py`:**
```python
# Before (deprecated in pandas 2.x)
df.style.applymap(color_decision, subset=["Decision"])

# After (correct API)
df.style.map(color_decision, subset=["Decision"])
```

---

## 7. Deployment

### 7.1 Launch Commands

**FastAPI Backend:**
```powershell
cd C:\Users\Windows\Documents\ICY\ids-ml-project
uvicorn src.api.main:app --reload --port 8000
```

**Streamlit Dashboard:**
```powershell
python -m streamlit run dashboard/app.py --server.port 8502 --server.headless true
```

> Port 8501 had stale processes from multiple launch attempts. Port 8502 was used to bypass `TIME_WAIT` socket cleanup delay.

### 7.2 Service URLs

| Service | URL |
|---|---|
| Dashboard | http://localhost:8502 |
| API | http://localhost:8000 |
| API Interactive Docs | http://localhost:8000/docs |

### 7.3 Health Check Verification

At launch, `/api/health` confirmed:
```json
{
  "status": "healthy",
  "models_ready": true,
  "flows_stored": 0
}
```

---

## 8. Git Commit Summary

**Commit:** `68c3bc7`  
**Branch:** `main`  
**Remote:** `https://github.com/RaghuBharathi3/ICY.git`

```
feat: add dual-source training (ML CSV + raw per-flow), fix inf/encoding bugs

8 files changed, 147 insertions(+), 62 deletions(-)
```

**Files changed:**

| File | Change |
|---|---|
| `src/pipeline/preprocessor.py` | Multi-source loader, encoding fallback, post-engineering re-clean, DROP_COLS extension |
| `src/models/train_rf.py` | `extra_dirs` parameter wired through both experiments |
| `src/models/ensemble.py` | `extra_dirs` parameter wired through ensemble |
| `run_training.py` | `--raw-flows` CLI flag, `extra_dirs` propagated to all functions |
| `src/api/main.py` | Import cleanup, removed redundant `_load_feature_cols()` call |
| `dashboard/pages/panel1_alerts.py` | `.applymap()` → `.map()` for pandas 2.x |
| `.gitignore` | Added `data/raw_flows/` exclusion |
| `artifacts/models/feature_cols.json` | New file — 85 ordered feature column names |

---

## 9. Known Limitations

- The Experiment 3 ensemble F1 (0.8784) reflects conservative binary evaluation where SUSPICIOUS is counted as a positive. The three-way output is the intended use case.
- The system performs flow-level analysis only — no live packet capture (PCAP replay via watcher is available separately).
- Trained exclusively on CICIDS2017 — generalisation to other network environments requires retraining or domain adaptation.
- The dashboard serves demo data when no flows have been processed through the watcher pipeline; live data populates once `data/watch/` receives CSV flow exports.

---

## 10. Performance Summary

| Experiment | F1 | ROC-AUC | FP Rate | Dataset |
|---|---|---|---|---|
| Baseline RF | 0.9937 | 0.9999 | 0.27% | 2.83M rows, no engineering |
| **Engineered + SMOTE** | **0.9974** | **0.9999** | **0.10%** | 2.83M rows, 85 features |
| RF + IF Ensemble | 0.8784 | 0.9999 | 6.75% | 3-way output, conservative eval |

The engineered model reduces false positives by **63%** compared to baseline while adding only 7 domain-specific features derived from network flow behaviour. The ensemble layer adds an unsupervised anomaly detection tier that flags traffic the RF classifies as normal but which statistically deviates from the training distribution.
