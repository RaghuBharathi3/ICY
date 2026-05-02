# DESIGN.md — System Architecture

## IDS-ML: Intrusion Detection System using Machine Learning

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA INGESTION                              │
│                                                                     │
│   CICIDS2017 CSVs  ──►  data/raw/          (offline training)       │
│   New CSV file     ──►  data/watch/        (semi-real-time)         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       PREPROCESSING LAYER                           │
│                                                                     │
│   1. Replace inf → NaN, drop NaN rows                               │
│   2. Drop columns >50% missing                                      │
│   3. Drop duplicates                                                │
│   4. Drop non-feature columns (IP, Timestamp, etc.)                 │
│   5. MinMaxScaler → normalize all features                          │
│   6. SMOTE → balance classes (training only)                        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FEATURE ENGINEERING LAYER                        │
│                                                                     │
│   + syn_ack_ratio      (DDoS: SYN flood pattern)                    │
│   + bytes_per_second   (DDoS: bandwidth burst)                      │
│   + packets_per_second (Packet flood indicator)                     │
│   + fwd_bwd_ratio      (Probe: one-directional traffic)             │
│   + avg_packet_size    (Scan: tiny packets)                         │
│   + iat_mean           (Bot: uniform inter-arrival)                 │
│   + flow_duration_var  (Recon: timing variance per IP)              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ML MODEL LAYER                              │
│                                                                     │
│   ┌────────────────────────┐   ┌────────────────────────────────┐   │
│   │  Random Forest (RF)    │   │  Isolation Forest (IF)         │   │
│   │  Supervised            │   │  Unsupervised anomaly          │   │
│   │  class_weight=balanced │   │  contamination=0.1             │   │
│   └──────────┬─────────────┘   └───────────────┬────────────────┘   │
│              │                                 │                    │
│              └──────────────┬──────────────────┘                    │
│                             ▼                                       │
│              ┌──────────────────────────────┐                       │
│              │  ENSEMBLE DECISION LOGIC     │                       │
│              │                              │                       │
│              │  RF=Attack      → ATTACK     │                       │
│              │  RF=Normal      → SUSPICIOUS │ (IF anomaly < 0)      │
│              │  RF=Normal      → NORMAL     │ (IF anomaly >= 0)     │
│              └──────────────┬───────────────┘                       │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EXPLAINABILITY LAYER                             │
│                                                                     │
│   SHAP TreeExplainer → top-5 feature contributions per prediction   │
│   Plain English summary → "Flagged because syn_ack_ratio is 3x high"│
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        API LAYER (FastAPI)                          │
│                                                                     │
│   GET  /api/health                  GET  /api/alerts                │
│   GET  /api/flows (paginated)       GET  /api/stats                 │
│   GET  /api/flows/{id}              POST /api/predict               │
│   GET  /api/flows/{id}/explain      GET  /api/model/performance     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   INVESTIGATIVE DASHBOARD (Next.js)                 │
│                                                                     │
│   Panel 1: Live Threat Feed (auto-refresh 10s)                      │
│   Panel 2: Flow Inspector   (click alert → full features)           │
│   Panel 3: SHAP Explanation (click "Explain" → top-5 chart)         │
│   Panel 4: IP Timeline      (click "Trace IP" → 15-min history)     │
│   Panel 5: Model Performance (experiment comparison + ROC curves)   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Why Each Component Exists

| Component | Why It Exists |
|-----------|--------------|
| Watch Folder | Enables semi-real-time detection without live packet capture infrastructure |
| CICIDS2017 | Only labeled, realistic, flow-based public dataset for Probing + DDoS |
| MinMaxScaler | RF is not scale-sensitive, but IF works better with normalized data |
| SMOTE | Training set has ~80% BENIGN — SMOTE prevents model learning only "normal" |
| SHAP | Makes every prediction defensible — critical for analyst trust |
| FastAPI | Async, fast, auto-generates OpenAPI docs, typed via Pydantic |
| Next.js | Investigative dashboard needs SSR + real-time data fetching patterns |

## Watch Folder vs Live Capture

**Watch Folder (chosen):**
- Works without network tap hardware
- Accepts pre-converted CICIDS2017-format CSVs
- Latency: 5–30 seconds
- Suitable for a research prototype

**Live Capture (not chosen):**
- Requires root/admin access + network interface
- Needs CICFlowMeter running in real-time (Java dependency)
- Platform-dependent, hard to demo
- Out of scope for this prototype

---

## Three-Experiment Proof Structure

| Experiment | Features | SMOTE | Model | Purpose |
|-----------|---------|-------|-------|---------|
| 1 Baseline | Raw only | No | RF | Establish floor |
| 2 Engineered | Raw + 7 custom | Yes | RF | Prove features add value |
| 3 Ensemble | Raw + 7 custom | No | RF + IF | Prove dual-layer detection |

**The improvement from Exp 1 → Exp 2 is the core contribution of this project.**
