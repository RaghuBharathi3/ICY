# IDS-ML — Intrusion Detection System using Machine Learning

> Binary classification of network flows: **ATTACK vs NORMAL**  
> Dataset: **CICIDS2017** | Models: **Random Forest + Isolation Forest** | Focus: **DDoS + Probing**

---

## Project Structure

```
ids-ml-project/
├── data/
│   ├── raw/          <- place CICIDS2017 CSV files here
│   ├── processed/    <- auto-generated cleaned data
│   └── watch/        <- drop CSVs here for live inference
├── src/
│   ├── pipeline/     <- preprocessor, predictor, watcher, flow_extractor
│   ├── models/       <- train_rf, train_if, ensemble
│   ├── explainability/   <- shap_explainer
│   └── api/          <- FastAPI (8 endpoints)
├── dashboard/
│   ├── app.py        <- Streamlit entry point
│   ├── components/   <- api_client
│   └── pages/        <- panel1-5
├── tests/            <- 25 passing tests
├── artifacts/        <- models, reports, plots (auto-generated)
├── run_training.py   <- master training orchestrator
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies
```powershell
pip install -r requirements.txt
```

### 2. Place CICIDS2017 data
Download from: https://www.unb.ca/cic/datasets/ids-2017.html  
Place CSV files in: `data/raw/`

### 3. Train models (all 3 experiments)
```powershell
python run_training.py
```

### 4. Start the API
```powershell
uvicorn src.api.main:app --reload --port 8000
```

### 5. Start the dashboard
```powershell
streamlit run dashboard/app.py --server.port 8501
```
Open: **http://localhost:8501**

---

## Run Tests
```powershell
python -m pytest tests/ -v
```
**25/25 tests passing**

---

## 3 Experiments

| Experiment | Features | SMOTE | Purpose |
|-----------|---------|-------|---------|
| Exp 1: Baseline | Raw CICIDS2017 | No | Performance floor |
| Exp 2: Engineered | 7 custom features | Yes | Prove engineering value |
| Exp 3: Ensemble | Engineered + IF | No | Best detection accuracy |

---

## 7 Engineered Features

| Feature | Attack Signal |
|---------|--------------|
| `syn_ack_ratio` | SYN Flood (DDoS) |
| `bytes_per_second` | Burst/DDoS traffic |
| `packets_per_second` | Packet flood |
| `fwd_bwd_ratio` | Port scan (asymmetric) |
| `avg_packet_size` | Reconnaissance |
| `iat_mean` | Bot behavior |
| `flow_duration_var` | Recon timing variation |

---

## Dashboard Panels

| Panel | What it shows |
|-------|--------------|
| Panel 1 | Live alert feed — real-time ATTACK/SUSPICIOUS flows |
| Panel 2 | Traffic distribution — donut, time-series, IP heatbar |
| Panel 3 | SHAP explainability — why was this flow flagged? |
| Panel 4 | Model performance — 3-experiment F1/ROC comparison |
| Panel 5 | Flow investigation — search, drill-down, manual predict |

---

## API Endpoints (FastAPI)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | System status + model readiness |
| GET | `/api/flows` | Paginated flow list |
| GET | `/api/flows/{id}` | Single flow detail |
| GET | `/api/flows/{id}/explain` | SHAP explanation |
| GET | `/api/alerts` | ATTACK + SUSPICIOUS flows |
| GET | `/api/stats` | Summary counts |
| POST | `/api/predict` | Manual prediction |
| GET | `/api/model/performance` | 3-experiment comparison |

Docs: **http://localhost:8000/docs**

---

## Limitations

- Research prototype — not a production IDS
- No live packet capture (flow-level analysis only)
- Binary classification only (Attack vs Normal)
- Tested on CICIDS2017 — may not generalize to all environments

See `LIMITATIONS.md` for full details.
