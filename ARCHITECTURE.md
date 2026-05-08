# IDS-ML System Architecture

This document illustrates the high-level system architecture and data flow for the Intrusion Detection System (IDS-ML) project.

## Architecture Diagram

```mermaid
graph TD
    %% Define Styles
    classDef storage fill:#1e2d4a,stroke:#7dd3fc,stroke-width:2px,color:#e2e8f0;
    classDef process fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#e2e8f0;
    classDef model fill:#312e81,stroke:#a78bfa,stroke-width:2px,color:#e2e8f0;
    classDef api fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#e2e8f0;
    classDef ui fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#e2e8f0;

    subgraph Data Ingestion
        A[Raw PCAP / CSV Files]:::storage -->|Dropped into| B[(data/watch/ Directory)]:::storage
    end

    subgraph Core Processing Pipeline
        B --> C{watcher.py Daemon}:::process
        C -->|Standardize, Impute, Scale| D[Preprocessed Data Vector]:::process
    end

    subgraph Inference & Ensemble Engine
        D -->|Feature Vector| E(Random Forest Classifier):::model
        D -->|Feature Vector| F(Isolation Forest Anomaly Detector):::model
        
        E -->|Confidence > 0.85| G{Decision Engine}:::process
        F -->|Anomaly Detected| G
        
        G -->|Classified as ATTACK/SUSPICIOUS| H(SHAP Explainer):::model
        G -->|Classified as NORMAL| I[(live_results.json)]:::storage
        H -->|Extract Top 5 Features| I
    end

    subgraph API & Presentation Layer
        I --> J[FastAPI Backend]:::api
        J -->|GET /api/flows| K[Streamlit Dashboard]:::ui
        J -->|GET /api/stats| K
        J -->|GET /api/alerts| K
        
        K -->|Panel 1: Alert Feed| L((Analyst))
        K -->|Panel 2: Traffic Overview| L
        K -->|Panel 3: SHAP Explainability| L
    end
```

### Components
1. **Data Ingestion:** Raw network flow data is deposited into a watch folder.
2. **Preprocessing:** A daemon monitors the folder and processes new data to prepare it for inference.
3. **Inference Engine:** An ensemble of a supervised Random Forest and an unsupervised Isolation Forest classify the network flows.
4. **Explainability:** SHAP is used to explain the reasoning behind flagged malicious flows.
5. **API & UI:** The results are stored locally and served via FastAPI to a 5-panel Streamlit Dashboard for analysts.
