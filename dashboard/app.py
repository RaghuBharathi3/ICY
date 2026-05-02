"""
dashboard/app.py
────────────────────────────────────────────────────────────────────────────────
IDS Investigative Dashboard — Streamlit Multi-Page App
Skill references: frontend-design, data-storytelling, matplotlib, plotly, seaborn

5 Panels (as defined in master prompt):
  Panel 1 — Live Alert Feed        (real-time attack stream)
  Panel 2 — Traffic Distribution   (Normal vs Attack visual breakdown)
  Panel 3 — SHAP Feature Importance (top engineered features)
  Panel 4 — Model Performance      (3-experiment comparison)
  Panel 5 — Flow Investigation     (drill-down per flow_id)

Run:  streamlit run dashboard/app.py --server.port 8501
API:  http://localhost:8000  (FastAPI must be running)
"""

import streamlit as st

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IDS · Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": "ML-based IDS | Random Forest + Isolation Forest | CICIDS2017",
    },
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Fonts & Base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Dark background ── */
.stApp {
    background: #0a0e1a;
    color: #e2e8f0;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0f1629;
    border-right: 1px solid #1e2d4a;
}

/* ── Metric cards ── */
.metric-card {
    background: linear-gradient(135deg, #111827 0%, #1a2332 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0,100,255,0.15);
}
.metric-value {
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.25rem;
}
.metric-label {
    font-size: 0.78rem;
    font-weight: 500;
    color: #6b7fa3;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

/* ── Alert badge ── */
.badge-attack  { background:#ef4444; color:#fff; padding:2px 10px; border-radius:99px; font-size:0.72rem; font-weight:600; }
.badge-suspicious { background:#f59e0b; color:#000; padding:2px 10px; border-radius:99px; font-size:0.72rem; font-weight:600; }
.badge-normal  { background:#10b981; color:#fff; padding:2px 10px; border-radius:99px; font-size:0.72rem; font-weight:600; }

/* ── Section headers ── */
.section-header {
    font-size: 1.1rem;
    font-weight: 600;
    color: #7dd3fc;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    letter-spacing: 0.02em;
}

/* ── Alert row ── */
.alert-row {
    background: #111827;
    border-left: 3px solid #ef4444;
    border-radius: 6px;
    padding: 0.6rem 0.9rem;
    margin-bottom: 0.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
}
.alert-row.suspicious {
    border-left-color: #f59e0b;
}

/* ── Status dot ── */
.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 1.5s infinite;
}
.status-dot.online  { background:#10b981; }
.status-dot.offline { background:#6b7280; animation:none; }

@keyframes pulse {
    0%   { opacity:1; transform:scale(1); }
    50%  { opacity:0.5; transform:scale(1.3); }
    100% { opacity:1; transform:scale(1); }
}

/* ── Streamlit element overrides ── */
[data-testid="metric-container"] {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem;
}
.stDataFrame { background: #111827; }
div[data-testid="stMarkdownContainer"] h1 { color: #7dd3fc; }
div[data-testid="stMarkdownContainer"] h2 { color: #93c5fd; }
div[data-testid="stMarkdownContainer"] h3 { color: #bfdbfe; }
</style>
""", unsafe_allow_html=True)

# ── Navigation ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 1.5rem 0;">
        <div style="font-size:2.5rem; margin-bottom:0.3rem;">🛡️</div>
        <div style="font-size:1.1rem; font-weight:700; color:#7dd3fc; letter-spacing:0.05em;">IDS Dashboard</div>
        <div style="font-size:0.72rem; color:#4b5e7e; margin-top:0.2rem;">ML Intrusion Detection System</div>
    </div>
    """, unsafe_allow_html=True)

    panel = st.radio(
        "Navigation",
        options=[
            "🚨  Panel 1 — Live Alerts",
            "📊  Panel 2 — Traffic Overview",
            "🔍  Panel 3 — SHAP Explainability",
            "📈  Panel 4 — Model Performance",
            "🔎  Panel 5 — Flow Investigation",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.72rem; color:#4b5e7e; line-height:1.7;">
    <b style="color:#6b7fa3;">Dataset:</b> CICIDS2017<br>
    <b style="color:#6b7fa3;">Models:</b> RF + Isolation Forest<br>
    <b style="color:#6b7fa3;">Focus:</b> DDoS + Probing<br>
    <b style="color:#6b7fa3;">Explainability:</b> SHAP
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    # API health check
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    from dashboard.components.api_client import APIClient
    client = APIClient()
    health = client.get_health()

    is_online = health.get("data", {}).get("models_ready", False)
    models_ready = health.get("data", {}).get("models_ready", False)

    dot_class = "online" if is_online else "offline"
    status_text = "API Online" if is_online else "API Offline"
    model_status = "✅ Models ready" if models_ready else "⚠️ Train models first"

    st.markdown(f"""
    <div style="font-size:0.78rem;">
        <span class="status-dot {dot_class}"></span>
        <span style="color:{'#10b981' if is_online else '#6b7280'};">{status_text}</span><br>
        <span style="color:#4b5e7e; margin-left:14px;">{model_status}</span>
    </div>
    """, unsafe_allow_html=True)

# ── Panel routing ──────────────────────────────────────────────────────────────
if "Panel 1" in panel:
    from dashboard.pages import panel1_alerts
    panel1_alerts.render(client)

elif "Panel 2" in panel:
    from dashboard.pages import panel2_traffic
    panel2_traffic.render(client)

elif "Panel 3" in panel:
    from dashboard.pages import panel3_shap
    panel3_shap.render(client)

elif "Panel 4" in panel:
    from dashboard.pages import panel4_performance
    panel4_performance.render(client)

elif "Panel 5" in panel:
    from dashboard.pages import panel5_investigate
    panel5_investigate.render(client)
