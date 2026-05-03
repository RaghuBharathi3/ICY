"""
Panel 4 — Model Performance
3-experiment comparison: Baseline → Engineered → Ensemble
Skill: plotly, ml-pipeline-workflow, data-storytelling
"""
from __future__ import annotations
import plotly.graph_objects as go
import pandas as pd
import streamlit as st

_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0", family="Inter", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
)
EXP_COLORS = {
    "baseline":   "#6b7fa3",
    "engineered": "#3b82f6",
    "ensemble":   "#10b981",
}
EXP_LABELS = {
    "baseline":   "Exp 1 · Baseline",
    "engineered": "Exp 2 · Engineered",
    "ensemble":   "Exp 3 · Ensemble",
}


def _delta_badge(val: float, ref: float, higher_better: bool = True) -> str:
    diff = val - ref
    if abs(diff) < 0.0001:
        return ""
    arrow = "▲" if diff > 0 else "▼"
    color = "#10b981" if (diff > 0) == higher_better else "#ef4444"
    return f' <span style="color:{color}; font-size:0.8rem;">{arrow} {abs(diff):.4f}</span>'


def render(client) -> None:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.5rem;">
        <div>
            <h1 style="margin:0;font-size:1.6rem;color:#7dd3fc;">Model Performance</h1>
            <p style="margin:0;color:#4b5e7e;font-size:0.82rem;">
                3-experiment comparison — proves feature engineering improves detection
            </p>
        </div>
    </div>""", unsafe_allow_html=True)

    perf = client.get_performance()
    experiments = perf.get("experiments", {})
    best_model  = perf.get("best_model", "")

    if not experiments:
        st.warning("No experiment reports found. Train models first (`python run_training.py`).")
        _show_demo_note()
        return

    # ── KPI comparison strip ──────────────────────────────────────────────
    baseline_f1 = experiments.get("baseline", {}).get("f1", 0)
    cols = st.columns(len(experiments))
    for i, (name, metrics) in enumerate(experiments.items()):
        with cols[i]:
            f1   = metrics.get("f1", 0)
            roc  = metrics.get("roc_auc", 0)
            fpr  = metrics.get("fp_rate", 0)
            color = EXP_COLORS.get(name, "#6b7fa3")
            is_best = name == best_model
            border = f"2px solid {color}" if is_best else f"1px solid #1e3a5f"
            crown  = " [Best]" if is_best else ""
            st.markdown(f"""
            <div class="metric-card" style="border:{border};">
                <div style="font-size:0.7rem;color:{color};text-transform:uppercase;
                            letter-spacing:0.08em;font-weight:600;margin-bottom:0.5rem;">
                    {EXP_LABELS.get(name, name)}{crown}
                </div>
                <div class="metric-value" style="color:{color}; font-size:1.9rem;">{f1:.4f}</div>
                <div class="metric-label">F1 Score</div>
                <div style="margin-top:0.6rem; font-size:0.78rem; color:#6b7fa3;">
                    ROC-AUC: <b style="color:#e2e8f0;">{roc:.4f}</b><br>
                    FP Rate: <b style="color:#e2e8f0;">{fpr:.4f}</b>
                </div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

    # ── Grouped metric bar chart ──────────────────────────────────────────
    st.markdown("<div class='section-header'>Metric Comparison</div>", unsafe_allow_html=True)

    metrics_to_plot = ["f1", "roc_auc", "fp_rate"]
    metric_labels   = ["F1 Score", "ROC-AUC", "FP Rate (lower=better)"]

    fig = go.Figure()
    for name, metrics in experiments.items():
        fig.add_trace(go.Bar(
            name=EXP_LABELS.get(name, name),
            x=metric_labels,
            y=[metrics.get(m, 0) for m in metrics_to_plot],
            marker_color=EXP_COLORS.get(name, "#6b7fa3"),
            opacity=0.9,
            text=[f"{metrics.get(m,0):.4f}" for m in metrics_to_plot],
            textposition="outside",
        ))
    fig.update_layout(
        **_LAYOUT, barmode="group", height=350,
        yaxis=dict(title="Score", gridcolor="#1e2d4a", range=[0, 1.05]),
        xaxis=dict(color="#6b7fa3"),
        legend=dict(bgcolor="#111827", bordercolor="#1e3a5f"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Confusion matrices ────────────────────────────────────────────────
    st.markdown("<div class='section-header'>Confusion Matrices</div>", unsafe_allow_html=True)
    cm_cols = st.columns(len(experiments))

    for i, (name, metrics) in enumerate(experiments.items()):
        cm = metrics.get("confusion_matrix", {})
        if not cm:
            continue
        tn = cm.get("tn", 0); fp = cm.get("fp", 0)
        fn = cm.get("fn", 0); tp = cm.get("tp", 0)

        with cm_cols[i]:
            color = EXP_COLORS.get(name, "#6b7fa3")
            st.markdown(f"<div style='color:{color};font-weight:600;font-size:0.85rem;"
                        f"text-align:center;margin-bottom:0.5rem;'>"
                        f"{EXP_LABELS.get(name,name)}</div>", unsafe_allow_html=True)

            z     = [[tn, fp], [fn, tp]]
            x_lbl = ["Predicted NORMAL", "Predicted ATTACK"]
            y_lbl = ["Actual NORMAL", "Actual ATTACK"]
            annotations = [
                dict(x=j, y=i, text=f"<b>{z[i][j]:,}</b>", showarrow=False,
                     font=dict(color="#e2e8f0", size=14))
                for i in range(2) for j in range(2)
            ]
            fig_cm = go.Figure(go.Heatmap(
                z=z, x=x_lbl, y=y_lbl,
                colorscale=[[0,"#0a0e1a"],[0.5,"#1e3a5f"],[1, color]],
                showscale=False,
            ))
            fig_cm.update_layout(
                **_LAYOUT, height=220,
                annotations=annotations,
                xaxis=dict(color="#6b7fa3"),
                yaxis=dict(color="#6b7fa3", autorange="reversed"),
            )
            st.plotly_chart(fig_cm, use_container_width=True)

    # ── Delta table ───────────────────────────────────────────────────────
    st.markdown("<div class='section-header'>Improvement Delta — Baseline vs Best</div>", unsafe_allow_html=True)
    if "baseline" in experiments and best_model in experiments and best_model != "baseline":
        base  = experiments["baseline"]
        best  = experiments[best_model]
        delta_data = {
            "Metric":    ["F1 Score", "ROC-AUC", "FP Rate"],
            "Baseline":  [f"{base.get('f1',0):.4f}", f"{base.get('roc_auc',0):.4f}", f"{base.get('fp_rate',0):.4f}"],
            "Best Model": [f"{best.get('f1',0):.4f}", f"{best.get('roc_auc',0):.4f}", f"{best.get('fp_rate',0):.4f}"],
            "Δ":         [
                f"+{best.get('f1',0)-base.get('f1',0):.4f}",
                f"+{best.get('roc_auc',0)-base.get('roc_auc',0):.4f}",
                f"{best.get('fp_rate',0)-base.get('fp_rate',0):.4f}",
            ],
        }
        df = pd.DataFrame(delta_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Train all 3 experiments to see the improvement delta.")


def _show_demo_note():
    st.markdown("""
    <div style="background:#111827;border:1px dashed #1e3a5f;border-radius:10px;
                padding:1.5rem;margin-top:1rem;color:#6b7fa3;font-size:0.85rem;">
        <b style="color:#7dd3fc;">Demo mode:</b> Showing simulated performance data.<br><br>
        To train real models, place CICIDS2017 CSVs in <code>data/raw/</code> and run:<br>
        <code style="color:#10b981;">python run_training.py</code>
    </div>""", unsafe_allow_html=True)
