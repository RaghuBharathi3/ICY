"""
Panel 1 — Live Alert Feed
Real-time stream of ATTACK and SUSPICIOUS flows with auto-refresh.
Skill: data-storytelling, frontend-design
"""

from __future__ import annotations

import time
from datetime import datetime

import pandas as pd
import streamlit as st


def render(client) -> None:
    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:1.5rem;">
        <div style="width:12px; height:12px; border-radius:50%; background:#f87171; box-shadow:0 0 8px #f87171;"></div>
        <div>
            <h1 style="margin:0; font-size:1.6rem; color:#f87171;">Alert Feed</h1>
            <p style="margin:0; color:#4b5e7e; font-size:0.82rem;">Real-time threat detection stream</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Controls ─────────────────────────────────────────────────────────────
    col_a, col_b, col_c, col_d = st.columns([2, 2, 2, 1])
    with col_a:
        filter_type = st.selectbox(
            "Filter by decision",
            ["All Threats", "ATTACK only", "SUSPICIOUS only"],
            key="p1_filter",
        )
    with col_b:
        max_rows = st.slider("Max rows", 10, 100, 30, 5, key="p1_rows")
    with col_c:
        auto_refresh = st.toggle("Auto-refresh (10s)", value=False, key="p1_refresh")
    with col_d:
        st.markdown("<div style='margin-top:1.6rem;'>", unsafe_allow_html=True)
        if st.button("Refresh now", key="p1_manual_refresh"):
            st.cache_data.clear()
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Load data ─────────────────────────────────────────────────────────────
    decision_map = {
        "All Threats": None,
        "ATTACK only": "ATTACK",
        "SUSPICIOUS only": "SUSPICIOUS",
    }
    alerts = client.get_alerts(decision=decision_map[filter_type])
    alerts = alerts[:max_rows]

    # ── KPI strip ─────────────────────────────────────────────────────────────
    all_alerts = client.get_alerts()
    total_att  = sum(1 for f in all_alerts if f["decision"] == "ATTACK")
    total_sus  = sum(1 for f in all_alerts if f["decision"] == "SUSPICIOUS")
    avg_conf   = (
        round(sum(f.get("rf_confidence", 0) for f in all_alerts) / len(all_alerts), 3)
        if all_alerts else 0.0
    )

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:#ef4444;">{total_att}</div>
            <div class="metric-label">Total Attacks</div>
        </div>""", unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:#f59e0b;">{total_sus}</div>
            <div class="metric-label">Suspicious</div>
        </div>""", unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:#7dd3fc;">{len(all_alerts)}</div>
            <div class="metric-label">Total Threats</div>
        </div>""", unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:#a78bfa;">{avg_conf:.3f}</div>
            <div class="metric-label">Avg RF Confidence</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

    # ── Alert table ───────────────────────────────────────────────────────────
    if not alerts:
        st.markdown("""
        <div style="text-align:center; padding:3rem; color:#4b5e7e; border:1px dashed #1e3a5f; border-radius:12px;">
            <div style="font-size:3rem; margin-bottom:1rem;">--</div>
            <div style="font-size:1.1rem; font-weight:500;">No threats detected</div>
            <div style="font-size:0.8rem; margin-top:0.5rem;">All monitored flows classified as NORMAL</div>
        </div>
        """, unsafe_allow_html=True)
        return

    rows = []
    for f in alerts:
        decision = f.get("decision", "?")
        conf = f.get("rf_confidence", 0)
        ts = f.get("timestamp", "")
        # Parse timestamp to human-readable
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_fmt = dt.strftime("%H:%M:%S")
        except Exception:
            ts_fmt = ts[:19] if ts else "—"

        top_feat = ""
        tf = f.get("top_features", [])
        if tf:
            top_feat = tf[0].get("feature", "").replace("_", " ")

        rows.append({
            "Decision":   decision,
            "Flow ID":    f.get("flow_id", "—"),
            "Source IP":  f.get("src_ip", "—"),
            "Dest IP":    f.get("dst_ip", "—"),
            "Confidence": f"{conf:.3f}",
            "Top Feature": top_feat,
            "Time":       ts_fmt,
            "IF Anomaly": "Yes" if f.get("if_anomaly") else "--",
        })

    df = pd.DataFrame(rows)

    # Color-code Decision column
    def color_decision(val):
        if val == "ATTACK":
            return "color: #ef4444; font-weight: 600;"
        elif val == "SUSPICIOUS":
            return "color: #f59e0b; font-weight: 600;"
        return "color: #10b981;"

    styled = (
        df.style
        .map(color_decision, subset=["Decision"])
        .set_properties(**{
            "background-color": "#111827",
            "color": "#e2e8f0",
            "border-color": "#1e3a5f",
        })
        .set_table_styles([{
            "selector": "th",
            "props": [
                ("background-color", "#0f1629"),
                ("color", "#7dd3fc"),
                ("font-size", "0.78rem"),
                ("text-transform", "uppercase"),
                ("letter-spacing", "0.06em"),
                ("border-bottom", "2px solid #1e3a5f"),
            ],
        }])
    )

    st.dataframe(styled, use_container_width=True, height=420)

    # ── Alert detail expander ─────────────────────────────────────────────────
    st.markdown("<div class='section-header' style='margin-top:1.5rem;'>Quick Inspect</div>", unsafe_allow_html=True)
    flow_ids = [f["flow_id"] for f in alerts]
    selected_id = st.selectbox("Select a flow to inspect:", flow_ids, key="p1_select")

    if selected_id:
        detail = next((f for f in alerts if f["flow_id"] == selected_id), None)
        if detail:
            col_l, col_r = st.columns([1, 1])
            with col_l:
                st.markdown("**Flow details:**")
                st.json({
                    "flow_id":      detail.get("flow_id"),
                    "decision":     detail.get("decision"),
                    "rf_confidence":detail.get("rf_confidence"),
                    "if_anomaly":   detail.get("if_anomaly"),
                    "src_ip":       detail.get("src_ip"),
                    "dst_ip":       detail.get("dst_ip"),
                })
            with col_r:
                st.markdown("**SHAP top features:**")
                tf = detail.get("top_features", [])
                if tf:
                    import plotly.graph_objects as go
                    features = [t["feature"].replace("_", " ") for t in tf]
                    values   = [t["shap_value"] for t in tf]
                    colors   = ["#ef4444" if v > 0 else "#10b981" for v in values]

                    fig = go.Figure(go.Bar(
                        x=values,
                        y=features,
                        orientation="h",
                        marker_color=colors,
                        marker_line_width=0,
                    ))
                    fig.update_layout(
                        paper_bgcolor="#111827",
                        plot_bgcolor="#111827",
                        font=dict(color="#e2e8f0", size=11),
                        xaxis=dict(
                            title="SHAP value",
                            color="#6b7fa3",
                            gridcolor="#1e3a5f",
                        ),
                        yaxis=dict(color="#e2e8f0", automargin=True),
                        margin=dict(l=10, r=10, t=10, b=10),
                        height=200,
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No SHAP data for this flow.")

    # ── Auto-refresh ──────────────────────────────────────────────────────────
    if auto_refresh:
        time.sleep(10)
        st.rerun()
