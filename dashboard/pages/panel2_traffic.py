"""
Panel 2 — Traffic Distribution
Visual breakdown of Normal vs Attack traffic.
Skill: plotly, data-storytelling
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import streamlit as st

_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0", family="Inter", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
)
COLORS = {"ATTACK": "#ef4444", "SUSPICIOUS": "#f59e0b", "NORMAL": "#10b981"}


def render(client) -> None:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.5rem;">
        <span style="font-size:2rem;">📊</span>
        <div>
            <h1 style="margin:0;font-size:1.6rem;color:#7dd3fc;">Traffic Distribution</h1>
            <p style="margin:0;color:#4b5e7e;font-size:0.82rem;">Network flow classification breakdown</p>
        </div>
    </div>""", unsafe_allow_html=True)

    flows = client.get_flows()
    stats = client.get_stats()
    if not flows:
        st.warning("No flow data. Run the pipeline or check the API.")
        return

    # ── KPI strip ─────────────────────────────────────────────────────────
    m1, m2, m3, m4, m5 = st.columns(5)
    kpis = [
        (m1, str(stats.get("total_flows", 0)),            "Total Flows",  "#7dd3fc"),
        (m2, str(stats.get("normal", 0)),                 "Normal",       "#10b981"),
        (m3, str(stats.get("attacks", 0)),                "Attacks",      "#ef4444"),
        (m4, str(stats.get("suspicious", 0)),             "Suspicious",   "#f59e0b"),
        (m5, f"{stats.get('attack_rate',0)*100:.1f}%",    "Attack Rate",  "#a78bfa"),
    ]
    for col, val, label, color in kpis:
        with col:
            st.markdown(f"""<div class="metric-card">
                <div class="metric-value" style="color:{color};">{val}</div>
                <div class="metric-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

    # ── Donut + Confidence Box ────────────────────────────────────────────
    c1, c2 = st.columns(2)
    counts = Counter(f["decision"] for f in flows)

    with c1:
        st.markdown("<div class='section-header'>🍩 Classification Breakdown</div>", unsafe_allow_html=True)
        labels = list(counts.keys())
        values = list(counts.values())
        colors = [COLORS.get(k, "#6b7fa3") for k in labels]
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.55,
            marker=dict(colors=colors, line=dict(color="#0a0e1a", width=3)),
            textinfo="label+percent",
            pull=[0.04 if l == "ATTACK" else 0 for l in labels],
        ))
        fig.add_annotation(
            text=f"<b>{sum(values)}</b><br>flows",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=18, color="#e2e8f0"),
        )
        fig.update_layout(**_LAYOUT, height=320)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown("<div class='section-header'>📶 Confidence by Class</div>", unsafe_allow_html=True)
        df_c = pd.DataFrame({"Decision": f["decision"], "Confidence": f.get("rf_confidence", 0)} for f in flows)
        fig2 = go.Figure()
        for d, color in COLORS.items():
            subset = df_c[df_c["Decision"] == d]["Confidence"]
            if len(subset) > 0:
                fig2.add_trace(go.Box(
                    y=subset, name=d,
                    marker_color=color, fillcolor=color + "33", boxmean="sd",
                ))
        fig2.update_layout(**_LAYOUT, height=320, showlegend=False,
            yaxis=dict(title="RF Confidence", gridcolor="#1e2d4a"),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Time-series ───────────────────────────────────────────────────────
    st.markdown("<div class='section-header'>⏱️ Threat Activity Over Time</div>", unsafe_allow_html=True)
    ts_rows = []
    for f in flows:
        ts = f.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_rows.append({"minute": dt.replace(second=0, microsecond=0), "decision": f["decision"]})
        except Exception:
            pass

    if ts_rows:
        df_ts = pd.DataFrame(ts_rows)
        df_ts["bucket"] = df_ts["minute"].dt.floor("5min")
        grouped = df_ts.groupby(["bucket", "decision"]).size().reset_index(name="count")
        fig3 = px.area(grouped, x="bucket", y="count", color="decision",
                       color_discrete_map=COLORS)
        fig3.update_layout(**_LAYOUT, height=280,
            xaxis=dict(title="Time (5-min buckets)", gridcolor="#1e2d4a"),
            yaxis=dict(title="Flow count", gridcolor="#1e2d4a"),
        )
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No timestamp data for time-series chart.")

    # ── Top attacking IPs ─────────────────────────────────────────────────
    st.markdown("<div class='section-header'>🔥 Top Attacking Source IPs</div>", unsafe_allow_html=True)
    attack_flows = [f for f in flows if f["decision"] in ("ATTACK", "SUSPICIOUS")]
    top_ips = Counter(f.get("src_ip", "?") for f in attack_flows).most_common(10)
    if top_ips:
        ip_df = pd.DataFrame(top_ips, columns=["IP", "Alerts"])
        fig4 = go.Figure(go.Bar(
            x=ip_df["Alerts"], y=ip_df["IP"], orientation="h",
            marker=dict(color=ip_df["Alerts"],
                colorscale=[[0,"#1e3a5f"],[0.5,"#f59e0b"],[1,"#ef4444"]],
                showscale=True,
            ),
            text=ip_df["Alerts"], textposition="outside",
        ))
        fig4.update_layout(**_LAYOUT, height=300,
            xaxis=dict(title="Alerts", gridcolor="#1e2d4a"),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig4, use_container_width=True)
    else:
        st.success("No attacking IPs detected.")
