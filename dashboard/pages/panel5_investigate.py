"""
Panel 5 — Flow Investigation
Analyst workflow: search by IP, inspect individual flow, manual predict.
Skill: frontend-design, fastapi-pro, data-storytelling
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
DECISION_COLORS = {"ATTACK": "#ef4444", "SUSPICIOUS": "#f59e0b", "NORMAL": "#10b981"}


def render(client) -> None:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.5rem;">
        <div>
            <h1 style="margin:0;font-size:1.6rem;color:#7dd3fc;">Flow Investigation</h1>
            <p style="margin:0;color:#4b5e7e;font-size:0.82rem;">
                Deep-dive into individual network flows — search, inspect, explain, re-predict
            </p>
        </div>
    </div>""", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Search & Inspect", "Manual Predict"])

    # ── Tab 1: Search & Inspect ────────────────────────────────────────────
    with tab1:
        flows = client.get_flows()
        if not flows:
            st.warning("No flows. Run the watch pipeline or check the API.")
            return

        col_a, col_b, col_c = st.columns([2, 2, 2])
        with col_a:
            search_ip = st.text_input("Filter by Source IP", placeholder="e.g. 192.168.1.5", key="p5_ip")
        with col_b:
            filter_dec = st.multiselect(
                "Decision filter",
                ["ATTACK", "SUSPICIOUS", "NORMAL"],
                default=["ATTACK", "SUSPICIOUS"],
                key="p5_dec",
            )
        with col_c:
            max_display = st.slider("Max rows", 10, 200, 50, key="p5_rows")

        # Apply filters
        filtered = flows
        if search_ip:
            filtered = [f for f in filtered if search_ip in f.get("src_ip", "")]
        if filter_dec:
            filtered = [f for f in filtered if f.get("decision") in filter_dec]
        filtered = filtered[:max_display]

        st.markdown(f"<div style='color:#6b7fa3;font-size:0.8rem;margin-bottom:0.8rem;'>"
                    f"Showing {len(filtered)} of {len(flows)} flows</div>", unsafe_allow_html=True)

        if not filtered:
            st.info("No flows match the current filters.")
            return

        # Flow table
        rows = []
        for f in filtered:
            rows.append({
                "Flow ID":   f.get("flow_id", "—"),
                "Decision":  f.get("decision", "—"),
                "Src IP":    f.get("src_ip", "—"),
                "Dst IP":    f.get("dst_ip", "—"),
                "RF Conf":   f"{f.get('rf_confidence', 0):.3f}",
                "IF Anomaly": "Yes" if f.get("if_anomaly") else "No",
                "Timestamp": (f.get("timestamp", "")[:19] or "—"),
            })
        df = pd.DataFrame(rows)

        def style_decision(val):
            color = DECISION_COLORS.get(val, "#6b7fa3")
            return f"color:{color}; font-weight:600;"

        styled = (
            df.style.map(style_decision, subset=["Decision"])
            .set_properties(**{"background-color": "#111827", "color": "#e2e8f0"})
            .set_table_styles([{"selector": "th", "props": [
                ("background-color","#0f1629"), ("color","#7dd3fc"),
                ("font-size","0.78rem"), ("text-transform","uppercase"),
            ]}])
        )
        st.dataframe(styled, use_container_width=True, height=320)

        # ── Flow detail drill-down ─────────────────────────────────────────
        st.markdown("<div class='section-header' style='margin-top:1.5rem;'>Flow Detail</div>", unsafe_allow_html=True)
        flow_map = {f"{f['flow_id']} | {f['decision']} | {f.get('src_ip','?')}": f["flow_id"]
                    for f in filtered}
        selected_label = st.selectbox("Select flow:", list(flow_map.keys()), key="p5_sel")
        selected_id    = flow_map[selected_label]

        selected_flow = next((f for f in filtered if f["flow_id"] == selected_id), None)
        if not selected_flow:
            return

        decision = selected_flow.get("decision", "?")
        dec_color = DECISION_COLORS.get(decision, "#6b7fa3")
        conf = selected_flow.get("rf_confidence", 0)
        is_anomaly = selected_flow.get("if_anomaly", False)

        st.markdown(f"""
        <div style="background:#111827; border:1px solid #1e3a5f; border-left:4px solid {dec_color};
                    border-radius:10px; padding:1.2rem 1.5rem; margin-bottom:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="font-size:1.2rem; font-weight:700; color:{dec_color};">
                        {decision}
                    </span>
                    <span style="color:#6b7fa3; font-size:0.8rem; margin-left:1rem;">
                        RF Confidence: <b style="color:#e2e8f0;">{conf:.4f}</b>
                    </span>
                    <span style="color:#6b7fa3; font-size:0.8rem; margin-left:1rem;">
                        IF Anomaly: <b style="color:{'#f59e0b' if is_anomaly else '#10b981'};">
                            {'Yes' if is_anomaly else 'No'}</b>
                    </span>
                </div>
                <div style="font-size:0.75rem; color:#4b5e7e; font-family:'JetBrains Mono',monospace;">
                    {selected_flow.get('flow_id','')}
                </div>
            </div>
            <div style="margin-top:0.8rem; font-size:0.82rem; color:#6b7fa3;">
                <b style="color:#e2e8f0;">{selected_flow.get('src_ip','?')}</b>
                <span style="margin:0 0.5rem;">→</span>
                <b style="color:#e2e8f0;">{selected_flow.get('dst_ip','?')}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # SHAP for this flow
        explanation = client.explain_flow(selected_id)
        top_feats   = explanation.get("top_features", [])
        plain       = explanation.get("plain_english", "")

        col_l, col_r = st.columns([1, 1])
        with col_l:
            st.markdown("**SHAP feature contributions:**")
            if top_feats:
                feats  = [t["feature"].replace("_", " ") for t in top_feats]
                values = [t["shap_value"] for t in top_feats]
                colors = ["#ef4444" if v > 0 else "#10b981" for v in values]
                fig = go.Figure(go.Bar(
                    x=values, y=feats, orientation="h",
                    marker_color=colors,
                    text=[f"{v:+.4f}" for v in values],
                    textposition="outside",
                ))
                fig.update_layout(**_LAYOUT, height=220,
                    xaxis=dict(title="SHAP value", gridcolor="#1e2d4a"),
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No SHAP data for this flow.")

        with col_r:
            st.markdown("**Plain English explanation:**")
            st.markdown(f"""
            <div style="background:#0f1629; border-left:3px solid #7dd3fc; border-radius:6px;
                        padding:1rem 1.2rem; color:#e2e8f0; font-size:0.88rem;
                        line-height:1.7; margin-top:0.5rem;">
                {plain if plain else "Explanation unavailable."}
            </div>""", unsafe_allow_html=True)

    # ── Tab 2: Manual Predict ──────────────────────────────────────────────
    with tab2:
        st.markdown("<div class='section-header'>Manual Flow Prediction</div>", unsafe_allow_html=True)
        st.markdown("""
        <div style="color:#6b7fa3; font-size:0.82rem; margin-bottom:1.2rem;">
            Enter feature values manually and run inference through the RF + IF ensemble.
            Use this to test custom scenarios or validate model behavior.
        </div>""", unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            src_ip = st.text_input("Source IP", value="192.168.1.100", key="p5_src")
            dst_ip = st.text_input("Dest IP",   value="10.0.0.1",      key="p5_dst")
            st.markdown("---")
            st.markdown("**Engineered Features:**")
            syn_ack    = st.number_input("syn_ack_ratio",    value=8.5,  step=0.1, key="p5_f1")
            bytes_ps   = st.number_input("bytes_per_second", value=50000.0, step=1000.0, key="p5_f2")
            packets_ps = st.number_input("packets_per_second", value=500.0, step=10.0, key="p5_f3")

        with col2:
            fwd_bwd    = st.number_input("fwd_bwd_ratio",    value=15.0, step=0.5, key="p5_f4")
            avg_pkt    = st.number_input("avg_packet_size",  value=48.0, step=1.0, key="p5_f5")
            iat        = st.number_input("iat_mean",          value=120.0, step=10.0, key="p5_f6")
            dur_var    = st.number_input("flow_duration_var", value=2500.0, step=100.0, key="p5_f7")

        features = {
            "syn_ack_ratio":     syn_ack,
            "bytes_per_second":  bytes_ps,
            "packets_per_second": packets_ps,
            "fwd_bwd_ratio":     fwd_bwd,
            "avg_packet_size":   avg_pkt,
            "iat_mean":          iat,
            "flow_duration_var": dur_var,
        }

        if st.button("Run Prediction", key="p5_predict", use_container_width=True):
            with st.spinner("Running RF + IF ensemble inference..."):
                result = client.predict(features, src_ip=src_ip, dst_ip=dst_ip)

            if result:
                decision  = result.get("decision", "?")
                dec_color = DECISION_COLORS.get(decision, "#6b7fa3")
                conf      = result.get("rf_confidence", 0)

                st.markdown(f"""
                <div style="background:#111827; border:2px solid {dec_color};
                            border-radius:12px; padding:1.5rem; text-align:center;
                            margin-top:1rem;">
                    <div style="font-size:2.5rem; font-weight:700; color:{dec_color};">
                        {decision}
                    </div>
                    <div style="color:#6b7fa3; font-size:0.85rem; margin-top:0.5rem;">
                        RF Confidence: <b style="color:#e2e8f0;">{conf:.4f}</b> &nbsp;|&nbsp;
                        IF Anomaly: <b style="color:{'#f59e0b' if result.get('if_anomaly') else '#10b981'};">
                        {'[WARNING] Yes' if result.get('if_anomaly') else '[OK] No'}</b>
                    </div>
                </div>""", unsafe_allow_html=True)

                top_feats = result.get("top_features", [])
                if top_feats:
                    st.markdown("<div style='margin-top:1rem;'><b>Contributing features:</b></div>",
                                unsafe_allow_html=True)
                    feats  = [t["feature"].replace("_", " ") for t in top_feats]
                    values = [t["shap_value"] for t in top_feats]
                    colors = ["#ef4444" if v > 0 else "#10b981" for v in values]
                    fig = go.Figure(go.Bar(
                        x=values, y=feats, orientation="h",
                        marker_color=colors,
                        text=[f"{v:+.4f}" for v in values],
                        textposition="outside",
                    ))
                    fig.update_layout(**_LAYOUT, height=220,
                        xaxis=dict(title="SHAP value", gridcolor="#1e2d4a"),
                        yaxis=dict(autorange="reversed"),
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.error("Prediction failed — API may be offline or models not trained.")
                st.info("Start the API: `uvicorn src.api.main:app --reload --port 8000`")
