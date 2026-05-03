"""
Panel 3 — SHAP Feature Importance
Aggregate SHAP across all flows + per-flow drill-down.
Skill: plotly, data-storytelling, scikit-learn
"""
from __future__ import annotations
from collections import defaultdict
import plotly.graph_objects as go
import pandas as pd
import streamlit as st

_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0", family="Inter", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
)


def render(client) -> None:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.5rem;">
        <div>
            <h1 style="margin:0;font-size:1.6rem;color:#7dd3fc;">SHAP Explainability</h1>
            <p style="margin:0;color:#4b5e7e;font-size:0.82rem;">
                Why did the model flag this flow? Top engineered features that drive each decision.
            </p>
        </div>
    </div>""", unsafe_allow_html=True)

    flows = client.get_flows()
    if not flows:
        st.warning("No flow data available. Run the pipeline first.")
        return

    # ── Aggregate SHAP across all flows ──────────────────────────────────
    agg: dict[str, list[float]] = defaultdict(list)
    for f in flows:
        for tf in f.get("top_features", []):
            feat = tf.get("feature", "")
            val  = tf.get("shap_value", 0.0)
            if feat:
                agg[feat].append(abs(val))

    if not agg:
        st.info("No SHAP data in flows. SHAP values are populated after training and inference.")
        _show_feature_description_table()
        return

    mean_shap = {f: sum(v) / len(v) for f, v in agg.items()}
    sorted_feats = sorted(mean_shap.items(), key=lambda x: x[1], reverse=True)
    feat_names = [x[0].replace("_", " ") for x in sorted_feats]
    feat_vals  = [round(x[1], 4) for x in sorted_feats]

    # ── Global importance bar ─────────────────────────────────────────────
    st.markdown("<div class='section-header'>Global Feature Importance (mean |SHAP|)</div>", unsafe_allow_html=True)

    bar_colors = []
    for v in feat_vals:
        norm = v / max(feat_vals) if max(feat_vals) > 0 else 0
        if norm > 0.7:
            bar_colors.append("#ef4444")
        elif norm > 0.4:
            bar_colors.append("#f59e0b")
        else:
            bar_colors.append("#3b82f6")

    fig = go.Figure(go.Bar(
        x=feat_vals,
        y=feat_names,
        orientation="h",
        marker=dict(color=bar_colors, line=dict(width=0)),
        text=[f"{v:.4f}" for v in feat_vals],
        textposition="outside",
        textfont=dict(color="#e2e8f0", size=11),
    ))
    fig.update_layout(
        **_LAYOUT, height=max(280, len(feat_names) * 45),
        xaxis=dict(title="Mean |SHAP value|", color="#6b7fa3", gridcolor="#1e2d4a"),
        yaxis=dict(autorange="reversed", color="#e2e8f0"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Per-attack vs per-normal comparison ──────────────────────────────
    st.markdown("<div class='section-header'>Attack vs Normal Feature Importance</div>", unsafe_allow_html=True)

    attack_agg: dict[str, list[float]] = defaultdict(list)
    normal_agg: dict[str, list[float]] = defaultdict(list)
    for f in flows:
        target = attack_agg if f.get("decision") in ("ATTACK", "SUSPICIOUS") else normal_agg
        for tf in f.get("top_features", []):
            feat = tf.get("feature", "")
            val  = abs(tf.get("shap_value", 0.0))
            if feat:
                target[feat].append(val)

    all_feats = sorted(set(list(attack_agg.keys()) + list(normal_agg.keys())))
    atk_vals = [sum(attack_agg.get(f, [0])) / max(len(attack_agg.get(f, [1])), 1) for f in all_feats]
    nrm_vals = [sum(normal_agg.get(f, [0])) / max(len(normal_agg.get(f, [1])), 1) for f in all_feats]
    feat_labels = [f.replace("_", " ") for f in all_feats]

    fig2 = go.Figure()
    fig2.add_trace(go.Bar(name="ATTACK / SUSPICIOUS", x=feat_labels, y=atk_vals,
                          marker_color="#ef4444", opacity=0.85))
    fig2.add_trace(go.Bar(name="NORMAL", x=feat_labels, y=nrm_vals,
                          marker_color="#10b981", opacity=0.85))
    fig2.update_layout(
        **_LAYOUT, barmode="group", height=320,
        xaxis=dict(title="Feature", color="#6b7fa3"),
        yaxis=dict(title="Mean |SHAP|", color="#6b7fa3", gridcolor="#1e2d4a"),
        legend=dict(bgcolor="#111827", bordercolor="#1e3a5f"),
    )
    st.plotly_chart(fig2, use_container_width=True)

    # ── Per-flow SHAP drill-down ──────────────────────────────────────────
    st.markdown("<div class='section-header'>Per-Flow SHAP Explanation</div>", unsafe_allow_html=True)

    attack_flows = [f for f in flows if f.get("decision") in ("ATTACK", "SUSPICIOUS")]
    if not attack_flows:
        st.info("No attack flows to inspect.")
    else:
        flow_options = {
            f"{f['flow_id']} | {f['decision']} | conf={f.get('rf_confidence', 0):.3f}": f["flow_id"]
            for f in attack_flows[:50]
        }
        selected_label = st.selectbox("Select attack flow:", list(flow_options.keys()), key="p3_flow")
        selected_id = flow_options[selected_label]
        explanation = client.explain_flow(selected_id)

        col_l, col_r = st.columns([1, 1])
        with col_l:
            tfs = explanation.get("top_features", [])
            if tfs:
                feats  = [t["feature"].replace("_", " ") for t in tfs]
                values = [t["shap_value"] for t in tfs]
                colors = ["#ef4444" if v > 0 else "#10b981" for v in values]
                fig3 = go.Figure(go.Bar(
                    x=values, y=feats, orientation="h",
                    marker_color=colors,
                    text=[f"{v:+.4f}" for v in values],
                    textposition="outside",
                ))
                fig3.update_layout(
                    **_LAYOUT, height=250,
                    xaxis=dict(title="SHAP value (red=attack indicator)", gridcolor="#1e2d4a"),
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig3, use_container_width=True)

        with col_r:
            st.markdown("**Plain English Explanation:**")
            plain = explanation.get("plain_english", "No explanation available.")
            st.markdown(f"""
            <div style="background:#111827; border-left:3px solid #7dd3fc;
                        border-radius:6px; padding:1rem 1.2rem; color:#e2e8f0;
                        font-size:0.88rem; line-height:1.7; margin-top:0.5rem;">
                {plain}
            </div>""", unsafe_allow_html=True)

    # ── Feature description table ─────────────────────────────────────────
    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)
    _show_feature_description_table()


def _show_feature_description_table():
    st.markdown("<div class='section-header'>Engineered Feature Reference</div>", unsafe_allow_html=True)
    data = {
        "Feature":      ["syn_ack_ratio", "bytes_per_second", "packets_per_second",
                         "fwd_bwd_ratio", "avg_packet_size", "iat_mean", "flow_duration_var"],
        "Attack Signal": ["SYN Flood (DDoS)", "Burst/DDoS traffic", "Packet flood",
                         "Port scan (one-directional)", "Reconnaissance (tiny packets)",
                         "Bot behavior (uniform timing)", "Recon (varied timing)"],
        "Formula":      [
            "SYN Flags / (ACK Flags + 1)",
            "Fwd Bytes / (Duration + 1)",
            "Fwd Packets / (Duration + 1)",
            "Fwd Packets / (Bwd Packets + 1)",
            "Fwd Bytes / (Fwd Packets + 1)",
            "Flow IAT Mean (direct)",
            "Rolling std of Flow Duration (window=5)",
        ],
    }
    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True, hide_index=True)
