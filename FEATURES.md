# FEATURES.md — Feature Engineering Rationale

## Custom Engineered Features for IDS-ML

These 7 features were manually designed based on known attack behavior patterns.
They are NOT generic ML features — each one maps to a specific network attack signal.

---

## Feature Table

| Feature Name | Formula | Attack Behavior It Captures |
|-------------|---------|----------------------------|
| `syn_ack_ratio` | `SYN Count / (ACK Count + 1)` | **DDoS SYN Flood**: Attacker sends many SYN packets, never completes handshake → ACK count stays near 0 |
| `bytes_per_second` | `Fwd Bytes / (Flow Duration + 1)` | **DDoS Bandwidth Flood**: Abnormally high data rate per flow indicates traffic amplification |
| `packets_per_second` | `Fwd Packets / (Flow Duration + 1)` | **Packet Flood**: Bots send massive packet counts in very short durations |
| `fwd_bwd_ratio` | `Fwd Packets / (Bwd Packets + 1)` | **Port Scanning/Probing**: Scanner sends packets but gets no response → asymmetric ratio |
| `avg_packet_size` | `Fwd Bytes / (Fwd Packets + 1)` | **Reconnaissance Scan**: Port scanners use tiny empty packets (< 64 bytes); normal traffic has larger packets |
| `iat_mean` | `Flow IAT Mean` (direct) | **Bot Behavior**: Automated attacks have very uniform inter-arrival times; humans are irregular |
| `flow_duration_var` | `Rolling std of Flow Duration` | **Reconnaissance**: Attackers deliberately vary flow duration to evade detection — high variance = suspicious |

---

## Why These Features Matter (Viva Answer)

### Raw CICIDS2017 features alone are insufficient because:
- They represent direct measurements (bytes, packets, flags)
- They don't encode **behavioral patterns** (what the traffic means)
- A model trained on raw features learns correlation, not causation

### Engineered features encode behavior because:
- `syn_ack_ratio` directly encodes the TCP handshake imbalance of a SYN flood
- `fwd_bwd_ratio` encodes the one-directional nature of a port scan
- `iat_mean` encodes the machine-like regularity of bot traffic
- These are the same features a human analyst would look at

### Proof of value:
- Experiment 1 (raw) vs Experiment 2 (engineered) shows measurable F1 improvement
- This proves feature design — not just model selection — drives IDS performance

---

## Feature Importance Rank (Expected Order)

Based on typical CICIDS2017 results, expected importance rank:

1. `syn_ack_ratio` — strongest DDoS signal
2. `bytes_per_second` — strong DDoS/flood signal
3. `fwd_bwd_ratio` — strong scan/probe signal
4. `packets_per_second` — strong flood signal
5. `avg_packet_size` — moderate scan signal
6. `iat_mean` — moderate automation signal
7. `flow_duration_var` — weakest but adds ensemble value

Actual order is determined by SHAP summary plot at `artifacts/plots/shap_summary.png`.

---

## Feature Engineering Design Principles

1. **Domain-first, data-second**: Features were designed by understanding network attacks, not by running correlation analysis on raw data
2. **Ratio-based**: Division normalizes for different flow durations and sizes
3. **+1 denominator**: Prevents division-by-zero for zero-packet flows
4. **Additive only**: Custom features are added to existing raw features, not replaced
5. **Interpretable**: Every feature can be explained in plain English to a non-technical audience
