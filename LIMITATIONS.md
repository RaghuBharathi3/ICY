# LIMITATIONS.md — Honest Scope Boundaries

## What This Project Is and Is Not

This is a **research prototype** built to demonstrate ML-based intrusion detection concepts.
It is NOT a production IDS product. The limitations below are intentional and known.

---

## Limitation 1 — Dataset Dependency

**What:** The system was trained and evaluated exclusively on CICIDS2017.

**Impact:**
- Traffic patterns in CICIDS2017 were generated in a controlled lab environment (University of New Brunswick, 2017)
- Real-world enterprise traffic has different flow characteristics, noise levels, and attack variations
- Model performance on real traffic may be lower than reported evaluation metrics

**Why accepted:**
- CICIDS2017 is the standard benchmark dataset for academic IDS research
- It provides labeled, realistic, flow-based data — sufficient for a research prototype

---

## Limitation 2 — Limited Attack Coverage

**What:** System is trained on Probing + DDoS only.

**Attacks NOT covered:**
- Ransomware
- Insider threats
- Application-layer attacks (SQL injection, XSS at flow level)
- Advanced Persistent Threats (APT)
- Encrypted attack traffic (HTTPS-based)
- Zero-day exploits

**Impact:**
- Presenting this system as a "general IDS" would be misleading
- Detection accuracy for attack types outside training scope is undefined

**Why accepted:**
- Focusing on 2 attack types allows deep feature engineering for each
- A narrow, high-quality detector is more credible than a broad, shallow one

---

## Limitation 3 — Not Real-Time (Semi-Real-Time Only)

**What:** Pipeline uses a watch folder — processes CSV files, not live packets.

**Pipeline latency:**
- File detection: ~1–5 seconds (watchdog polling)
- Feature extraction + prediction: ~1–10 seconds per file
- Total end-to-end: **5–30 seconds** (not milliseconds)

**Impact:**
- A real IDS needs < 1 second detection latency
- This prototype cannot block attacks in progress

**Why accepted:**
- Live packet capture requires: root/admin, network tap, CICFlowMeter in streaming mode, Java runtime
- These dependencies make reproducible demo impossible
- Watch folder approach is reproducible and demonstrable on any laptop

---

## Limitation 4 — No Enterprise Hardening

**What:** The system lacks production-readiness features.

**Missing:**
- Authentication and authorization (API has no auth)
- Rate limiting on prediction endpoints
- High availability / load balancing
- Encrypted storage of flow data
- Audit logging
- Input sanitization beyond Pydantic validation

**Impact:**
- Cannot be deployed as-is in a real network environment
- API is open to anyone with network access

**Why accepted:**
- Adding auth/HA would double the codebase without adding academic value
- The project scope is ML system design, not security engineering

---

## Limitation 5 — Offline Model (No Online Learning)

**What:** Model does not learn from new traffic after deployment.

**Impact:**
- If attack patterns change (adversarial drift), model accuracy degrades silently
- Retraining requires: new labeled data + manual trigger + redeployment
- No concept drift detection is implemented

**Why accepted:**
- Online learning for RF requires approximation algorithms (Hoeffding trees)
- Adds significant complexity for marginal gain in a prototype
- Periodic retraining is standard practice in real IDS deployments

---

## Limitation 6 — Binary Labels Only

**What:** Final output is ATTACK / SUSPICIOUS / NORMAL — attack subtype is not distinguished.

**Impact:**
- Analyst cannot distinguish DDoS from PortScan in the final alert
- Attack subtype information is used only in feature engineering, not in output

**Why accepted:**
- Multi-class classification requires separate models or more complex architectures
- Binary classification is a valid first stage in a tiered detection system
- Adding multi-class output would require redefining the evaluation strategy

---

## Summary Table

| Limitation | Severity | Impact | Mitigation if Scaled |
|-----------|---------|--------|---------------------|
| Dataset dependency | Medium | Lower accuracy on real traffic | Periodic retraining on real flows |
| Limited attack types | High | Misses many attack categories | Extend training to CICIDS2018 + UNSW-NB15 |
| Semi-real-time only | High | Cannot block attacks in progress | Replace with Scapy + Zeek streaming |
| No enterprise hardening | Medium | Cannot deploy in production | Add OAuth2 + rate limiting |
| No online learning | Low | Accuracy degrades over time | Implement Hoeffding tree or scheduled retraining |
| Binary labels only | Low | No attack subtype in output | Add multi-class second-stage classifier |

---

*Naming limitations explicitly is a sign of intellectual maturity.
It shows understanding of what was built — not just that it was built.*
