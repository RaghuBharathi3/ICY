# MODELS.md — Model Selection Rationale

## Why These Two Models (And Not Others)

---

## Model 1: Random Forest (Primary Classifier)

**Role:** Supervised binary classification — predicts ATTACK (1) or NORMAL (0)

### Why Random Forest?

| Criterion | Reasoning |
|-----------|-----------|
| **Labeled data exists** | CICIDS2017 is fully labeled → supervised learning is appropriate |
| **Handles tabular data natively** | Flow-based features are tabular — RF is purpose-built for this |
| **Feature importance built-in** | `.feature_importances_` gives free interpretability without SHAP |
| **Imbalanced class support** | `class_weight='balanced'` auto-adjusts for 80/20 class split |
| **No scaling required** | RF is invariant to feature scale (unlike SVM, KNN) |
| **Fast inference** | Sub-millisecond per prediction after training |
| **SHAP-compatible** | `shap.TreeExplainer` supports RF natively with exact values |

### Why NOT SVM?
- Does not scale to 500k+ flows in CICIDS2017
- No native feature importance
- Requires careful kernel selection

### Why NOT Neural Network?
- Requires more data for stable training
- Black-box — SHAP approximate, not exact
- No justification for additional complexity in binary tabular classification
- Out of scope (master prompt hard rule: no deep learning)

### Hyperparameters (Locked)

```python
RandomForestClassifier(
    n_estimators=100,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
)
```

---

## Model 2: Isolation Forest (Anomaly Detection Layer)

**Role:** Unsupervised anomaly detection — flags statistically unusual flows

### Why Isolation Forest?

| Criterion | Reasoning |
|-----------|-----------|
| **No labels needed** | Works purely on statistical isolation — supplements RF without labels |
| **Catches zero-day-like patterns** | Detects flows that are statistically rare, even if not in training labels |
| **High-dimensional data** | IF handles many features without distance-metric sensitivity |
| **Interpretable threshold** | `decision_function < 0` = anomalous (clear boundary) |
| **Complements RF** | RF catches known patterns; IF catches unusual-but-unlabeled flows |

### Why NOT Local Outlier Factor (LOF)?
- Scales poorly (O(n²) complexity) on large datasets
- Slow inference — not suitable for semi-real-time pipeline

### Why NOT Autoencoder?
- Deep learning — out of scope per master prompt hard rule
- Requires GPU for reasonable training time
- Harder to explain reconstruction error to a non-technical audience

### Hyperparameters (Locked)

```python
IsolationForest(
    n_estimators=100,
    contamination=0.1,   # ~10% expected anomalies in network traffic
    random_state=42,
)
```

---

## Ensemble Decision Logic

```
RF=Attack              → final = ATTACK      (confident attack classification)
RF=Normal, IF<0        → final = SUSPICIOUS  (normal by label, but statistically rare)
RF=Normal, IF>=0       → final = NORMAL      (both models agree: benign)
```

**Why this logic:**
- ATTACK (both agree) → high confidence
- SUSPICIOUS (RF=normal, IF=anomaly) → catches edge cases RF misses
- NORMAL (both agree) → low false positive rate

---

## Model Comparison Table

| Model | Type | Training Data | Interpretability | Inference Speed | SHAP Support |
|-------|------|--------------|-----------------|----------------|-------------|
| Random Forest | Supervised | Labeled (RF + SMOTE) | High (feature importance) | Fast (< 1ms) | Native |
| Isolation Forest | Unsupervised | Unlabeled (features only) | Medium (anomaly score) | Fast (< 1ms) | Partial |

---

## Accuracy vs Interpretability Tradeoff

```
More Interpretable ◄──────────────────────────────────► More Accurate
                   RF    Gradient Boost   Neural Net
                   ▲
                   Chosen: best balance for an IDS prototype
                   that must be explained in a viva examination
```

The interpretability of Random Forest is intentional — every prediction must be defensible.
