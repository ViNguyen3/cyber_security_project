# ids_realtime_infer.py

import pandas as pd
import numpy as np
import joblib

# -----------------------------
# 1. Load artifacts
# -----------------------------
artifacts_path = "unsw_xgb_realtime.joblib"
artifacts = joblib.load(artifacts_path)

xgb = artifacts["xgb_model"]
scaler = artifacts["scaler"]
label_encoders = artifacts["label_encoders"]
feature_cols = artifacts["feature_cols"]
top_features = artifacts["top_features"]
cat_cols = artifacts["cat_cols"]

print("✅ Loaded model and preprocessing artifacts")

# -----------------------------
# 2. Load new CSV from pcap
# -----------------------------
NEW_CSV_PATH = "new_combine.csv"  # <--- change if you use a different file
df_new = pd.read_csv(NEW_CSV_PATH)
print("New data shape (raw):", df_new.shape)

# -----------------------------
# 3. Canonicalize column names
# -----------------------------
# Map pcap-converter column names to the names used in training
rename_map = {
    "Sload": "sload",
    "Dload": "dload",
    "Spkts": "spkts",
    "Dpkts": "dpkts",
    "Smean": "smean",
    "Smeans": "smean",
    "Dmean": "dmean",
    "Dmeans": "dmean",
    "Sjit": "sjit",
    "Djit": "djit",
    "res_bdy_len": "response_body_len",
    "Sintpkt": "sinpkt",
    "Dintpkt": "dinpkt",
}

df_new = df_new.rename(columns=rename_map)

# -----------------------------
# 4. Basic cleaning (same as training)
# -----------------------------
drop_cols = ["id", "srcip", "sport", "dstip", "dsport"]
for c in drop_cols:
    if c in df_new.columns:
        df_new = df_new.drop(columns=[c])

# Optional: binary label if present (attack=1, normal=0)
y_true = None
if "label" in df_new.columns:
    df_new["label"] = df_new["label"].apply(lambda x: 1 if x == 1 else 0)
    y_true = df_new["label"].values
    df_new = df_new.drop(columns=["label"])

if "attack_cat" in df_new.columns:
    df_new = df_new.drop(columns=["attack_cat"])

# -----------------------------
# 5. Engineer missing features
# -----------------------------
# Compute 'rate' if missing and we have dur / bytes
if "rate" not in df_new.columns and all(
    col in df_new.columns for col in ["sbytes", "dbytes", "dur"]
):
    dur_safe = df_new["dur"].replace(0, 1e-6)
    df_new["rate"] = (df_new["sbytes"] + df_new["dbytes"]) / dur_safe

# If these count features are missing, fill with 0 (reasonable default)
for col in ["ct_srv_src", "ct_srv_dst"]:
    if col not in df_new.columns:
        df_new[col] = 0

# -----------------------------
# 6. Apply stored label encoders
# -----------------------------
def safe_label_transform(col_series, le):
    """
    Make sure unseen categories don't crash transform.
    We extend le.classes_ to include new categories.
    """
    col_series = col_series.astype(str)
    known = set(le.classes_)
    new_values = sorted(set(col_series.unique()) - known)
    if new_values:
        le.classes_ = np.concatenate(
            [le.classes_, np.array(new_values, dtype=object)]
        )
    return le.transform(col_series)


for col in cat_cols:
    if col in df_new.columns:
        le = label_encoders[col]
        df_new[col] = safe_label_transform(df_new[col], le)

# -----------------------------
# 7. Build full feature matrix & scale
# -----------------------------
missing = [f for f in feature_cols if f not in df_new.columns]
if missing:
    print(
        "⚠️ Warning: new data is missing some training features. "
        "Filling them with training minima:"
    )
    print("   ", missing)

# Build X_new_full with all training-time feature columns
n = len(df_new)
X_new_full = pd.DataFrame(index=df_new.index)

for j, f in enumerate(feature_cols):
    if f in df_new.columns:
        X_new_full[f] = df_new[f].values
    else:
        # Use the MinMaxScaler's data_min_ as a neutral-ish value
        X_new_full[f] = np.full(n, scaler.data_min_[j])

# Scale using the training scaler
X_new_scaled = scaler.transform(X_new_full)
X_new_scaled = pd.DataFrame(X_new_scaled, columns=feature_cols)

# Pick the same top features used in training
X_new_selected = X_new_scaled[top_features]

# -----------------------------
# 8. Predict with XGBoost
# -----------------------------
y_pred = xgb.predict(X_new_selected)
y_prob = xgb.predict_proba(X_new_selected)[:, 1]

df_result = pd.DataFrame(
    {
        "prediction": y_pred,
        "attack_prob": y_prob,
    }
)

print("Prediction counts:")
print(
    df_result["prediction"]
    .value_counts()
    .rename(index={0: "Normal", 1: "Attack"})
)

# If ground truth labels are present, compute metrics
if y_true is not None:
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix,
    )

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)

    print("\n📈 Evaluation on new pcap-converted CSV:")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-score:  {f1:.4f}")

    cm = confusion_matrix(y_true, y_pred)
    print("Confusion matrix (rows=true, cols=pred):\n", cm)

# Optionally, save results for inspection
df_result.to_csv("pcap_predictions.csv", index=False)
print("✅ Saved predictions to pcap_predictions.csv")
