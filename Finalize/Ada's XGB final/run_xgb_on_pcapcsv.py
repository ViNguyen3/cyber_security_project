#!/usr/bin/env python3
import sys
import pandas as pd
import numpy as np
import joblib

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_xgb_on_pcapcsv.py pcap_output_unsw.csv")
        sys.exit(1)

    csv_path = sys.argv[1]

    # --- Load model + preprocessing artifacts (from Colab) ---
    xgb = joblib.load("unsw_xgb_model.pkl")
    scaler = joblib.load("unsw_scaler.pkl")
    feature_cols = joblib.load("unsw_feature_cols.pkl")       # list of all features scaler was fit on
    top_features = joblib.load("unsw_top_features.pkl")       # list of selected feature names
    encoders = joblib.load("unsw_label_encoders.pkl")         # dict: {'proto': LabelEncoder, ...}

    # --- Load your UNSW-style flow CSV from pcap2csv ---
    df = pd.read_csv(csv_path)

    # Keep original info for display
    meta_cols = ["srcip", "sport", "dstip", "dsport", "proto", "service", "state"]
    meta_cols = [c for c in meta_cols if c in df.columns]
    meta = df[meta_cols].copy()

    # Match training preprocessing: drop IP/port columns & attack info
    drop_cols = ['id', 'srcip', 'sport', 'dstip', 'dsport', 'attack_cat']  # id may not exist, that's fine
    df_proc = df.drop(columns=drop_cols, errors="ignore")

    # Make sure label is present (pcap2csv sets label=0 for normal)
    # but we do NOT use it as input
    if 'label' in df_proc.columns:
        df_proc = df_proc.drop(columns=['label'])

    # # --- Encode categoricals the same way as training ---
    # for col, le in encoders.items():
    #     if col in df_proc.columns:
    #         # Simple case: assume categories are known from training
    #         # (for a demo this is usually fine: proto ∈ {tcp, udp}, services like http, dns, etc.)
    #         df_proc[col] = le.transform(df_proc[col].astype(str))

    # --- Encode categoricals, allowing unseen labels (e.g. 'other') ---
    for col, le in encoders.items():
        if col in df_proc.columns:
            col_vals = df_proc[col].astype(str)

            # Find labels that were not seen during training
            unseen = np.setdiff1d(col_vals.unique(), le.classes_)

            if len(unseen) > 0:
                # Append unseen labels to the encoder's known classes
                # (keeps existing mappings the same; new labels get new indices)
                le.classes_ = np.concatenate([le.classes_, unseen])

            # Now transform with the updated classes_
            df_proc[col] = le.transform(col_vals)

    # --- Align columns to scaler's expected order ---
    # Ensure all expected feature columns exist (fill any missing with 0)
    for col in feature_cols:
        if col not in df_proc.columns:
            df_proc[col] = 0.0

    # Reorder
    df_proc = df_proc[feature_cols]

    # --- Scale features ---
    X_all = scaler.transform(df_proc.values)
    X_all = pd.DataFrame(X_all, columns=feature_cols)

    # --- Select top features (same subset used for training XGB) ---
    X_selected = X_all[top_features]

    # --- Predict with XGBoost ---
    y_pred = xgb.predict(X_selected)
    y_prob = xgb.predict_proba(X_selected)[:, 1] if hasattr(xgb, "predict_proba") else None

    # Attach predictions back to meta info
    result = meta.copy()
    result["pred_label"] = y_pred
    result["pred_class"] = np.where(y_pred == 1, "Attack", "Normal")
    if y_prob is not None:
        result["attack_prob"] = y_prob

    # Print a small table to console
    print("\n=== IDS Prediction Results ===")
    for i, row in result.iterrows():
        desc = f"{row.get('srcip','?')}:{row.get('sport','?')} -> {row.get('dstip','?')}:{row.get('dsport','?')}"
        print(f"[Flow {i:03d}] {desc} | {row['pred_class']} (label={row['pred_label']})"
              + (f" | attack_prob={row['attack_prob']:.3f}" if 'attack_prob' in result.columns else ""))

    # Save to CSV for logs
    out_path = csv_path.replace(".csv", "_with_predictions.csv")
    result.to_csv(out_path, index=False)
    print(f"\n[+] Saved detailed predictions to {out_path}")

if __name__ == "__main__":
    main()
