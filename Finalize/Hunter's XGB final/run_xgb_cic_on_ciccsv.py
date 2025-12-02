import sys
import os
import pandas as pd
import joblib
from xgboost import XGBClassifier


MODEL_FILENAME = "XGBoost_classifier.json"


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_xgb_cic_on_ciccsv.py <cic_csv_file>")
        sys.exit(1)

    csv_path = sys.argv[1]

    if not os.path.isfile(csv_path):
        print(f"[!] CSV file not found: {csv_path}")
        sys.exit(1)

    if not os.path.isfile(MODEL_FILENAME):
        print(f"[!] Model file not found: {MODEL_FILENAME}")
        sys.exit(1)

    print(f"[*] Loading model from {MODEL_FILENAME} ...")
    # This follows your teammate's instruction exactly:
    # loaded_model = joblib.load(MODEL_FILENAME)
    model: XGBClassifier = joblib.load(MODEL_FILENAME)

    print(f"[*] Loading data from {csv_path} ...")
    df = pd.read_csv(csv_path)

    # --- Separate label column if it exists (for optional evaluation) ---
    label_col = None
    for c in ["Label", "LABEL", "label"]:
        if c in df.columns:
            label_col = c
            break

    y_true = None
    if label_col is not None:
        y_true = df[label_col].copy()
        df = df.drop(columns=[label_col])

    # NOTE:
    # We assume the CSV already has the SAME feature columns and preprocessing
    # that Hunter used in training. We do NOT change column types here.
    X_new_data = df.values

    print("[*] Running model.predict on new data ...")
    new_predictions = model.predict(X_new_data)

    # Try to get human-readable class names (if available)
    class_names = getattr(model, "classes_", None)

    # Build an output DataFrame with some useful meta info if present
    meta_cols = [
        "Flow ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Protocol",
    ]
    meta_cols = [c for c in meta_cols if c in df.columns]

    result = pd.DataFrame()
    for c in meta_cols:
        result[c] = df[c]

    result["pred_class_index"] = new_predictions

    if class_names is not None and len(class_names) > 0:
        try:
            result["pred_class_name"] = [class_names[int(i)] for i in new_predictions]
        except Exception:
            # If classes_ are also numeric, this mapping might be redundant; ignore errors.
            pass

    if y_true is not None:
        result["true_label"] = y_true

    # Save results
    out_path = csv_path.replace(".csv", "_with_predictions_cic.csv")
    result.to_csv(out_path, index=False)
    print(f"[+] Saved predictions to {out_path}")

    # Print a quick preview
    print("\n=== CIC/XGB Prediction Preview (first 10 flows) ===")
    for i, row in result.head(10).iterrows():
        parts = []
        if {"Source IP", "Source Port", "Destination IP", "Destination Port"} <= set(
            result.columns
        ):
            parts.append(
                f"{row['Source IP']}:{row['Source Port']} -> "
                f"{row['Destination IP']}:{row['Destination Port']}"
            )
        if "pred_class_name" in result.columns:
            parts.append(f"class={row['pred_class_name']}")
        else:
            parts.append(f"class_idx={row['pred_class_index']}")
        if "true_label" in result.columns:
            parts.append(f"true={row['true_label']}")
        print(f"[Flow {i:03d}] " + " | ".join(parts))

    # Optional: if we had true labels, show accuracy
    if y_true is not None:
        try:
            from sklearn.metrics import accuracy_score, classification_report

            print("\n=== Evaluation against label column ===")
            print("Accuracy:", accuracy_score(y_true, new_predictions))
            print(classification_report(y_true, new_predictions))
        except Exception as e:
            print(f"[!] Could not compute metrics: {e}")


if __name__ == "__main__":
    main()
