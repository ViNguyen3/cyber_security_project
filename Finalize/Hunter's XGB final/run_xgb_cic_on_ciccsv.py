# hunter_predict.py

import sys
import os
import joblib
import numpy as np
import pandas as pd


MODEL_FILENAME = "XGBoost_classifier.json"


def preprocess_for_hunter_model(df_raw: pd.DataFrame) -> np.ndarray:
    """
    Apply the SAME preprocessing that script.py uses,
    but in a reusable function for new data.
    """
    df = df_raw.copy()

    # 1) Match script.py: strip + uppercase column names
    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.upper()

    # 2) Drop entirely empty rows (just in case)
    df = df.dropna(how="all", axis=0).reset_index(drop=True)

    # 3) Drop FLOW ID if present
    if "FLOW ID" in df.columns:
        df = df.drop(columns=["FLOW ID"])

    # 4) Drop LABEL if present (for inference we don't need it in X)
    if "LABEL" in df.columns:
        df = df.drop(columns=["LABEL"])

    # 5) IP feature engineering (SOURCE IP / DESTINATION IP -> octets)
    ip_columns = ["SOURCE IP", "DESTINATION IP"]
    for ip_col in ip_columns:
        if ip_col in df.columns:
            new_octets = df[ip_col].astype(str).str.split(".", expand=True)
            # coerce to numeric (invalid -> NaN -> later to 0)
            new_octets = new_octets.apply(pd.to_numeric, errors="coerce")
            new_octets.columns = [f"{ip_col} {i}" for i in range(4)]
            df = pd.concat([df, new_octets], axis=1)
            df = df.drop(columns=[ip_col])

    # 6) TIMESTAMP feature engineering
    if "TIMESTAMP" in df.columns:
        ts = pd.to_datetime(df["TIMESTAMP"], errors="coerce")
        df["DAY"] = ts.dt.day
        df["DAY OF WEEK"] = ts.dt.dayofweek
        df["MONTH"] = ts.dt.month
        df["YEAR"] = ts.dt.year
        df["MINUTE"] = ts.dt.minute
        df["HOUR"] = ts.dt.hour
        df = df.drop(columns=["TIMESTAMP"])

    # 7) Convert to numpy and handle inf / NaN like script.py
    X = df.to_numpy()
    X = X.astype(float, copy=False)  # best-effort numeric
    X[np.isinf(X)] = np.nan
    X = np.nan_to_num(X, nan=0.0)

    return X


def main():
    if len(sys.argv) < 2:
        print("Usage: python hunter_predict.py <cicflowmeter_csv>")
        sys.exit(1)

    csv_path = sys.argv[1]

    if not os.path.isfile(csv_path):
        print(f"[!] CSV file not found: {csv_path}")
        sys.exit(1)

    if not os.path.isfile(MODEL_FILENAME):
        print(f"[!] Model file not found: {MODEL_FILENAME}")
        sys.exit(1)

    print(f"[*] Loading model from {MODEL_FILENAME} ...")
    model = joblib.load(MODEL_FILENAME)

    print(f"[*] Loading data from {csv_path} ...")
    df_raw = pd.read_csv(csv_path)

    print("[*] Preprocessing data (same as script.py) ...")
    X_new = preprocess_for_hunter_model(df_raw)

    print(f"[*] Feature shape for new data: {X_new.shape}")

    print("[*] Running predictions ...")
    new_preds = model.predict(X_new)

    # Try to get class names, if stored
    class_names = getattr(model, "classes_", None)

    # Build a small result DataFrame to inspect
    result = pd.DataFrame()
    # Some useful meta columns if present
    for col in ["FLOW ID", "SOURCE IP", "SOURCE PORT", "DESTINATION IP", "DESTINATION PORT", "PROTOCOL"]:
        col_up = col.upper()
        if col_up in df_raw.columns:
            result[col_up] = df_raw[col_up]

    result["PRED_CLASS_IDX"] = new_preds
    if class_names is not None and len(class_names) > 0:
        try:
            result["PRED_CLASS_NAME"] = [class_names[int(i)] for i in new_preds]
        except Exception:
            pass

    out_path = csv_path.replace(".csv", "_hunter_preds.csv")
    result.to_csv(out_path, index=False)
    print(f"[+] Saved predictions to {out_path}")

    print("\n=== Preview (first 10 rows) ===")
    print(result.head(10))


if __name__ == "__main__":
    main()
