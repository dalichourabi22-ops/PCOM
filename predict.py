import sys
import time
import math
import joblib
import pandas as pd
from features import TARGET_COLUMNS, engineer_features

MODEL_ARTIFACT_PATH = "models/xgb_vulnerability_models.joblib"


def poisson_pmf(k: int, lam: float) -> float:
    """Computes exact Poisson probability P(X = k) for expected rate lambda."""
    return (lam ** k) * math.exp(-lam) / math.factorial(k)


def predict_from_csv(input_csv_path: str, output_csv_path: str = "prediction_output.csv") -> pd.DataFrame:
    """
    Reads a single-record CSV matching the package record schema,
    predicts the 90-day vulnerability counts per severity, and writes
    a single-record CSV matching the prediction goal schema.
    """
    start_time = time.perf_counter()

    # 1. Load pre-trained models and feature schema
    artifact = joblib.load(MODEL_ARTIFACT_PATH)
    models = artifact["models"]
    feature_columns = artifact["feature_columns"]

    # 2. Load input CSV (take first record if multiple are provided)
    input_df = pd.read_csv(input_csv_path)
    if input_df.empty:
        raise ValueError("Input CSV is empty.")
    record_df = input_df.iloc[[0]].copy()

    # 3. Engineer and align features to exact training column order
    X = engineer_features(record_df)
    X = X.reindex(columns=feature_columns)

    # 4. Build output record matching the prediction goal part of the schema
    output_record = {}
    if "purl" in record_df.columns:
        output_record["purl"] = record_df["purl"].iloc[0]

    print(f"\n--- Prediction Breakdown for {output_record.get('purl', 'package')} ---")
    for target in TARGET_COLUMNS:
        expected_count = float(max(models[target].predict(X)[0], 0.0))
        output_record[target] = round(expected_count, 6)

        # Print Poisson distribution for manual class round discussion
        p0 = poisson_pmf(0, expected_count) * 100
        p1 = poisson_pmf(1, expected_count) * 100
        p2 = poisson_pmf(2, expected_count) * 100
        p3_plus = max(0.0, 100.0 - (p0 + p1 + p2))
        print(
            f"{target:32s} | lambda={expected_count:.4f} | "
            f"P(0)={p0:5.1f}%, P(1)={p1:4.1f}%, P(2)={p2:4.1f}%, P(>=3)={p3_plus:4.1f}%"
        )

    output_df = pd.DataFrame([output_record])
    output_df.to_csv(output_csv_path, index=False)

    elapsed = time.perf_counter() - start_time
    print(f"\nSaved prediction to {output_csv_path} in {elapsed:.3f} seconds.")
    return output_df


if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else "sample_input.csv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "prediction_output.csv"
    predict_from_csv(in_path, out_path)