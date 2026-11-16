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
    Reads a CSV matching the package record schema (1 or multiple rows),
    predicts the 90-day vulnerability counts per severity for every row,
    and writes the predictions to output_csv_path.
    """
    start_time = time.perf_counter()

    # 1. Load pre-trained models and feature schema
    artifact = joblib.load(MODEL_ARTIFACT_PATH)
    models = artifact["models"]
    feature_columns = artifact["feature_columns"]

    # 2. Load all records from input CSV
    input_df = pd.read_csv(input_csv_path)
    if input_df.empty:
        raise ValueError("Input CSV is empty.")

    # 3. Engineer and align features to exact training column order
    X = engineer_features(input_df)
    X = X.reindex(columns=feature_columns)

    # 4. Build output DataFrame matching the prediction goal schema
    output_df = pd.DataFrame(index=input_df.index)
    if "purl" in input_df.columns:
        output_df["purl"] = input_df["purl"]

    for target in TARGET_COLUMNS:
        preds = models[target].predict(X).clip(min=0.0)
        output_df[target] = preds.round(6)

    # 5. Print Poisson probability breakdown for each package version
    for idx, row in output_df.iterrows():
        pkg_name = row["purl"] if "purl" in output_df.columns else f"row_{idx}"
        print(f"\n--- Prediction Breakdown for {pkg_name} ---")
        for target in TARGET_COLUMNS:
            lam = float(row[target])
            p0 = poisson_pmf(0, lam) * 100
            p1 = poisson_pmf(1, lam) * 100
            p2 = poisson_pmf(2, lam) * 100
            p3_plus = max(0.0, 100.0 - (p0 + p1 + p2))
            print(
                f"{target:32s} | lambda={lam:.4f} | "
                f"P(0)={p0:5.1f}%, P(1)={p1:4.1f}%, P(2)={p2:4.1f}%, P(>=3)={p3_plus:4.1f}%"
            )

    output_df.to_csv(output_csv_path, index=False)

    elapsed = time.perf_counter() - start_time
    print(f"\nSaved {len(output_df)} prediction(s) to {output_csv_path} in {elapsed:.3f} seconds.")
    return output_df


if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else "sample_input.csv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "prediction_output.csv"
    predict_from_csv(in_path, out_path)