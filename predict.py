import re
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


def parse_semver(version_str: str) -> tuple:
    """
    Parses a Semantic Versioning (SemVer 2.0) string into a sortable tuple.
    Normal releases outrank pre-releases of the same core version (e.g., 5.0.0 > 5.0.0-beta.2 > 4.21.2).
    """
    if not isinstance(version_str, str) or not version_str.strip():
        return (0, 0, 0, 0, ())

    v = version_str.strip().lstrip("vV").split("+", 1)[0]
    if "-" in v:
        core, prerelease = v.split("-", 1)
        is_final = 0
        pre_parts = tuple(
            (0, int(p)) if p.isdigit() else (1, p)
            for p in prerelease.split(".")
        )
    else:
        core = v
        is_final = 1
        pre_parts = ()

    nums = [int(x) for x in re.findall(r"\d+", core)[:3]]
    while len(nums) < 3:
        nums.append(0)

    return (nums[0], nums[1], nums[2], is_final, pre_parts)


def predict_from_csv(input_csv_path: str, output_csv_path: str = "prediction_output.csv") -> pd.DataFrame:
    """
    Predicts 90-day vulnerability counts and outputs a single-record CSV:
    - If 'purl' or 'version' is present: selects the highest semantic version row.
    - If anonymized (no version identifiers): predicts all rows and aggregates via median.
    """
    start_time = time.perf_counter()

    # 1. Load pre-trained models and feature schema
    artifact = joblib.load(MODEL_ARTIFACT_PATH)
    models = artifact["models"]
    feature_columns = artifact["feature_columns"]

    # 2. Load input CSV
    input_df = pd.read_csv(input_csv_path)
    if input_df.empty:
        raise ValueError("Input CSV is empty.")

    has_purl = "purl" in input_df.columns and input_df["purl"].notna().any()
    has_version = "version" in input_df.columns and input_df["version"].notna().any()

    if len(input_df) == 1 or has_purl or has_version:
        # Select single row with highest semantic version
        work_df = input_df.copy()
        work_df["_ts"] = (
            pd.to_datetime(work_df["published_at"], errors="coerce", utc=True)
            if "published_at" in work_df.columns
            else pd.NaT
        )
        if has_purl:
            versions = work_df["purl"].astype(str).apply(lambda p: p.rsplit("@", 1)[-1] if "@" in p else "")
            work_df["_semver"] = versions.apply(parse_semver)
            target_df = work_df.sort_values(by=["_semver", "_ts"], ascending=[False, False]).iloc[[0]]
            mode_info = f"Highest SemVer selected: {target_df['purl'].iloc[0]}"
        elif has_version:
            work_df["_semver"] = work_df["version"].astype(str).apply(parse_semver)
            target_df = work_df.sort_values(by=["_semver", "_ts"], ascending=[False, False]).iloc[[0]]
            mode_info = f"Highest SemVer selected: version={target_df['version'].iloc[0]}"
        else:
            target_df = work_df
            mode_info = "Single input record"

        target_df = target_df.drop(columns=["_ts", "_semver"], errors="ignore")
        X = engineer_features(target_df).reindex(columns=feature_columns)

        output_record = {}
        for target in TARGET_COLUMNS:
            lam = float(max(models[target].predict(X)[0], 0.0))
            output_record[target] = round(lam, 6)
    else:
        # Anonymized multi-row input: predict all rows and aggregate with median
        X = engineer_features(input_df).reindex(columns=feature_columns)
        all_preds = pd.DataFrame(index=input_df.index)
        for target in TARGET_COLUMNS:
            all_preds[target] = models[target].predict(X).clip(min=0.0)

        print(f"\nAll {len(all_preds)} candidate version predictions:")
        print(all_preds.to_string(float_format=lambda x: f"{x:.6f}"))

        median_series = all_preds.median(axis=0)
        output_record = {target: round(float(median_series[target]), 6) for target in TARGET_COLUMNS}
        mode_info = f"Anonymized input ({len(input_df)} versions) -> Median ensemble"

    # 3. Print final 1-record Poisson breakdown and save CSV
    print(f"\nMode: {mode_info}")
    for target in TARGET_COLUMNS:
        lam = output_record[target]
        p0 = poisson_pmf(0, lam) * 100
        p1 = poisson_pmf(1, lam) * 100
        p2 = poisson_pmf(2, lam) * 100
        p3_plus = max(0.0, 100.0 - (p0 + p1 + p2))
        print(
            f"{target:32s} | lambda={lam:.6f} | "
            f"P(0)={p0:5.1f}%, P(1)={p1:4.1f}%, P(2)={p2:4.1f}%, P(>=3)={p3_plus:4.1f}%"
        )

    output_df = pd.DataFrame([output_record], columns=TARGET_COLUMNS)
    output_df.to_csv(output_csv_path, index=False, float_format="%.6f")

    elapsed = time.perf_counter() - start_time
    print(f"\nSaved 1-record prediction to {output_csv_path} in {elapsed:.3f} seconds.")
    return output_df


if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else "sample_input.csv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "prediction_output.csv"
    predict_from_csv(in_path, out_path)