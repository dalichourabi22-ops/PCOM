import io
import re
import joblib
import requests
import pandas as pd
import uvicorn
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from features import TARGET_COLUMNS, engineer_features

MODEL_ARTIFACT_PATH = "models/xgb_vulnerability_models.joblib"

# Load pre-trained models and feature schema once at server startup
ARTIFACT = joblib.load(MODEL_ARTIFACT_PATH)
MODELS = ARTIFACT["models"]
FEATURE_COLUMNS = ARTIFACT["feature_columns"]

app = FastAPI(title="ML Prediction API")


class EvaluationBody(BaseModel):
    testdata_download_endpoint: str
    prediction_upload_endpoint: str


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


def run_model(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame([{t: 0.0 for t in TARGET_COLUMNS}], columns=TARGET_COLUMNS)

    has_purl = "purl" in df.columns and df["purl"].notna().any()
    has_version = "version" in df.columns and df["version"].notna().any()

    if len(df) == 1 or has_purl or has_version:
        work_df = df.copy()
        work_df["_ts"] = (
            pd.to_datetime(work_df["published_at"], errors="coerce", utc=True)
            if "published_at" in work_df.columns
            else pd.NaT
        )
        if has_purl:
            versions = work_df["purl"].astype(str).apply(lambda p: p.rsplit("@", 1)[-1] if "@" in p else "")
            work_df["_semver"] = versions.apply(parse_semver)
            target_df = work_df.sort_values(by=["_semver", "_ts"], ascending=[False, False]).iloc[[0]]
        elif has_version:
            work_df["_semver"] = work_df["version"].astype(str).apply(parse_semver)
            target_df = work_df.sort_values(by=["_semver", "_ts"], ascending=[False, False]).iloc[[0]]
        else:
            target_df = work_df

        target_df = target_df.drop(columns=["_ts", "_semver"], errors="ignore")
        X = engineer_features(target_df).reindex(columns=FEATURE_COLUMNS)

        output_record = {}
        for target in TARGET_COLUMNS:
            lam = float(max(MODELS[target].predict(X)[0], 0.0))
            output_record[target] = round(lam, 6)
    else:
        # Anonymized input (without purl/version): predict across all rows and take the median
        X = engineer_features(df).reindex(columns=FEATURE_COLUMNS)
        all_preds = pd.DataFrame(index=df.index)
        for target in TARGET_COLUMNS:
            all_preds[target] = MODELS[target].predict(X).clip(min=0.0)

        median_series = all_preds.median(axis=0)
        output_record = {target: round(float(median_series[target]), 6) for target in TARGET_COLUMNS}

    prediction_df = pd.DataFrame([output_record], columns=TARGET_COLUMNS).fillna(0.0)
    return prediction_df


def start_prediction(download_url: str, upload_url: str):
    try:
        result = requests.get(download_url, timeout=30)
        result.raise_for_status()

        # Read input time-series CSV (comma-separated, US float format)
        input_data = pd.read_csv(io.StringIO(result.text), sep=",", decimal=".")

        prediction_data = run_model(input_data)

        assert len(prediction_data) == 1, "Prediction DataFrame must contain exactly 1 row"
        output_buffer = io.StringIO()
        prediction_data.to_csv(
            output_buffer,
            sep=",",
            decimal=".",
            header=True,
            index=False,
            float_format="%.6f",
        )
        output_buffer.seek(0)

        file = {"predictions": ("prediction.csv", output_buffer.getvalue(), "text/csv")}

        upload_res = requests.post(upload_url, files=file, timeout=30)
        upload_res.raise_for_status()
        print("Evaluation Result:", upload_res.json())

    except Exception as e:
        print("Error:", e)


@app.post("/predict", status_code=200)
async def prediction(payload: EvaluationBody, background_tasks: BackgroundTasks):
    background_tasks.add_task(
        start_prediction,
        payload.testdata_download_endpoint,
        payload.prediction_upload_endpoint,
    )
    return {"status": "prediction started"}


@app.get("/health", status_code=200)
async def health():
    return {"health": "up"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)