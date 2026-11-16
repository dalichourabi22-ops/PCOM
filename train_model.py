import os
import joblib
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import mean_absolute_error, mean_poisson_deviance
from features import TARGET_COLUMNS, engineer_features

TRAINING_CSV = "training_data.csv"
MODEL_ARTIFACT_PATH = "models/xgb_vulnerability_models.joblib"


def build_model(base_score: float) -> xgb.XGBRegressor:
    return xgb.XGBRegressor(
        objective="count:poisson",
        n_estimators=1000,
        max_depth=4,
        learning_rate=0.04,
        subsample=0.8,
        colsample_bytree=0.8,
        base_score=base_score,
        random_state=42,
    )


def train_and_save_models():
    df = pd.read_csv(TRAINING_CSV)
    X = engineer_features(df)
    feature_columns = list(X.columns)

    # Extract package identifier without version (e.g., "pkg:npm/react@19.1.1" -> "pkg:npm/react")
    package_groups = df["purl"].astype(str).apply(lambda p: p.rsplit("@", 1)[0])

    # Group-aware 80/20 split by package (prevents version-level data leakage across train/test)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X, groups=package_groups))

    train_pkgs = sorted(package_groups.iloc[train_idx].unique())
    test_pkgs = sorted(package_groups.iloc[test_idx].unique())
    print(f"Train packages ({len(train_pkgs)}): {train_pkgs}")
    print(f"Test packages  ({len(test_pkgs)}): {test_pkgs}\n")

    models = {}
    for target in TARGET_COLUMNS:
        y = df[target].fillna(0).astype(float)

        # 1. Local evaluation on unseen packages (80% packages train / 20% packages test)
        X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
        X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

        val_model = build_model(max(float(y_train.mean()), 1e-5))
        val_model.fit(X_train, y_train)
        preds = val_model.predict(X_test)

        mae = mean_absolute_error(y_test, preds)
        mpd = mean_poisson_deviance(y_test, preds.clip(min=1e-9))
        print(f"[{target}] Group 80/20 Eval -> MAE: {mae:.4f} | Poisson Deviance: {mpd:.4f}")

        # 2. Train final production model on 100% of packages for live inference
        final_model = build_model(max(float(y.mean()), 1e-5))
        final_model.fit(X, y)
        models[target] = final_model

    os.makedirs(os.path.dirname(MODEL_ARTIFACT_PATH), exist_ok=True)
    joblib.dump({"models": models, "feature_columns": feature_columns}, MODEL_ARTIFACT_PATH)
    print(f"\nSaved final 100%-trained models to {MODEL_ARTIFACT_PATH}")


if __name__ == "__main__":
    train_and_save_models()