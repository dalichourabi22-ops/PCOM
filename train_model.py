import os
import joblib
import pandas as pd
import xgboost as xgb
from features import TARGET_COLUMNS, engineer_features

TRAINING_CSV = "initial_training_data.csv"
MODEL_ARTIFACT_PATH = "models/xgb_vulnerability_models.joblib"


def train_and_save_models():
    df = pd.read_csv(TRAINING_CSV)
    X = engineer_features(df)
    feature_columns = list(X.columns)

    models = {}
    for target in TARGET_COLUMNS:
        y = df[target].fillna(0).astype(float)

        # Ensure base_score > 0 so count:poisson never fails even if a target is all zeros
        init_base_score = max(float(y.mean()), 1e-5)

        model = xgb.XGBRegressor(
            objective="count:poisson",
            n_estimators=100,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            base_score=init_base_score,
            random_state=42,
        )
        model.fit(X, y)
        models[target] = model
        print(f"Trained model for {target} (mean target={y.mean():.4f})")

    os.makedirs(os.path.dirname(MODEL_ARTIFACT_PATH), exist_ok=True)
    joblib.dump({"models": models, "feature_columns": feature_columns}, MODEL_ARTIFACT_PATH)
    print(f"\nSaved all models to {MODEL_ARTIFACT_PATH}")


if __name__ == "__main__":
    train_and_save_models()