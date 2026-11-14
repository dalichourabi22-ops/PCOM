import pandas as pd
import numpy as np

TARGET_COLUMNS = [
    "target_ghsa_low_count_90d",
    "target_ghsa_moderate_count_90d",
    "target_ghsa_high_count_90d",
    "target_ghsa_critical_count_90d",
    "target_ghsa_unknown_count_90d",
]

NON_FEATURE_COLUMNS = ["purl", "package_created_at", "published_at"] + TARGET_COLUMNS


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transforms raw schema columns into model-ready features, including
    package age and M0-M11 velocity/momentum ratios.
    """
    data = df.copy()

    # 1. Package age at release date (in days)
    created = pd.to_datetime(data["package_created_at"], errors="coerce", utc=True)
    published = pd.to_datetime(data["published_at"], errors="coerce", utc=True)
    data["package_age_days"] = (published - created).dt.total_seconds() / 86400.0

    # 2. Download momentum (recent 3 months vs. 12-month baseline)
    dl_all = [f"package_downloads_M{i}" for i in range(12) if f"package_downloads_M{i}" in data.columns]
    dl_recent = [f"package_downloads_M{i}" for i in range(3) if f"package_downloads_M{i}" in data.columns]
    if dl_all and dl_recent:
        data["downloads_3m_avg"] = data[dl_recent].mean(axis=1)
        data["downloads_12m_avg"] = data[dl_all].mean(axis=1)
        data["download_momentum"] = data["downloads_3m_avg"] / (data["downloads_12m_avg"] + 1e-9)

    # 3. Release velocity momentum
    rel_all = [f"package_stable_release_count_M{i}" for i in range(12) if f"package_stable_release_count_M{i}" in data.columns]
    rel_recent = [f"package_stable_release_count_M{i}" for i in range(3) if f"package_stable_release_count_M{i}" in data.columns]
    if rel_all and rel_recent:
        data["releases_3m_avg"] = data[rel_recent].mean(axis=1)
        data["releases_12m_avg"] = data[rel_all].mean(axis=1)
        data["release_momentum"] = data["releases_3m_avg"] / (data["releases_12m_avg"] + 1e-9)

    # 4. Historical vulnerability totals & recent 3-month spike
    hist_total_cols = [
        c for c in ["ghsa_low_count", "ghsa_moderate_count", "ghsa_high_count", "ghsa_critical_count", "ghsa_unknown_count"]
        if c in data.columns
    ]
    if hist_total_cols:
        data["total_historical_ghsa"] = data[hist_total_cols].sum(axis=1)

    ghsa_recent_cols = [
        c for c in data.columns
        if c.startswith("ghsa_") and not c.startswith("target_") and any(c.endswith(f"_M{i}") for i in range(3))
    ]
    if ghsa_recent_cols:
        data["recent_vulnerability_count_3m"] = data[ghsa_recent_cols].sum(axis=1)

    # Drop identifier, raw timestamp, and target columns
    feature_cols = [c for c in data.columns if c not in NON_FEATURE_COLUMNS]
    return data[feature_cols].apply(pd.to_numeric, errors="coerce")