from __future__ import annotations
from pathlib import Path
import pandas as pd


def repo_root_from_gui() -> Path:
    return Path(__file__).resolve().parents[2]


def expected_feature_columns() -> list[str]:
    return [
        "protocol",
        "action",
        "log_type",
        "bytes_transferred",
        "user_agent",
        "request_path",
    ]


def ensure_required_columns(df: pd.DataFrame, required_cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    for col in required_cols:
        if col not in df.columns:
            if col == "bytes_transferred":
                df[col] = 0
            else:
                df[col] = ""
    return df


def clean_ml_input(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    object_cols = ["protocol", "action", "log_type", "user_agent", "request_path"]
    for col in object_cols:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)

    if "bytes_transferred" in df.columns:
        df["bytes_transferred"] = pd.to_numeric(
            df["bytes_transferred"], errors="coerce"
        ).fillna(0)

    return df
