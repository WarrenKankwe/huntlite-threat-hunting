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


def ensure_required_columns(
    df: pd.DataFrame,
    required_cols: list[str],
) -> pd.DataFrame:
    missing_cols = [
        col
        for col in required_cols
        if col not in df.columns
    ]

    if missing_cols:
        raise ValueError(
            "Missing required HUNT-LITE model input columns: "
            + ", ".join(missing_cols)
        )

    return df.copy()


def clean_ml_input(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    object_cols = [
        "protocol",
        "action",
        "log_type",
        "user_agent",
        "request_path",
    ]

    for col in object_cols:
        if col not in df.columns:
            continue

        if df[col].isna().any():
            raise ValueError(
                f"Required model field '{col}' contains missing values."
            )

        cleaned = df[col].astype(str).str.strip()

        if cleaned.eq("").any():
            raise ValueError(
                f"Required model field '{col}' contains blank values."
            )

        df[col] = cleaned

    if "bytes_transferred" in df.columns:
        numeric = pd.to_numeric(
            df["bytes_transferred"],
            errors="coerce",
        )

        if numeric.isna().any():
            raise ValueError(
                "Required model field 'bytes_transferred' "
                "contains missing or non-numeric values."
            )

        if (numeric < 0).any():
            raise ValueError(
                "Required model field 'bytes_transferred' "
                "contains negative values."
            )

        df["bytes_transferred"] = numeric

    return df
