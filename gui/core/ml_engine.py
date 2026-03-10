from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import streamlit as st
from tensorflow.keras.models import load_model

from .utils import repo_root_from_gui, ensure_required_columns, clean_ml_input


EXPECTED_SKLEARN = "1.6.1"


@dataclass
class HuntLiteAssets:
    feature_info: dict
    label_mapping: dict
    preprocessor: object
    model: object


def _artifacts_dir() -> Path:
    return repo_root_from_gui() / "artifacts"


def _models_dir() -> Path:
    return repo_root_from_gui() / "models"


@st.cache_resource
def load_assets() -> HuntLiteAssets:
    artifacts_dir = _artifacts_dir()
    models_dir = _models_dir()

    if sklearn.__version__ != EXPECTED_SKLEARN:
        raise RuntimeError(
            f"HUNT-LITE requires scikit-learn {EXPECTED_SKLEARN}, "
            f"but {sklearn.__version__} is installed. "
            f"Please install the correct version with:\n"
            f"pip install scikit-learn=={EXPECTED_SKLEARN}"
        )

    with open(artifacts_dir / "feature_info.json", "r", encoding="utf-8") as f:
        feature_info = json.load(f)

    with open(artifacts_dir / "label_mapping.json", "r", encoding="utf-8") as f:
        raw_mapping = json.load(f)

    label_mapping = {int(k): v for k, v in raw_mapping.items()}

    try:
        preprocessor = joblib.load(artifacts_dir / "preprocessor.joblib")
    except Exception as e:
        raise RuntimeError(
            "Failed to load preprocessor.joblib. "
            "This usually means the local scikit-learn version does not match "
            "the version used during training. "
            f"Expected scikit-learn=={EXPECTED_SKLEARN}."
        ) from e

    try:
        model = load_model(models_dir / "huntlite_threat_detection_model.keras")
    except Exception as e:
        raise RuntimeError(
            "Failed to load the Keras model file "
            "'models/huntlite_threat_detection_model.keras'."
        ) from e

    return HuntLiteAssets(
        feature_info=feature_info,
        label_mapping=label_mapping,
        preprocessor=preprocessor,
        model=model,
    )


def prepare_features(df: pd.DataFrame, feature_info: dict) -> pd.DataFrame:
    numeric_cols = feature_info.get("numeric_cols", [])
    categorical_cols = feature_info.get("categorical_cols", [])
    expected_cols = numeric_cols + categorical_cols

    df = ensure_required_columns(df, expected_cols)
    df = clean_ml_input(df)

    X = df[expected_cols].copy()
    return X


def score_dataframe(df: pd.DataFrame, assets: HuntLiteAssets) -> pd.DataFrame:
    df = df.copy()

    X = prepare_features(df, assets.feature_info)
    X_transformed = assets.preprocessor.transform(X)

    if hasattr(X_transformed, "toarray"):
        X_transformed = X_transformed.toarray()

    probabilities = assets.model.predict(X_transformed, verbose=0)
    predicted_idx = np.argmax(probabilities, axis=1)
    predicted_conf = probabilities.max(axis=1)

    scored_df = df.copy()
    scored_df["predicted_label"] = [assets.label_mapping[int(i)] for i in predicted_idx]
    scored_df["predicted_confidence"] = predicted_conf.round(4)

    for idx, label in sorted(assets.label_mapping.items()):
        scored_df[f"prob_{label}"] = probabilities[:, idx].round(4)

    return scored_df