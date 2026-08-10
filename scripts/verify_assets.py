from pathlib import Path
import csv
import hashlib
import json
import sys

import joblib
from tensorflow.keras.models import load_model


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_COLUMNS = [
    "protocol",
    "action",
    "log_type",
    "bytes_transferred",
    "user_agent",
    "request_path",
    "threat_label",
]

FULL_DATASET_SHA256 = (
    "6d1067ebefda43c30c52aabcf16b6eba4be86b8f14ae67f4b0f149a2ef98eedf"
)

failures = []


def passed(message):
    print(f"PASS: {message}")


def failed(message):
    print(f"FAIL: {message}")
    failures.append(message)


def require_file(relative_path):
    path = ROOT / relative_path

    if not path.is_file():
        failed(f"Missing file: {relative_path}")
        return None

    if path.stat().st_size == 0:
        failed(f"Empty file: {relative_path}")
        return None

    passed(f"Present: {relative_path}")
    return path


def check_csv(relative_path, expected_hash=None):
    path = require_file(relative_path)
    if path is None:
        return

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            header = next(csv.reader(fh))

        missing = [col for col in EXPECTED_COLUMNS if col not in header]
        unexpected = [col for col in header if col not in EXPECTED_COLUMNS]
        duplicates = sorted({col for col in header if header.count(col) > 1})

        if missing or unexpected or duplicates:
            failed(
                f"Invalid CSV schema in {relative_path}: "
                f"missing={missing}, unexpected={unexpected}, "
                f"duplicates={duplicates}"
            )
            return

        passed(f"Valid CSV schema: {relative_path}")

    except Exception as exc:
        failed(f"Could not parse CSV {relative_path}: {exc}")
        return

    if expected_hash:
        digest = hashlib.sha256()

        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)

        actual = digest.hexdigest()

        if actual == expected_hash:
            passed(f"SHA-256 matches: {relative_path}")
        else:
            failed(
                f"SHA-256 mismatch for {relative_path}\n"
                f"  Expected: {expected_hash}\n"
                f"  Actual:   {actual}"
            )


def check_json(relative_path):
    path = require_file(relative_path)
    if path is None:
        return

    try:
        with path.open("r", encoding="utf-8") as fh:
            json.load(fh)

        passed(f"Valid JSON: {relative_path}")

    except Exception as exc:
        failed(f"Invalid JSON {relative_path}: {exc}")


def check_joblib(relative_path):
    path = require_file(relative_path)
    if path is None:
        return

    try:
        joblib.load(path)
        passed(f"Loadable Joblib asset: {relative_path}")

    except Exception as exc:
        failed(f"Could not load {relative_path}: {exc}")


def check_model():
    relative_path = "models/huntlite_threat_detection_model.keras"
    path = require_file(relative_path)

    if path is None:
        return

    try:
        load_model(path, compile=False)
        passed(f"Loadable Keras model: {relative_path}")

    except Exception as exc:
        failed(f"Could not load Keras model: {exc}")


def check_notebook():
    relative_path = "notebooks/huntlite_full_training.ipynb"
    path = require_file(relative_path)

    if path is None:
        return

    try:
        with path.open("r", encoding="utf-8") as fh:
            notebook = json.load(fh)

        if "cells" not in notebook:
            raise ValueError("Notebook does not contain a cells field")

        passed(f"Valid notebook: {relative_path}")

    except Exception as exc:
        failed(f"Invalid notebook {relative_path}: {exc}")


print("HUNT-LITE Asset Verification")
print("=" * 30)

check_csv(
    "data/processed/huntlite_ml_dataset.csv",
    expected_hash=FULL_DATASET_SHA256,
)

check_csv(
    "data/processed/huntlite_streamlit_test_samples.csv"
)

check_model()

check_joblib("artifacts/preprocessor.joblib")
check_joblib("artifacts/label_encoder.joblib")

check_json("artifacts/feature_info.json")
check_json("artifacts/label_mapping.json")
check_json("artifacts/version_info.json")

check_notebook()

print("=" * 30)

if failures:
    print(f"RESULT: FAIL ({len(failures)} problem(s) found)")
    sys.exit(1)

print("RESULT: PASS — all required HUNT-LITE assets verified")
