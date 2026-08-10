from pathlib import Path
import sys

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
GUI_DIR = ROOT / "gui"

sys.path.insert(0, str(GUI_DIR))

from core.triage_engine import run_triage


TEST_DATA = ROOT / "data/processed/huntlite_streamlit_test_samples.csv"

failures = []


def passed(message):
    print(f"PASS: {message}")


def failed(message):
    print(f"FAIL: {message}")
    failures.append(message)


print("HUNT-LITE Smoke Test")
print("=" * 30)


# 1. Confirm test dataset exists
if not TEST_DATA.is_file():
    failed(f"Missing test dataset: {TEST_DATA}")
else:
    passed("Test dataset found")


# 2. Load test dataset
df = None

if TEST_DATA.is_file():
    try:
        df = pd.read_csv(TEST_DATA)

        if df.empty:
            failed("Test dataset loaded but contains no records")
        else:
            passed(f"Loaded test dataset ({len(df)} records)")

    except Exception as exc:
        failed(f"Could not load test dataset: {exc}")


# 3. Run HUNT-LITE triage
result = None

if df is not None and not df.empty:
    try:
        result = run_triage(df)
        passed("ML triage pipeline completed")

    except Exception as exc:
        failed(f"ML triage pipeline failed: {exc}")


# 4. Validate expected triage output
if result is not None:
    required_keys = [
        "summary",
        "review_df",
        "alerts",
    ]

    missing_keys = [
        key for key in required_keys
        if key not in result
    ]

    if missing_keys:
        failed(
            f"Triage result missing expected keys: {missing_keys}"
        )
    else:
        passed("Triage result contains expected output sections")


# 5. Validate summary
if result is not None and "summary" in result:
    summary = result["summary"]

    expected_summary_keys = [
        "total_records",
        "flagged_records",
        "benign_count",
        "suspicious_count",
        "malicious_count",
        "top_predicted_label",
        "average_confidence",
    ]

    missing_summary_keys = [
        key for key in expected_summary_keys
        if key not in summary
    ]

    if missing_summary_keys:
        failed(
            f"Summary missing expected fields: {missing_summary_keys}"
        )
    else:
        passed("Triage summary contains expected fields")

        print()
        print("Smoke Test Triage Summary")
        print("-" * 30)
        print(f"Total records:      {summary['total_records']}")
        print(f"Flagged records:    {summary['flagged_records']}")
        print(f"Benign:             {summary['benign_count']}")
        print(f"Suspicious:         {summary['suspicious_count']}")
        print(f"Malicious:          {summary['malicious_count']}")
        print(f"Top prediction:     {summary['top_predicted_label']}")
        print(f"Average confidence: {summary['average_confidence']}")


# 6. Confirm records were scored
if result is not None and "summary" in result:
    if result["summary"].get("total_records") == len(df):
        passed("All input records were processed")
    else:
        failed(
            "Number of processed records does not match input dataset"
        )


# 7. Confirm review queue is usable
if result is not None and "review_df" in result:
    review_df = result["review_df"]

    if review_df is None:
        failed("Review queue was not returned")
    else:
        passed(
            f"Analyst review queue generated "
            f"({len(review_df)} records)"
        )


print()
print("=" * 30)

if failures:
    print(f"RESULT: FAIL ({len(failures)} problem(s) found)")
    sys.exit(1)

print("RESULT: PASS — HUNT-LITE core workflow smoke test completed")
