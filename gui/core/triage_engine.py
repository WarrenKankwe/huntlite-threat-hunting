from __future__ import annotations
import pandas as pd

from .ml_engine import load_assets, score_dataframe


def assign_severity(predicted_label: str, confidence: float) -> str:
    label = str(predicted_label).lower()

    if label == "malicious":
        if confidence >= 0.90:
            return "Critical"
        if confidence >= 0.75:
            return "High"
        return "Medium"

    if label == "suspicious":
        if confidence >= 0.85:
            return "High"
        if confidence >= 0.60:
            return "Medium"
        return "Low"

    return "Informational"


def add_triage_columns(scored_df: pd.DataFrame) -> pd.DataFrame:
    df = scored_df.copy()

    df["severity"] = df.apply(
        lambda row: assign_severity(
            row["predicted_label"], float(row["predicted_confidence"])
        ),
        axis=1,
    )

    df["needs_review"] = df["severity"].isin(["Critical", "High", "Medium"])
    df["triage_reason"] = df.apply(_triage_reason, axis=1)

    return df


def _triage_reason(row: pd.Series) -> str:
    label = str(row.get("predicted_label", "unknown"))
    conf = float(row.get("predicted_confidence", 0.0))
    severity = str(row.get("severity", "Unknown"))
    action = str(row.get("action", ""))
    path = str(row.get("request_path", ""))
    ua = str(row.get("user_agent", ""))

    highlights = [
        f"Model predicted '{label}' with {conf:.2%} confidence.",
        f"Severity assigned: {severity}.",
    ]

    if action.lower() == "blocked":
        highlights.append("Traffic was blocked, which may indicate control action already occurred.")
    elif action.lower() == "allowed":
        highlights.append("Traffic was allowed, so analyst validation is important.")

    if ".." in path or "passwd" in path.lower():
        highlights.append("Request path contains traversal-style or sensitive-file access pattern.")

    if "nmap" in ua.lower():
        highlights.append("User agent suggests reconnaissance/scanning behavior.")

    if "curl" in ua.lower():
        highlights.append("User agent may indicate scripted or automated access.")

    return " ".join(highlights)


def build_summary(df: pd.DataFrame) -> dict:
    total = len(df)
    benign_count = int((df["predicted_label"] == "benign").sum())
    suspicious_count = int((df["predicted_label"] == "suspicious").sum())
    malicious_count = int((df["predicted_label"] == "malicious").sum())

    critical_count = int((df["severity"] == "Critical").sum())
    high_count = int((df["severity"] == "High").sum())
    medium_count = int((df["severity"] == "Medium").sum())

    flagged_count = int(df["needs_review"].sum())

    if total > 0:
        top_threat = df["predicted_label"].value_counts().idxmax()
        avg_conf = float(df["predicted_confidence"].mean())
    else:
        top_threat = "n/a"
        avg_conf = 0.0

    return {
        "total_records": total,
        "flagged_records": flagged_count,
        "benign_count": benign_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "top_predicted_label": top_threat,
        "average_confidence": round(avg_conf, 4),
    }


def run_triage(df: pd.DataFrame) -> dict:
    if df is None or df.empty:
        return {
            "summary": {},
            "alerts": ["No data loaded."],
            "steps": ["Load a processed CSV dataset to begin ML triage."],
            "scored_df": pd.DataFrame(),
            "review_df": pd.DataFrame(),
        }

    assets = load_assets()
    scored_df = score_dataframe(df, assets)
    triaged_df = add_triage_columns(scored_df)

    review_df = triaged_df[triaged_df["needs_review"]].copy()
    review_df = review_df.sort_values(
        by=["predicted_confidence", "predicted_label"],
        ascending=[False, True],
    )

    summary = build_summary(triaged_df)

    alerts = [
        f"Scored {summary['total_records']} records using the trained Keras model.",
        f"Flagged {summary['flagged_records']} records for analyst review.",
        f"Top predicted class: {summary['top_predicted_label']}.",
        f"Critical: {summary['critical_count']} | High: {summary['high_count']} | Medium: {summary['medium_count']}.",
    ]

    steps = [
        "Loaded trained model and preprocessing artifacts.",
        "Validated and aligned dataset fields to the ML feature schema.",
        "Generated class probabilities and predicted labels.",
        "Assigned SOC-style severity based on label and confidence.",
        "Built analyst review queue for suspicious and malicious records.",
    ]

    return {
        "summary": summary,
        "alerts": alerts,
        "steps": steps,
        "scored_df": triaged_df,
        "review_df": review_df,
    }
