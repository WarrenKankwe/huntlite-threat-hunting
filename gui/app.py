import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import pandas as pd
import streamlit as st

from core.utils import repo_root_from_gui
from core.triage_engine import run_triage
from core.ai_coach import ai_explain
from core.report_engine import build_record_report, build_case_summary

st.set_page_config(page_title="HUNT-LITE", layout="wide")

st.title("HUNT-LITE: ML-Powered SOC Triage Assistant")
st.caption(
    "Load processed security records, classify them with the trained Keras model, "
    "triage suspicious activity, and generate beginner-friendly analyst guidance."
)

REPO_ROOT = repo_root_from_gui()
DATA_PROCESSED = REPO_ROOT / "data" / "processed"

DEFAULT_SAMPLE = DATA_PROCESSED / "huntlite_streamlit_test_samples.csv"
DEFAULT_FULL = DATA_PROCESSED / "huntlite_ml_dataset.csv"

with st.sidebar:
    st.header("Controls")

    data_option = st.radio(
        "Data source",
        [
            "Use test sample CSV",
            "Use processed full CSV",
            "Upload CSV",
        ],
    )

    confidence_threshold = st.slider(
        "Minimum confidence for review queue",
        min_value=0.00,
        max_value=1.00,
        value=0.60,
        step=0.01,
    )

    max_display_rows = st.slider(
        "Max rows to display",
        min_value=10,
        max_value=500,
        value=100,
        step=10,
    )

    uploaded = None
    if data_option == "Upload CSV":
        uploaded = st.file_uploader("Upload processed CSV", type=["csv"])

st.divider()

df = pd.DataFrame()
source_label = ""

try:
    if data_option == "Use test sample CSV":
        df = pd.read_csv(DEFAULT_SAMPLE)
        source_label = str(DEFAULT_SAMPLE)
    elif data_option == "Use processed full CSV":
        df = pd.read_csv(DEFAULT_FULL)
        source_label = str(DEFAULT_FULL)
    elif uploaded is not None:
        df = pd.read_csv(uploaded)
        source_label = uploaded.name
except Exception as e:
    st.error(f"Failed to load dataset: {type(e).__name__}: {e}")

st.subheader("Dataset Preview")
st.write(f"**Source:** {source_label or 'No source selected'}")

if df.empty:
    st.info("Load a processed CSV to begin.")
else:
    st.write(f"Rows: {len(df)} | Columns: {len(df.columns)}")
    st.dataframe(df.head(min(max_display_rows, len(df))), use_container_width=True)

st.divider()

st.subheader("Run ML Triage")
run_btn = st.button("Run HUNT-LITE ML Triage", type="primary", use_container_width=True)

if "triage_results" not in st.session_state:
    st.session_state.triage_results = None

if run_btn:
    if df.empty:
        st.warning("No data loaded yet.")
    else:
        st.session_state.triage_results = run_triage(df)

results = st.session_state.triage_results

if results:
    summary = results["summary"]
    scored_df = results["scored_df"]
    review_df = results["review_df"].copy()

    if not review_df.empty:
        review_df = review_df[
            review_df["predicted_confidence"] >= confidence_threshold
        ].copy()

    st.subheader("SOC Triage Dashboard")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", summary.get("total_records", 0))
    c2.metric("Flagged for Review", len(review_df))
    c3.metric("Top Predicted Threat", summary.get("top_predicted_label", "n/a"))
    c4.metric("Avg Confidence", f"{summary.get('average_confidence', 0):.2%}")

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Benign", summary.get("benign_count", 0))
    c6.metric("Suspicious", summary.get("suspicious_count", 0))
    c7.metric("Malicious", summary.get("malicious_count", 0))
    c8.metric(
        "Critical / High",
        summary.get("critical_count", 0) + summary.get("high_count", 0),
    )

    st.markdown("### Alerts")
    for alert in results["alerts"]:
        st.warning(alert)

    st.markdown("### Workflow Steps")
    for step in results["steps"]:
        st.write(f"- {step}")

    st.divider()

    st.subheader("Analyst Review Queue")
    if review_df.empty:
        st.success("No records met the current review threshold.")
    else:
        display_cols = [
            "protocol",
            "action",
            "log_type",
            "bytes_transferred",
            "user_agent",
            "request_path",
            "predicted_label",
            "predicted_confidence",
            "severity",
            "triage_reason",
        ]
        existing_cols = [c for c in display_cols if c in review_df.columns]
        st.dataframe(
            review_df[existing_cols].head(max_display_rows),
            use_container_width=True,
        )

        st.divider()
        st.subheader("Record Detail Explorer")

        review_indices = review_df.index.tolist()
        selected_index = st.selectbox(
            "Choose a flagged row index",
            review_indices,
        )

        selected_row = review_df.loc[selected_index]

        st.markdown("### Selected Record")
        st.json(selected_row.to_dict())

        st.markdown("### Analyst Note / Incident Draft")
        st.code(build_record_report(selected_row), language="markdown")

        st.markdown("### Case Summary")
        st.code(build_case_summary(summary), language="markdown")

        st.divider()
        st.subheader("AI Coach")

        a1, a2, a3, a4, a5 = st.columns(5)

        if "ai_text" not in st.session_state:
            st.session_state.ai_text = ""

        with a1:
            if st.button("Explain Record"):
                st.session_state.ai_text = ai_explain(
                    selected_row, summary, mode="explain_record"
                )
        with a2:
            if st.button("Triage Decision"):
                st.session_state.ai_text = ai_explain(
                    selected_row, summary, mode="triage_decision"
                )
        with a3:
            if st.button("Next Steps"):
                st.session_state.ai_text = ai_explain(
                    selected_row, summary, mode="next_steps"
                )
        with a4:
            if st.button("Incident Summary"):
                st.session_state.ai_text = ai_explain(
                    selected_row, summary, mode="incident_summary"
                )
        with a5:
            if st.button("Executive Summary"):
                st.session_state.ai_text = ai_explain(
                    selected_row, summary, mode="executive_summary"
                )

        st.markdown("### AI Coach Output")
        st.write(
            st.session_state.ai_text
            or "Select a flagged row and click a coaching button."
        )
else:
    st.info("Run the ML triage workflow to see results.")
