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
from core.schema_mapper import (
    MODEL_FIELDS,
    build_mapped_dataframe,
    suggest_byte_pair,
    suggest_mapping,
    validate_mapping,
)


st.set_page_config(
    page_title="HUNT-LITE",
    layout="wide",
)

st.title("HUNT-LITE: ML-Powered SOC Triage Assistant")

st.caption(
    "Load security records, map compatible external datasets into the "
    "HUNT-LITE schema, classify them with the trained Keras model, "
    "triage suspicious activity, and generate beginner-friendly "
    "analyst guidance."
)


REPO_ROOT = repo_root_from_gui()
DATA_PROCESSED = REPO_ROOT / "data" / "processed"

DEFAULT_SAMPLE = (
    DATA_PROCESSED
    / "huntlite_streamlit_test_samples.csv"
)

DEFAULT_FULL = (
    DATA_PROCESSED
    / "huntlite_ml_dataset.csv"
)


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
        uploaded = st.file_uploader(
            "Upload external security CSV",
            type=["csv"],
            help=(
                "External datasets must resolve all six "
                "HUNT-LITE model fields before ML triage "
                "can run."
            ),
        )


st.divider()


df = pd.DataFrame()
triage_df = pd.DataFrame()
source_label = ""

mapping_ready = (
    data_option != "Upload CSV"
)

mapping_validation = None


try:
    if data_option == "Use test sample CSV":
        df = pd.read_csv(DEFAULT_SAMPLE)
        triage_df = df.copy()
        source_label = str(DEFAULT_SAMPLE)

    elif data_option == "Use processed full CSV":
        df = pd.read_csv(DEFAULT_FULL)
        triage_df = df.copy()
        source_label = str(DEFAULT_FULL)

    elif uploaded is not None:
        df = pd.read_csv(uploaded)
        source_label = uploaded.name

except Exception:
    st.error(
        "Failed to load dataset. Verify that the file is a valid, "
        "readable CSV and try again."
    )


st.subheader("Dataset Preview")

st.write(
    f"**Source:** "
    f"{source_label or 'No source selected'}"
)

if df.empty:
    if data_option == "Upload CSV":
        st.info(
            "Upload an external security CSV to begin."
        )
    else:
        st.info(
            "Load a processed CSV to begin."
        )

else:
    st.write(
        f"Rows: {len(df)} | "
        f"Columns: {len(df.columns)}"
    )

    st.dataframe(
        df.head(
            min(
                max_display_rows,
                len(df),
            )
        ),
        use_container_width=True,
    )


# ---------------------------------------------------------
# External Dataset Schema Mapper
# ---------------------------------------------------------

if (
    data_option == "Upload CSV"
    and not df.empty
):
    st.divider()

    st.subheader(
        "External Dataset Schema Mapper"
    )

    st.write(
        "Map the external dataset into the six fields required "
        "by the existing HUNT-LITE ML model."
    )

    st.info(
        "ML triage is enabled only when all 6/6 HUNT-LITE "
        "model fields are explicitly resolved and validated. "
        "A field may be directly mapped or safely derived."
    )

    st.caption(
        "Automatic suggestions are based on known column aliases. "
        "Review each suggestion before running triage."
    )

    suggestions = suggest_mapping(
        df.columns
    )

    suggested_sent, suggested_received = (
        suggest_byte_pair(
            df.columns
        )
    )

    source_columns = list(
        df.columns
    )

    column_options = [
        "-- Not mapped --"
    ] + source_columns

    def selection_index(
        suggested_column,
    ):
        if (
            suggested_column
            and suggested_column
            in source_columns
        ):
            return column_options.index(
                suggested_column
            )

        return 0

    mapping = {}

    st.markdown(
        "### Required Field Mapping"
    )

    left, right = st.columns(2)

    with left:
        selected_protocol = st.selectbox(
            "protocol",
            column_options,
            index=selection_index(
                suggestions.get(
                    "protocol"
                )
            ),
            help=(
                "Examples: protocol, proto, "
                "network_protocol, transport_protocol."
            ),
        )

        mapping["protocol"] = (
            None
            if selected_protocol
            == "-- Not mapped --"
            else selected_protocol
        )

        selected_action = st.selectbox(
            "action",
            column_options,
            index=selection_index(
                suggestions.get(
                    "action"
                )
            ),
            help=(
                "This must represent event or traffic disposition. "
                "Examples include allowed, blocked, permit, deny, "
                "drop, or reject."
            ),
        )

        mapping["action"] = (
            None
            if selected_action
            == "-- Not mapped --"
            else selected_action
        )

        selected_log_type = st.selectbox(
            "log_type",
            column_options,
            index=selection_index(
                suggestions.get(
                    "log_type"
                )
            ),
            help=(
                "Examples include log type, event source, "
                "sensor, device type, or detection system."
            ),
        )

        mapping["log_type"] = (
            None
            if selected_log_type
            == "-- Not mapped --"
            else selected_log_type
        )

    with right:
        selected_user_agent = st.selectbox(
            "user_agent",
            column_options,
            index=selection_index(
                suggestions.get(
                    "user_agent"
                )
            ),
            help=(
                "Examples include user_agent, "
                "http_user_agent, client_agent, or ua."
            ),
        )

        mapping["user_agent"] = (
            None
            if selected_user_agent
            == "-- Not mapped --"
            else selected_user_agent
        )

        selected_request_path = st.selectbox(
            "request_path",
            column_options,
            index=selection_index(
                suggestions.get(
                    "request_path"
                )
            ),
            help=(
                "Examples include request_path, URI, URL, "
                "path, endpoint, or resource. Full HTTP/HTTPS "
                "URLs can be reduced to path and query."
            ),
        )

        mapping["request_path"] = (
            None
            if selected_request_path
            == "-- Not mapped --"
            else selected_request_path
        )

    st.markdown(
        "### bytes_transferred"
    )

    direct_bytes = suggestions.get(
        "bytes_transferred"
    )

    can_derive_bytes = bool(
        suggested_sent
        and suggested_received
    )

    if (
        direct_bytes is None
        and can_derive_bytes
    ):
        default_byte_mode = 1
    else:
        default_byte_mode = 0

    byte_mode = st.radio(
        "How should bytes_transferred be resolved?",
        [
            "Map one source column",
            "Derive from sent + received columns",
        ],
        index=default_byte_mode,
        horizontal=True,
    )

    bytes_sent_column = None
    bytes_received_column = None

    if (
        byte_mode
        == "Map one source column"
    ):
        selected_bytes = st.selectbox(
            "bytes_transferred source",
            column_options,
            index=selection_index(
                direct_bytes
            ),
        )

        mapping[
            "bytes_transferred"
        ] = (
            None
            if selected_bytes
            == "-- Not mapped --"
            else selected_bytes
        )

    else:
        mapping[
            "bytes_transferred"
        ] = None

        b1, b2 = st.columns(2)

        with b1:
            selected_sent = (
                st.selectbox(
                    "Bytes sent column",
                    column_options,
                    index=selection_index(
                        suggested_sent
                    ),
                )
            )

            if (
                selected_sent
                != "-- Not mapped --"
            ):
                bytes_sent_column = (
                    selected_sent
                )

        with b2:
            selected_received = (
                st.selectbox(
                    "Bytes received column",
                    column_options,
                    index=selection_index(
                        suggested_received
                    ),
                )
            )

            if (
                selected_received
                != "-- Not mapped --"
            ):
                bytes_received_column = (
                    selected_received
                )

    # -----------------------------------------------------
    # Explicit 6/6 mapping gate
    # -----------------------------------------------------

    explicitly_resolved = {
        "protocol": bool(
            mapping.get(
                "protocol"
            )
        ),
        "action": bool(
            mapping.get(
                "action"
            )
        ),
        "log_type": bool(
            mapping.get(
                "log_type"
            )
        ),
        "user_agent": bool(
            mapping.get(
                "user_agent"
            )
        ),
        "request_path": bool(
            mapping.get(
                "request_path"
            )
        ),
        "bytes_transferred": (
            bool(
                mapping.get(
                    "bytes_transferred"
                )
            )
            if (
                byte_mode
                == "Map one source column"
            )
            else bool(
                bytes_sent_column
                and bytes_received_column
            )
        ),
    }

    resolved_count = sum(
        explicitly_resolved.values()
    )

    unresolved_fields = [
        field
        for field, resolved
        in explicitly_resolved.items()
        if not resolved
    ]

    # Prevent accidental reuse of one source column
    # for different semantic model fields.
    source_usage = []

    for field in [
        "protocol",
        "action",
        "log_type",
        "user_agent",
        "request_path",
    ]:
        source_column = mapping.get(
            field
        )

        if source_column:
            source_usage.append(
                source_column
            )

    if (
        byte_mode
        == "Map one source column"
    ):
        if mapping.get(
            "bytes_transferred"
        ):
            source_usage.append(
                mapping[
                    "bytes_transferred"
                ]
            )

    else:
        if bytes_sent_column:
            source_usage.append(
                bytes_sent_column
            )

        if bytes_received_column:
            source_usage.append(
                bytes_received_column
            )

    duplicate_columns = sorted(
        {
            column
            for column
            in source_usage
            if source_usage.count(
                column
            ) > 1
        }
    )

    mapped_df = pd.DataFrame()

    try:
        mapped_df = (
            build_mapped_dataframe(
                source_df=df,
                mapping=mapping,
                bytes_sent_column=(
                    bytes_sent_column
                ),
                bytes_received_column=(
                    bytes_received_column
                ),
            )
        )

        mapping_validation = (
            validate_mapping(
                mapped_df
            )
        )

    except Exception:
        mapping_validation = {
            "ready": False,
            "resolved_count": (
                resolved_count
            ),
            "total_fields": len(
                MODEL_FIELDS
            ),
            "missing_fields": (
                unresolved_fields
            ),
            "errors": [
                "Schema mapping could not be validated. Review the selected "
                "field mappings and data values, then try again."
            ],
            "warnings": [],
        }

    if mapping_validation is None:
        mapping_validation = {
            "ready": False,
            "resolved_count": (
                resolved_count
            ),
            "total_fields": len(
                MODEL_FIELDS
            ),
            "missing_fields": (
                unresolved_fields
            ),
            "errors": [],
            "warnings": [],
        }

    # The mapper must use explicit mappings.
    mapping_validation[
        "resolved_count"
    ] = resolved_count

    mapping_validation[
        "missing_fields"
    ] = unresolved_fields

    if unresolved_fields:
        mapping_validation[
            "errors"
        ].append(
            "Unresolved HUNT-LITE fields: "
            + ", ".join(
                unresolved_fields
            )
        )

    if duplicate_columns:
        mapping_validation[
            "errors"
        ].append(
            "A source column cannot be reused for "
            "multiple HUNT-LITE fields: "
            + ", ".join(
                duplicate_columns
            )
        )

    mapping_ready = (
        resolved_count
        == len(MODEL_FIELDS)
        and not duplicate_columns
        and len(
            mapping_validation[
                "errors"
            ]
        )
        == 0
    )

    mapping_validation[
        "ready"
    ] = mapping_ready

    # -----------------------------------------------------
    # Mapping summary
    # -----------------------------------------------------

    mapping_rows = []

    for field in MODEL_FIELDS:
        if (
            field
            == "bytes_transferred"
            and byte_mode
            == "Derive from sent + received columns"
        ):
            if (
                bytes_sent_column
                and bytes_received_column
            ):
                source_description = (
                    f"{bytes_sent_column} + "
                    f"{bytes_received_column}"
                )

                method = "Derived"

            else:
                source_description = (
                    "Not mapped"
                )

                method = "Missing"

        else:
            source_column = mapping.get(
                field
            )

            if source_column:
                source_description = (
                    source_column
                )

                method = "Direct"

            else:
                source_description = (
                    "Not mapped"
                )

                method = "Missing"

        mapping_rows.append(
            {
                "HUNT-LITE field": (
                    field
                ),
                "Source": (
                    source_description
                ),
                "Method": method,
            }
        )

    st.markdown(
        "### Mapping Summary"
    )

    st.dataframe(
        pd.DataFrame(
            mapping_rows
        ),
        use_container_width=True,
        hide_index=True,
    )

    status_left, status_right = (
        st.columns(2)
    )

    status_left.metric(
        "Resolved Model Fields",
        f"{resolved_count}/"
        f"{len(MODEL_FIELDS)}",
    )

    status_right.metric(
        "ML Triage Status",
        (
            "Enabled"
            if mapping_ready
            else "Blocked"
        ),
    )

    for warning in (
        mapping_validation.get(
            "warnings",
            []
        )
    ):
        st.warning(
            warning
        )

    for error in (
        mapping_validation.get(
            "errors",
            []
        )
    ):
        st.error(
            error
        )

    canonical_preview_fields = [
        field
        for field in MODEL_FIELDS
        if (
            field
            in mapped_df.columns
            and explicitly_resolved.get(
                field,
                False,
            )
        )
    ]

    if canonical_preview_fields:
        st.markdown(
            "### Normalized HUNT-LITE Preview"
        )

        st.caption(
            "This preview shows the canonical fields "
            "prepared for the trained model. The original "
            "external columns remain preserved for analyst "
            "context and later evaluation."
        )

        st.dataframe(
            mapped_df[
                canonical_preview_fields
            ].head(
                min(
                    10,
                    len(mapped_df),
                )
            ),
            use_container_width=True,
        )

    if mapping_ready:
        triage_df = (
            mapped_df.copy()
        )

        st.success(
            "Schema validation passed: "
            "6/6 HUNT-LITE model fields are "
            "resolved and validated. "
            "ML triage is enabled."
        )

    else:
        triage_df = pd.DataFrame()

        st.warning(
            "ML triage is blocked until all six "
            "HUNT-LITE model fields are resolved "
            "and validation passes."
        )


st.divider()

st.subheader("Run ML Triage")


if (
    "triage_results"
    not in st.session_state
):
    st.session_state.triage_results = (
        None
    )


run_disabled = (
    data_option == "Upload CSV"
    and uploaded is not None
    and not mapping_ready
)

run_btn = st.button(
    "Run HUNT-LITE ML Triage",
    type="primary",
    use_container_width=True,
    disabled=run_disabled,
)


if run_disabled:
    st.caption(
        "Resolve and validate all 6/6 "
        "model fields to enable ML triage."
    )


if run_btn:
    if df.empty:
        st.warning(
            "No data loaded yet."
        )

    elif (
        data_option == "Upload CSV"
        and not mapping_ready
    ):
        st.warning(
            "External dataset schema validation "
            "has not passed."
        )

    else:
        try:
            input_df = (
                triage_df
                if data_option
                == "Upload CSV"
                else df
            )

            st.session_state.triage_results = (
                run_triage(
                    input_df
                )
            )

        except Exception:
            st.session_state.triage_results = (
                None
            )

            st.error(
                "ML triage could not process this dataset. Verify the mapped "
            "fields and data values, then try again."
            )


results = (
    st.session_state.triage_results
)

# Do not display stale previous results while an
# external dataset currently fails the mapping gate.
if (
    data_option == "Upload CSV"
    and uploaded is not None
    and not mapping_ready
):
    results = None


if results:
    summary = results["summary"]
    scored_df = results["scored_df"]
    review_df = results["review_df"].copy()

    if not review_df.empty:
        review_df = review_df[
            review_df["predicted_confidence"]
            >= confidence_threshold
        ].copy()

    st.subheader("SOC Triage Dashboard")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total Records",
        summary.get(
            "total_records",
            0,
        ),
    )

    c2.metric(
        "Flagged for Review",
        len(review_df),
    )

    c3.metric(
        "Top Predicted Threat",
        summary.get(
            "top_predicted_label",
            "n/a",
        ),
    )

    c4.metric(
        "Avg Confidence",
        f"{summary.get('average_confidence', 0):.2%}",
    )

    c5, c6, c7, c8 = st.columns(4)

    c5.metric(
        "Benign",
        summary.get(
            "benign_count",
            0,
        ),
    )

    c6.metric(
        "Suspicious",
        summary.get(
            "suspicious_count",
            0,
        ),
    )

    c7.metric(
        "Malicious",
        summary.get(
            "malicious_count",
            0,
        ),
    )

    c8.metric(
        "Critical / High",
        (
            summary.get(
                "critical_count",
                0,
            )
            + summary.get(
                "high_count",
                0,
            )
        ),
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
        st.success(
            "No records met the current "
            "review threshold."
        )

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

        existing_cols = [
            column
            for column in display_cols
            if column in review_df.columns
        ]

        st.dataframe(
            review_df[
                existing_cols
            ].head(max_display_rows),
            use_container_width=True,
        )

        st.divider()
        st.subheader("Record Detail Explorer")

        review_indices = (
            review_df.index.tolist()
        )

        selected_index = st.selectbox(
            "Choose a flagged row index",
            review_indices,
        )

        selected_row = review_df.loc[
            selected_index
        ]

        st.markdown("### Selected Record")

        st.json(
            selected_row.to_dict()
        )

        st.markdown(
            "### Analyst Note / Incident Draft"
        )

        st.code(
            build_record_report(
                selected_row
            ),
            language="markdown",
        )

        st.markdown("### Case Summary")

        st.code(
            build_case_summary(
                summary
            ),
            language="markdown",
        )

        st.divider()
        st.subheader("AI Coach")

        coach_choice = st.radio(
            "Choose AI Coach mode",
            [
                "Local Coach",
                "OpenAI Coach",
            ],
            horizontal=True,
            help=(
                "Local Coach requires no external AI. "
                "OpenAI Coach uses an OpenAI API key "
                "for enhanced guidance."
            ),
        )

        coach_mode = "local"
        session_api_key = None

        if coach_choice == "Local Coach":
            st.caption(
                "Local Coach uses deterministic "
                "HUNT-LITE guidance. No API key or "
                "external AI service is required."
            )

        else:
            coach_mode = "openai"

            st.caption(
                "OpenAI Coach uses your own OpenAI "
                "API key. Paste a key for this running "
                "session, or leave the field blank to "
                "use OPENAI_API_KEY if it is already "
                "configured locally."
            )

            session_api_key = st.text_input(
                "OpenAI API Key",
                type="password",
                placeholder="Paste your OpenAI API key",
                help=(
                    "The pasted key is passed directly "
                    "to the OpenAI client for this "
                    "running HUNT-LITE session. "
                    "HUNT-LITE does not write the key "
                    "to a project file."
                ),
            )

        if "ai_text" not in st.session_state:
            st.session_state.ai_text = ""

        if "ai_status" not in st.session_state:
            st.session_state.ai_status = "none"

        if "ai_key_source" not in st.session_state:
            st.session_state.ai_key_source = "none"

        def run_ai_coach(action_mode):
            output = ai_explain(
                selected_row=selected_row,
                summary=summary,
                mode=action_mode,
                coach_mode=coach_mode,
                provider="openai",
                api_key=session_api_key,
            )

            st.session_state.ai_text = output

            if output.startswith(
                "OpenAI Coach unavailable:"
            ):
                st.session_state.ai_status = (
                    "fallback"
                )
                st.session_state.ai_key_source = (
                    "none"
                )

            elif output.startswith(
                "AI Coach Mode: OpenAI Coach"
            ):
                st.session_state.ai_status = (
                    "openai"
                )

                if (
                    session_api_key
                    and session_api_key.strip()
                ):
                    st.session_state.ai_key_source = (
                        "session"
                    )
                else:
                    st.session_state.ai_key_source = (
                        "environment"
                    )

            else:
                st.session_state.ai_status = (
                    "local"
                )
                st.session_state.ai_key_source = (
                    "none"
                )

        a1, a2, a3, a4, a5 = st.columns(5)

        with a1:
            if st.button(
                "Explain Record",
                use_container_width=True,
            ):
                run_ai_coach(
                    "explain_record"
                )

        with a2:
            if st.button(
                "Triage Decision",
                use_container_width=True,
            ):
                run_ai_coach(
                    "triage_decision"
                )

        with a3:
            if st.button(
                "Next Steps",
                use_container_width=True,
            ):
                run_ai_coach(
                    "next_steps"
                )

        with a4:
            if st.button(
                "Incident Summary",
                use_container_width=True,
            ):
                run_ai_coach(
                    "incident_summary"
                )

        with a5:
            if st.button(
                "Executive Summary",
                use_container_width=True,
            ):
                run_ai_coach(
                    "executive_summary"
                )

        st.markdown("### AI Coach Output")

        ai_text = st.session_state.ai_text
        ai_status = st.session_state.ai_status
        ai_key_source = (
            st.session_state.ai_key_source
        )

        if ai_status == "fallback":
            sections = ai_text.split("\n\n")

            failure_reason = sections[0].replace(
                "OpenAI Coach unavailable:",
                "",
                1,
            ).strip()

            st.warning(
                "**OpenAI Coach failed — "
                "Local Coach is now active.**\n\n"
                f"{failure_reason}\n\n"
                "The guidance below was generated "
                "by HUNT-LITE's Local Coach and "
                "did not use OpenAI."
            )

            if len(sections) >= 3:
                local_output = "\n\n".join(
                    sections[2:]
                )
            else:
                local_output = ai_text

            st.write(local_output)

        elif ai_status == "openai":
            if ai_key_source == "session":
                st.success(
                    "**OpenAI Coach active — "
                    "session API key accepted.**\n\n"
                    "This response was generated "
                    "using OpenAI. The pasted key "
                    "has not been written to a "
                    "HUNT-LITE project file."
                )

            else:
                st.success(
                    "**OpenAI Coach active — "
                    "configured environment key "
                    "accepted.**\n\n"
                    "This response was generated "
                    "using OpenAI."
                )

            st.write(ai_text)

        elif ai_status == "local":
            st.info(
                "**Local Coach active.**\n\n"
                "This guidance was generated "
                "locally and did not use OpenAI."
            )

            st.write(ai_text)

        else:
            st.write(
                "Select an AI Coach mode and "
                "click a coaching button."
            )

else:
    st.info(
        "Run the ML triage workflow "
        "to see results."
    )
