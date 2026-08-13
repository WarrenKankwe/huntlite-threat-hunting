from __future__ import annotations

import re
from urllib.parse import urlsplit

import pandas as pd


MODEL_FIELDS = [
    "protocol",
    "action",
    "log_type",
    "bytes_transferred",
    "user_agent",
    "request_path",
]


MODEL_CATEGORIES = {
    "protocol": {
        "FTP",
        "HTTP",
        "HTTPS",
        "ICMP",
        "SSH",
        "TCP",
        "UDP",
    },
    "action": {
        "allowed",
        "blocked",
    },
    "log_type": {
        "application",
        "firewall",
        "ids",
    },
}


FIELD_ALIASES = {
    "protocol": [
        "protocol",
        "proto",
        "network_protocol",
        "transport_protocol",
        "transport",
    ],
    "action": [
        "action",
        "verdict",
        "decision",
        "disposition",
        "event_action",
        "rule_action",
        "outcome",
    ],
    "log_type": [
        "log_type",
        "event_type",
        "event_source",
        "source_type",
        "device_type",
        "sensor",
        "detection_system",
    ],
    "bytes_transferred": [
        "bytes_transferred",
        "total_bytes",
        "bytes",
        "byte_count",
        "bytes_total",
        "transfer_size",
    ],
    "user_agent": [
        "user_agent",
        "useragent",
        "http_user_agent",
        "client_agent",
        "ua",
    ],
    "request_path": [
        "request_path",
        "request_uri",
        "uri",
        "url",
        "url_path",
        "path",
        "endpoint",
        "resource",
    ],
}


BYTE_SENT_ALIASES = [
    "bytes_sent",
    "sent_bytes",
    "bytes_out",
    "outbound_bytes",
    "response_bytes",
]


BYTE_RECEIVED_ALIASES = [
    "bytes_received",
    "received_bytes",
    "bytes_in",
    "inbound_bytes",
    "request_bytes",
]


def _normalized_name(value: str) -> str:
    value = str(value).strip().lower()

    return re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    ).strip("_")


def _column_lookup(columns) -> dict[str, str]:
    return {
        _normalized_name(column): column
        for column in columns
    }


def suggest_source_column(
    columns,
    target_field: str,
) -> str | None:
    """
    Suggest a source column for one HUNT-LITE field.

    Suggestions are based only on known semantic aliases.
    No values are fabricated.
    """

    lookup = _column_lookup(columns)

    for alias in FIELD_ALIASES.get(
        target_field,
        [],
    ):
        normalized_alias = _normalized_name(alias)

        if normalized_alias in lookup:
            return lookup[normalized_alias]

    return None


def suggest_mapping(
    columns,
) -> dict[str, str | None]:
    """
    Return automatic column suggestions for all six
    HUNT-LITE model fields.
    """

    return {
        field: suggest_source_column(
            columns,
            field,
        )
        for field in MODEL_FIELDS
    }


def suggest_byte_pair(
    columns,
) -> tuple[str | None, str | None]:
    """
    Look for a defensible pair of byte fields that can
    be summed into bytes_transferred.
    """

    lookup = _column_lookup(columns)

    sent_column = None
    received_column = None

    for alias in BYTE_SENT_ALIASES:
        key = _normalized_name(alias)

        if key in lookup:
            sent_column = lookup[key]
            break

    for alias in BYTE_RECEIVED_ALIASES:
        key = _normalized_name(alias)

        if key in lookup:
            received_column = lookup[key]
            break

    return sent_column, received_column


def normalize_protocol(value):
    if pd.isna(value):
        return pd.NA

    text = str(value).strip()

    if not text:
        return pd.NA

    return text.upper()


def normalize_action(value):
    if pd.isna(value):
        return pd.NA

    text = str(value).strip().lower()

    if not text:
        return pd.NA

    allowed_values = {
        "allow",
        "allowed",
        "permit",
        "permitted",
        "accept",
        "accepted",
        "pass",
        "passed",
    }

    blocked_values = {
        "block",
        "blocked",
        "deny",
        "denied",
        "drop",
        "dropped",
        "reject",
        "rejected",
    }

    if text in allowed_values:
        return "allowed"

    if text in blocked_values:
        return "blocked"

    return text


def normalize_log_type(value):
    if pd.isna(value):
        return pd.NA

    text = str(value).strip().lower()

    if not text:
        return pd.NA

    normalized = _normalized_name(text)

    if normalized in {
        "ids",
        "intrusion_detection",
        "intrusion_detection_system",
        "snort",
        "suricata",
    }:
        return "ids"

    if (
        "ids" in normalized
        or "snort" in normalized
        or "suricata" in normalized
    ):
        return "ids"

    if normalized in {
        "firewall",
        "fw",
        "network_firewall",
        "ngfw",
    }:
        return "firewall"

    if "firewall" in normalized:
        return "firewall"

    if normalized in {
        "application",
        "app",
        "web_application",
        "waf",
        "web_application_firewall",
    }:
        return "application"

    if (
        "application" in normalized
        or normalized.startswith("waf")
    ):
        return "application"

    return text


def normalize_request_path(value):
    if pd.isna(value):
        return pd.NA

    text = str(value).strip()

    if not text:
        return pd.NA

    # Full HTTP/HTTPS URLs can safely be reduced to the
    # path and query used by the HUNT-LITE model.
    if text.startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = urlsplit(text)

        path = parsed.path or "/"

        if parsed.query:
            return f"{path}?{parsed.query}"

        return path

    return text


def _normalize_direct_field(
    series: pd.Series,
    target_field: str,
) -> pd.Series:
    if target_field == "protocol":
        return series.map(normalize_protocol)

    if target_field == "action":
        return series.map(normalize_action)

    if target_field == "log_type":
        return series.map(normalize_log_type)

    if target_field == "request_path":
        return series.map(normalize_request_path)

    if target_field == "user_agent":
        return (
            series
            .where(series.notna(), pd.NA)
            .map(
                lambda value: (
                    str(value).strip()
                    if not pd.isna(value)
                    else pd.NA
                )
            )
            .replace("", pd.NA)
        )

    if target_field == "bytes_transferred":
        return pd.to_numeric(
            series,
            errors="coerce",
        )

    return series.copy()


def build_mapped_dataframe(
    source_df: pd.DataFrame,
    mapping: dict[str, str | None],
    bytes_sent_column: str | None = None,
    bytes_received_column: str | None = None,
) -> pd.DataFrame:
    """
    Build canonical HUNT-LITE model fields while preserving
    all original external-dataset columns.

    bytes_transferred may be derived by summing a sent and
    received byte column when both are explicitly supplied.
    """

    mapped_df = source_df.copy()

    for field in MODEL_FIELDS:
        source_column = mapping.get(field)

        if field == "bytes_transferred":
            if source_column:
                if source_column not in source_df.columns:
                    raise ValueError(
                        "Mapped source column "
                        f"'{source_column}' does not exist."
                    )

                mapped_df[field] = (
                    _normalize_direct_field(
                        source_df[source_column],
                        field,
                    )
                )

            elif (
                bytes_sent_column
                and bytes_received_column
            ):
                if (
                    bytes_sent_column
                    not in source_df.columns
                ):
                    raise ValueError(
                        "Byte source column "
                        f"'{bytes_sent_column}' "
                        "does not exist."
                    )

                if (
                    bytes_received_column
                    not in source_df.columns
                ):
                    raise ValueError(
                        "Byte source column "
                        f"'{bytes_received_column}' "
                        "does not exist."
                    )

                sent = pd.to_numeric(
                    source_df[
                        bytes_sent_column
                    ],
                    errors="coerce",
                )

                received = pd.to_numeric(
                    source_df[
                        bytes_received_column
                    ],
                    errors="coerce",
                )

                mapped_df[field] = (
                    sent + received
                )

            continue

        if not source_column:
            continue

        if source_column not in source_df.columns:
            raise ValueError(
                "Mapped source column "
                f"'{source_column}' does not exist."
            )

        mapped_df[field] = (
            _normalize_direct_field(
                source_df[source_column],
                field,
            )
        )

    return mapped_df


def validate_mapping(
    mapped_df: pd.DataFrame,
) -> dict:
    """
    Validate whether a mapped external dataset is safe to
    pass into the existing HUNT-LITE model.

    A dataset is model-ready only when all six canonical
    fields exist and contain usable values.
    """

    errors = []
    warnings = []

    missing_fields = [
        field
        for field in MODEL_FIELDS
        if field not in mapped_df.columns
    ]

    if missing_fields:
        errors.append(
            "Missing required HUNT-LITE fields: "
            + ", ".join(missing_fields)
        )

    if missing_fields:
        return {
            "ready": False,
            "resolved_count": (
                len(MODEL_FIELDS)
                - len(missing_fields)
            ),
            "total_fields": len(MODEL_FIELDS),
            "missing_fields": missing_fields,
            "errors": errors,
            "warnings": warnings,
        }

    for field in MODEL_FIELDS:
        missing_count = int(
            mapped_df[field].isna().sum()
        )

        if missing_count:
            errors.append(
                f"{field} contains "
                f"{missing_count} missing/invalid values."
            )

    numeric_bytes = pd.to_numeric(
        mapped_df["bytes_transferred"],
        errors="coerce",
    )

    invalid_bytes = int(
        numeric_bytes.isna().sum()
    )

    if invalid_bytes:
        errors.append(
            "bytes_transferred contains "
            f"{invalid_bytes} non-numeric values."
        )

    negative_bytes = int(
        (numeric_bytes.dropna() < 0).sum()
    )

    if negative_bytes:
        errors.append(
            "bytes_transferred contains "
            f"{negative_bytes} negative values."
        )

    action_values = set(
        mapped_df["action"]
        .dropna()
        .astype(str)
        .str.lower()
        .unique()
    )

    unsupported_actions = sorted(
        action_values
        - MODEL_CATEGORIES["action"]
    )

    if unsupported_actions:
        errors.append(
            "Unsupported action values after "
            "normalization: "
            + ", ".join(
                unsupported_actions[:10]
            )
        )

    log_type_values = set(
        mapped_df["log_type"]
        .dropna()
        .astype(str)
        .str.lower()
        .unique()
    )

    unsupported_log_types = sorted(
        log_type_values
        - MODEL_CATEGORIES["log_type"]
    )

    if unsupported_log_types:
        errors.append(
            "Unsupported log_type values after "
            "normalization: "
            + ", ".join(
                unsupported_log_types[:10]
            )
        )

    protocol_values = set(
        mapped_df["protocol"]
        .dropna()
        .astype(str)
        .str.upper()
        .unique()
    )

    unseen_protocols = sorted(
        protocol_values
        - MODEL_CATEGORIES["protocol"]
    )

    if unseen_protocols:
        warnings.append(
            "The trained model has not seen these "
            "protocol values: "
            + ", ".join(
                unseen_protocols[:10]
            )
            + ". The encoder will ignore unseen "
            "categories."
        )

    ready = len(errors) == 0

    return {
        "ready": ready,
        "resolved_count": len(MODEL_FIELDS),
        "total_fields": len(MODEL_FIELDS),
        "missing_fields": [],
        "errors": errors,
        "warnings": warnings,
    }
