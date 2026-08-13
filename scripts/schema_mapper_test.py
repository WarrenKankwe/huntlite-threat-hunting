from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gui.core.schema_mapper import (
    MODEL_FIELDS,
    build_mapped_dataframe,
    validate_mapping,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_successful_external_mapping() -> None:
    source = pd.DataFrame(
        {
            "scheme": ["http", "tcp", "https"],
            "filter_result": [
                "PROXIED",
                "DENIED",
                "PROXIED",
            ],
            "site_name": [
                "SG-HTTP-Service",
                "SG-HTTP-Service",
                "SG-HTTPS-Service",
            ],
            "sc_bytes": [186, 1000, 50],
            "cs_bytes": [231, 200, 25],
            "ua": [
                "Mozilla/5.0",
                "ProxyAV",
                "ExampleBrowser/1.0",
            ],
            "uri_path": [
                "/tests/testconnectivity.asp",
                "/admin",
                "/login",
            ],
        }
    )

    mapping = {
        "protocol": "scheme",
        "action": "filter_result",
        "log_type": "site_name",
        "bytes_transferred": None,
        "user_agent": "ua",
        "request_path": "uri_path",
    }

    mapped = build_mapped_dataframe(
        source,
        mapping,
        bytes_sent_column="sc_bytes",
        bytes_received_column="cs_bytes",
    )

    validation = validate_mapping(mapped)

    require(
        validation["ready"] is True,
        f"Expected mapping to be ready: {validation}",
    )

    require(
        validation["resolved_count"] == 6,
        "Expected all 6 HUNT-LITE fields to resolve.",
    )

    require(
        validation["total_fields"] == 6,
        "Expected HUNT-LITE model to require 6 fields.",
    )

    require(
        list(mapped["protocol"])
        == ["HTTP", "TCP", "HTTPS"],
        "Protocol normalization failed.",
    )

    require(
        list(mapped["action"])
        == ["allowed", "blocked", "allowed"],
        "Action normalization failed.",
    )

    require(
        list(mapped["log_type"])
        == [
            "application",
            "application",
            "application",
        ],
        "Blue Coat log-type normalization failed.",
    )

    require(
        list(mapped["bytes_transferred"])
        == [417, 1200, 75],
        "Byte derivation failed.",
    )

    require(
        list(mapped["request_path"])
        == [
            "/tests/testconnectivity.asp",
            "/admin",
            "/login",
        ],
        "Request-path mapping failed.",
    )

    print(
        "PASS: Compatible external dataset "
        "resolved 6/6 and validated"
    )
    print(
        "PASS: Protocol/action/log-type normalization "
        "worked"
    )
    print(
        "PASS: bytes_transferred derivation worked"
    )


def test_incomplete_mapping_is_rejected() -> None:
    source = pd.DataFrame(
        {
            "scheme": ["http"],
            "filter_result": ["PROXIED"],
            "site_name": ["SG-HTTP-Service"],
            "sc_bytes": [100],
            "cs_bytes": [50],
            "ua": ["Mozilla/5.0"],
        }
    )

    mapping = {
        "protocol": "scheme",
        "action": "filter_result",
        "log_type": "site_name",
        "bytes_transferred": None,
        "user_agent": "ua",
        "request_path": None,
    }

    mapped = build_mapped_dataframe(
        source,
        mapping,
        bytes_sent_column="sc_bytes",
        bytes_received_column="cs_bytes",
    )

    validation = validate_mapping(mapped)

    require(
        validation["ready"] is False,
        "Incomplete mapping should have been rejected.",
    )

    require(
        validation["resolved_count"] == 5,
        "Incomplete mapping should resolve exactly 5/6.",
    )

    require(
        "request_path" in validation["missing_fields"],
        "request_path should be reported as missing.",
    )

    print(
        "PASS: Incomplete 5/6 mapping was blocked"
    )
    print(
        "PASS: Missing request_path was identified"
    )


def test_original_columns_are_preserved() -> None:
    source = pd.DataFrame(
        {
            "scheme": ["http"],
            "filter_result": ["DENIED"],
            "site_name": ["SG-HTTP-Service"],
            "sc_bytes": [10],
            "cs_bytes": [20],
            "ua": ["ProxyAV"],
            "uri_path": ["/"],
            "evidence_id": ["EXT-001"],
        }
    )

    mapping = {
        "protocol": "scheme",
        "action": "filter_result",
        "log_type": "site_name",
        "bytes_transferred": None,
        "user_agent": "ua",
        "request_path": "uri_path",
    }

    mapped = build_mapped_dataframe(
        source,
        mapping,
        bytes_sent_column="sc_bytes",
        bytes_received_column="cs_bytes",
    )

    require(
        "evidence_id" in mapped.columns,
        "Original external columns were not preserved.",
    )

    require(
        mapped.loc[0, "evidence_id"] == "EXT-001",
        "Original external value changed unexpectedly.",
    )

    for field in MODEL_FIELDS:
        require(
            field in mapped.columns,
            f"Canonical field missing: {field}",
        )

    print(
        "PASS: Original external columns were preserved"
    )
    print(
        "PASS: Canonical HUNT-LITE fields were added"
    )


def main() -> None:
    print("HUNT-LITE Schema Mapper Test")
    print("=" * 55)

    test_successful_external_mapping()
    print("-" * 55)

    test_incomplete_mapping_is_rejected()
    print("-" * 55)

    test_original_columns_are_preserved()

    print("=" * 55)
    print(
        "RESULT: PASS — controlled schema mapper "
        "regression test completed"
    )


if __name__ == "__main__":
    main()
