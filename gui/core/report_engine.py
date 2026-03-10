from __future__ import annotations
import pandas as pd


def build_record_report(row: pd.Series) -> str:
    protocol = row.get("protocol", "")
    action = row.get("action", "")
    log_type = row.get("log_type", "")
    bytes_transferred = row.get("bytes_transferred", "")
    user_agent = row.get("user_agent", "")
    request_path = row.get("request_path", "")
    predicted_label = row.get("predicted_label", "")
    confidence = float(row.get("predicted_confidence", 0.0))
    severity = row.get("severity", "")
    triage_reason = row.get("triage_reason", "")

    report = f"""
## HUNT-LITE Incident / Triage Note

**Predicted Threat Label:** {predicted_label}  
**Confidence:** {confidence:.2%}  
**Assigned Severity:** {severity}

### Observed Record
- Protocol: {protocol}
- Action: {action}
- Log Type: {log_type}
- Bytes Transferred: {bytes_transferred}
- User Agent: {user_agent}
- Request Path: {request_path}

### Initial Triage Assessment
{triage_reason}

### Potential Analyst Interpretation
This record was surfaced by the trained HUNT-LITE ML pipeline as worthy of triage review. The confidence score indicates how strongly the model matched this event to known synthetic threat patterns in the trained dataset. Severity is used as a teaching and prioritization aid, not as final proof of compromise.

### Recommended Analyst Actions
1. Validate whether the request path aligns with expected application behavior.
2. Review related activity from the same client or session for repetition or escalation.
3. Check whether the user agent is expected in the environment.
4. Determine whether the blocked/allowed decision matches organizational security policy.
5. Escalate if corroborating indicators suggest exploitation, scanning, or malicious automation.
""".strip()

    return report


def build_case_summary(summary: dict) -> str:
    return f"""
## HUNT-LITE Case Summary

- Total records reviewed: {summary.get('total_records', 0)}
- Records flagged for review: {summary.get('flagged_records', 0)}
- Benign predictions: {summary.get('benign_count', 0)}
- Suspicious predictions: {summary.get('suspicious_count', 0)}
- Malicious predictions: {summary.get('malicious_count', 0)}
- Critical severity: {summary.get('critical_count', 0)}
- High severity: {summary.get('high_count', 0)}
- Medium severity: {summary.get('medium_count', 0)}
- Top predicted class: {summary.get('top_predicted_label', 'n/a')}
- Average confidence: {summary.get('average_confidence', 0):.2%}

This summary reflects the initial SOC triage view produced by the HUNT-LITE machine learning workflow.
""".strip()
