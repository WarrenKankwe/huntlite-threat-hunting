from __future__ import annotations
import os
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def _client():
    return OpenAI()


def _model():
    return os.getenv("OPENAI_MODEL", "gpt-5.2")


def ai_explain(
    selected_row: pd.Series | None,
    summary: dict | None,
    mode: str,
) -> str:
    if selected_row is None:
        return "No record selected yet. Choose a flagged record first."

    record = selected_row.to_dict()
    summary = summary or {}

    if mode == "explain_record":
        instruction = (
            "Explain this record to a beginner SOC analyst. "
            "Describe why it may be benign, suspicious, or malicious using plain language."
        )
    elif mode == "triage_decision":
        instruction = (
            "Explain the triage decision, likely severity, and whether escalation is warranted."
        )
    elif mode == "next_steps":
        instruction = (
            "Suggest the next investigative steps, pivots, and validation checks for a SOC analyst."
        )
    elif mode == "executive_summary":
        instruction = (
            "Write a short leadership-ready summary with business-friendly language."
        )
    else:
        instruction = (
            "Write an incident-style summary suitable for analyst notes."
        )

    prompt = f"""
You are the HUNT-LITE AI Coach.

Your role is to teach a first-time SOC analyst how triage works, what to notice in a suspicious record, and how to think through next steps.

CASE SUMMARY:
{summary}

SELECTED RECORD:
{record}

TASK:
{instruction}

Requirements:
- Be practical and clear.
- Do not invent evidence that is not present.
- Reference the model prediction, confidence, severity, request path, action, protocol, and user agent if relevant.
- Keep it useful for beginner SOC learning.
- Use concise bullet points.
"""

    try:
        response = _client().responses.create(
            model=_model(),
            input=prompt,
        )
        return response.output_text
    except Exception as e:
        return f"[AI Error] {e}"
