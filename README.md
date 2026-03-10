# HUNT-LITE (Threat Hunting Lite)

HUNT-LITE is a beginner-friendly threat-hunting assistant built with Python and Streamlit. It provides guided scenarios using sample Windows EVTX logs and PCAPs, along with an AI coach that explains findings in plain language.

## What you can do
- Run guided threat-hunting scenarios:
  - PowerShell activity (EVTX)
  - Brute-force authentication attempts (EVTX)
  - Network beaconing behavior (PCAP)
- Parse raw logs and traffic into analysis-friendly formats
- Get AI-assisted explanations of suspicious activity (optional)

## Repository structure
- `gui/` – Streamlit application and core logic
- `data/` – Sample logs and PCAPs used by scenarios
- `sigma_rules/` – Example Sigma detection rules
- `docs/` – Notes and documentation

## Requirements
- Python 3.10 or newer
- macOS, Linux, or Windows

## Setup
From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r gui/requirements.txt

## Setup
From the repository root:

```bash
streamlit run gui/app.py
