HUNT-LITE

ML-Powered Beginner Threat Hunting and SOC Triage Assistant

HUNT-LITE is an interactive cybersecurity learning tool that demonstrates how machine learning can assist Security Operations Center (SOC) analysts in identifying suspicious activity, triaging potential incidents, and generating investigation guidance.

The project combines:

- Machine learning threat detection
- SOC triage workflows
- Interactive analyst dashboards
- AI-assisted investigation guidance
- Incident reporting

The goal is to help new analysts understand the thought process behind threat hunting and incident response.

---

Project Overview

HUNT-LITE simulates a simplified SOC workflow where security logs are analyzed by a trained machine learning model and then triaged through an analyst-style interface.

Prepared HUNT-LITE data follows this workflow:

```text
Dataset -> ML Model -> Triage Engine -> SOC Dashboard -> AI Coach -> Incident Report
```

Compatible external CSV data follows a controlled mapping workflow:

```text
External CSV -> Schema Mapper -> Validation -> ML Model -> Triage Engine -> SOC Dashboard -> AI Coach
```

Core components:

| Component | Description |
|---|---|
| ML Model | Keras neural network trained on cybersecurity log patterns |
| Preprocessor | Scikit-learn pipeline for feature transformation |
| Triage Engine | Assigns severity and flags suspicious activity |
| Streamlit Dashboard | Interactive SOC-style interface |
| AI Coach | Explains threats and suggests investigation steps |
| Report Engine | Generates analyst notes and case summaries |

---

Dataset

Dataset source:

Kaggle Cybersecurity Threat Detection Logs

The dataset contains simulated network and application activity including:

- Protocol
- Action
- Log type
- Bytes transferred
- User agent
- Request path

The ML model predicts three classes:

```text
benign
suspicious
malicious
```

---

External Dataset Support

HUNT-LITE can also evaluate compatible external security-log CSV files without retraining the existing model.

The controlled schema mapper requires six model inputs:

```text
protocol
action
log_type
bytes_transferred
user_agent
request_path
```

External column names do not have to match the HUNT-LITE names exactly. The mapper allows the user to inspect the uploaded schema and explicitly map compatible source fields into the six required model fields.

Supported transformations include:

- Known semantic column aliases
- Protocol normalization
- Controlled action normalization
- Controlled log-type normalization
- Direct bytes-transferred mapping
- Derivation of bytes transferred by summing sent and received byte fields
- Request-path extraction from compatible URL values
- Preservation of the original external columns for analyst review

All six model fields must be resolved before ML triage is enabled.

HUNT-LITE intentionally blocks incomplete or semantically incompatible mappings rather than silently filling missing model inputs with fabricated blank or zero values.

External labels, when present, are not used to manufacture HUNT-LITE model inputs.

The schema mapper addresses input compatibility only. Successful mapping and model inference on an external dataset do not establish that the model is accurate on that dataset. Prediction quality depends on how closely the external data distribution and semantics match the data used to train the model.

---

Machine Learning Pipeline

Training was performed in Google Colab using the following environment:

```text
Python        3.12.12
scikit-learn  1.6.1
numpy         2.0.2
pandas        2.2.2
tensorflow    2.19.0
joblib        1.5.3
```

Training steps:

1. Dataset cleaning
2. Feature engineering
3. ColumnTransformer preprocessing
4. One-hot encoding categorical features
5. Neural network training with Keras
6. Artifact export

Saved artifacts include:

```text
preprocessor.joblib
feature_info.json
label_mapping.json
label_encoder.joblib
version_info.json
huntlite_threat_detection_model.keras
```

---

SOC Workflow

Step 1 - Load Security Records

Users load processed security logs into the system.

Step 2 - ML Classification

The model predicts whether each record is:

```text
benign
suspicious
malicious
```

Each record receives values including:

```text
predicted_label
predicted_confidence
class_probabilities
```

Step 3 - Triage

The triage engine assigns severity and determines which records require analyst review.

| Condition | Severity |
|---|---|
| malicious >= 90% | Critical |
| malicious >= 75% | High |
| suspicious >= 75% | High |
| suspicious >= 60% | Medium |

Step 4 - Analyst Investigation

The dashboard allows analysts to inspect information such as:

- Request paths
- User agents
- Network protocols
- Traffic actions
- Data transfer patterns
- Model prediction
- Prediction confidence
- Assigned severity

Step 5 - AI Coach

The AI Coach provides additional investigation guidance for selected records.

Available actions include:

```text
Explain Record
Triage Decision
Next Investigation Steps
Incident Summary
Executive Summary
```

The AI Coach can help explain:

- Why a record may be suspicious
- Which indicators deserve attention
- What the analyst should investigate next

The AI Coach provides two operating modes:

- Local Coach - deterministic investigation guidance that requires no API key or external service
- OpenAI Coach - optional LLM-assisted guidance using a user-provided session key or a locally configured OpenAI API key

If OpenAI credentials are missing or the external request fails, HUNT-LITE falls back to the Local Coach so the core investigation workflow remains usable.

The OpenAI Coach treats telemetry as untrusted input and is instructed not to invent evidence, treat model predictions as proof of compromise, or follow instructions embedded inside log data.

Step 6 - Incident Reporting

HUNT-LITE generates:

- SOC analyst notes
- Incident drafts
- Case summaries
- Recommended investigation actions

---

Installation

1. Clone the repository

```bash
git clone https://github.com/WarrenKankwe/huntlite-threat-hunting.git
cd huntlite-threat-hunting
```

2. Confirm Python 3.12 is installed

```bash
python3.12 --version
```

HUNT-LITE has been tested with Python 3.12.

3. Create a virtual environment

```bash
python3.12 -m venv .venv
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r gui/requirements.txt
```

The requirements file uses tested dependency versions to improve reproducibility.

---

Downloading HUNT-LITE Assets

Large datasets and trained project assets are stored externally in Google Drive to keep the GitHub repository lightweight.

The downloader uses the Python package gdown. It is installed automatically through gui/requirements.txt.

wget is not required.

Run:

```bash
./scripts/download_huntlite_assets.sh
```

The downloader provides four options:

```text
1. Raw data only
2. Processed data only
3. Project assets only (model and preprocessing artifacts)
4. Everything
```

Option 1 - Raw Data Only

Downloads:

```text
data/raw/cybersecurity_threat_detection_logs.csv
```

Use this option if you want to inspect or recreate the original preprocessing workflow.

Option 2 - Processed Data Only

Downloads:

```text
data/processed/huntlite_ml_dataset.csv
data/processed/huntlite_streamlit_test_samples.csv
```

Use this option to obtain the processed datasets used by the application.

Option 3 - Project Assets Only

Downloads:

```text
models/huntlite_threat_detection_model.keras
artifacts/preprocessor.joblib
artifacts/feature_info.json
artifacts/label_mapping.json
artifacts/version_info.json
artifacts/label_encoder.joblib
```
The training notebook is already included in the GitHub repository and does not need to be downloaded separately.

Option 4 - Everything

Downloads:

- Raw dataset
- Processed datasets
- ML artifacts
- Model

For most users who only want to run the application, Option 2 followed by Option 3 is sufficient.

The downloader now uses temporary .part files and performs basic validation before reporting a successful download.

---

Asset Verification

After downloading the required files, run:

```bash
python scripts/verify_assets.py
```

The verification script checks that:

- Required files exist
- Required files are not empty
- Processed CSV files contain the expected fields
- The full processed dataset matches the expected SHA-256 hash
- The Keras model can be loaded
- Joblib artifacts can be loaded
- JSON artifacts can be parsed
- The training notebook can be parsed

A successful run ends with:

```text
RESULT: PASS — all required HUNT-LITE assets verified
```

---

Smoke Test

Before launching the application, run:

```bash
python scripts/smoke_test.py
```

The smoke test:

- Loads the prepared test dataset
- Runs the HUNT-LITE ML triage pipeline
- Confirms expected output sections are returned
- Confirms all records are processed
- Confirms the analyst review queue is generated

A successful run ends with:

```text
RESULT: PASS — HUNT-LITE core workflow smoke test completed
```

---

Schema Mapper Test

The controlled external-dataset mapper has a standalone regression test:

```bash
python scripts/schema_mapper_test.py
```

The test verifies that:

- A compatible external schema resolves all 6 required model fields
- Protocol, action, and log-type normalization work as expected
- Sent and received byte fields can be derived into bytes_transferred
- Original external columns are preserved
- An incomplete 5/6 mapping is rejected
- The missing model field is reported rather than silently fabricated

A successful run ends with:

```text
RESULT: PASS — controlled schema mapper regression test completed
```

---

Running HUNT-LITE

Start the Streamlit application:

```bash
python -m streamlit run gui/app.py
```

Streamlit normally opens the application automatically in a browser.

If needed, open:

```text
http://localhost:8501
```

Recommended first-time setup sequence:

```text
1. Clone the repository
2. Create and activate a Python 3.12 virtual environment
3. Install gui/requirements.txt
4. Run the asset downloader
5. Choose Option 2
6. Run the downloader again and choose Option 3
7. Run verify_assets.py
8. Run smoke_test.py
9. Run schema_mapper_test.py
10. Start the Streamlit application
```

---

Dashboard

Dataset Preview

Displays the currently loaded security records.

External Dataset Schema Mapper

When an external CSV is uploaded, HUNT-LITE displays the original schema and allows the user to map compatible source columns into the six required model inputs.

The interface shows:

- Required-field selections
- Direct or derived byte mapping
- Mapping summary
- Resolved-field count
- Normalized HUNT-LITE preview
- Validation errors and warnings
- Enabled or blocked ML triage status

ML triage remains disabled until all six model fields have been resolved and validated.

SOC Triage Dashboard

Shows information including:

- Total records
- Records flagged for review
- Threat distribution
- Severity counts
- Average prediction confidence

Analyst Review Queue

Displays suspicious and malicious records selected for additional investigation.

Record Detail Explorer

Allows the analyst to inspect an individual record and its model and triage results.

AI Coach

Provides investigation explanations and guidance through either the no-key Local Coach or the optional OpenAI Coach.

The OpenAI Coach can use a session-provided API key without requiring that key to be stored in the repository. If OpenAI is unavailable, HUNT-LITE can fall back to the Local Coach.

Incident Report Generator

Produces analyst notes, investigation guidance, and case summaries.

---

Example Suspicious Indicators

HUNT-LITE can surface patterns such as:

```text
Directory traversal attempts
Automated scanning tools
Suspicious user agents
Unexpected protocols
Large abnormal data transfers
```

Example flagged event:

```text
protocol: UDP
action: allowed
request_path: /?..\..\etc\passwd
prediction: suspicious
```

---

Educational Purpose

HUNT-LITE demonstrates concepts including:

- Machine learning in cybersecurity
- SOC triage workflows
- Controlled external-log schema mapping
- Threat investigation reasoning
- AI-assisted analyst support
- Security record review
- Incident documentation

The project is intended for educational and research purposes and is not designed to replace production SOC or threat detection systems.

---

Future Improvements

Potential future improvements include:

- Explainable AI feature attribution
- SIEM integration
- Real-time log ingestion
- Threat intelligence enrichment
- Analyst feedback and model retraining

---

Author

Warren Kankwe

University of Denver
MSc Cybersecurity, 2026

---

License

This project is licensed under the MIT License.

See the LICENSE file for details.
