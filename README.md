# HUNT-LITE

### ML-Powered Beginner Threat Hunting & SOC Triage Assistant

HUNT-LITE is an interactive cybersecurity learning tool that demonstrates how **machine learning can assist Security Operations Center (SOC) analysts** in identifying suspicious activity, triaging potential incidents, and generating investigation guidance.

The project combines:

* Machine Learning threat detection
* SOC triage workflows
* Interactive analyst dashboards
* AI-assisted investigation guidance

The goal is to help **new analysts understand the thought process behind threat hunting and incident response**.

---

# Project Overview

HUNT-LITE simulates a simplified SOC workflow where security logs are analyzed by a trained machine learning model and then triaged through an analyst-style interface.

```
Dataset → ML Model → Triage Engine → SOC Dashboard → AI Coach → Incident Report
```

### Core Components

| Component           | Description                                                |
| ------------------- | ---------------------------------------------------------- |
| ML Model            | Keras neural network trained on cybersecurity log patterns |
| Preprocessor        | Scikit-learn pipeline for feature transformation           |
| Triage Engine       | Assigns severity and flags suspicious activity             |
| Streamlit Dashboard | Interactive SOC-style interface                            |
| AI Coach            | Explains threats and suggests investigation steps          |
| Report Engine       | Generates incident summary notes                           |

---

# Dataset

Dataset source:

**Kaggle Cybersecurity Threat Detection Logs**

The dataset contains simulated network and application activity including:

* Protocol
* Action
* Log type
* Bytes transferred
* User agent
* Request path

The ML model predicts three classes:

```
benign
suspicious
malicious
```

---

# Machine Learning Pipeline

Training was performed in **Google Colab** using the following environment:

```
Python        3.12.12
scikit-learn  1.6.1
numpy         2.0.2
pandas        2.2.2
tensorflow    2.19.0
joblib        1.5.3
```

### Training Steps

1. Dataset cleaning
2. Feature engineering
3. ColumnTransformer preprocessing
4. One-hot encoding categorical features
5. Neural network training (Keras)
6. Artifact export

Saved artifacts:

```
preprocessor.joblib
feature_info.json
label_mapping.json
huntlite_threat_detection_model.keras
```

---

# SOC Workflow Demonstrated

HUNT-LITE simulates the process a SOC analyst follows.

---

## Step 1 — Load Security Records

Users load processed security logs into the system.

---

## Step 2 — ML Classification

The model predicts whether each record is:

```
benign
suspicious
malicious
```

Each record receives:

```
predicted_label
predicted_confidence
class_probabilities
```

---

## Step 3 — Triage

The triage engine assigns severity.

| Condition        | Severity |
| ---------------- | -------- |
| malicious ≥ 90%  | Critical |
| malicious ≥ 75%  | High     |
| suspicious ≥ 75% | High     |
| suspicious ≥ 60% | Medium   |

Suspicious records are flagged for analyst review.

---

## Step 4 — Analyst Investigation

The dashboard allows analysts to inspect:

* Request paths
* User agents
* Network protocols
* Traffic actions
* Data transfer patterns

---

## Step 5 — AI Coach Guidance

The **AI Coach** helps analysts understand and investigate alerts.

Modes include:

```
Explain Record
Triage Decision
Next Investigation Steps
Incident Summary
Executive Summary
```

The AI coach explains:

* Why a record was flagged
* What indicators look suspicious
* How an analyst should investigate further

---

## Step 6 — Incident Report Generation

HUNT-LITE automatically generates:

* SOC analyst notes
* Incident summaries
* Recommended response actions

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOURUSERNAME/huntlite.git
cd huntlite
```

---

## 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

---

## 3. Install dependencies

```bash
pip install -r gui/requirements.txt
```

Dependencies include:

* Streamlit
* TensorFlow
* Scikit-learn
* Pandas
* NumPy
* OpenAI API client

---

# Download Options

Large files are stored externally in **Google Drive** to keep the GitHub repository lightweight.

HUNT-LITE includes a download script that allows users to download only the components they need.

Run the script:

```bash
./scripts/download_huntlite_assets.sh
```

You will be prompted to choose one of the following options.

---

## Option 1 — Raw Data Only

Downloads the original heavy dataset used for preprocessing and training.

Example file downloaded:

```
data/raw/cybersecurity_threat_detection_logs.csv
```

Use this option if you want to explore or recreate the dataset preparation process.

---

## Option 2 — Processed Data Only

Downloads the lightweight processed datasets used directly by the application.

Files downloaded:

```
data/processed/huntlite_ml_dataset.csv
data/processed/huntlite_streamlit_test_samples.csv
```

Use this option if you want to run the Streamlit app quickly without processing raw data.

---

## Option 3 — Project Assets Only

Downloads the trained machine learning artifacts and notebook.

Files downloaded:

```
models/huntlite_threat_detection_model.keras
artifacts/preprocessor.joblib
artifacts/feature_info.json
artifacts/label_mapping.json
artifacts/version_info.json
artifacts/label_encoder.joblib
notebooks/huntlite_full_training.ipynb
```

Use this option if you want the trained pipeline without downloading datasets.

---

## Option 4 — Everything

Downloads:

* raw dataset
* processed datasets
* ML artifacts
* model
* notebook

Use this option if you want the **complete project environment locally**.

---

# Recommended Setup

For most users who only want to run the application:

1. Install dependencies
2. Run the download script
3. Choose **Option 2 and Option 3**, or simply **Option 4**

---

# Running the Application

Launch the Streamlit interface:

```bash
streamlit run gui/app.py
```

Open your browser:

```
http://localhost:8501
```

---

# Dashboard Overview

The HUNT-LITE dashboard includes several components.

### Dataset Preview

Displays the loaded security records.

### SOC Triage Dashboard

Shows:

* Threat distribution
* Severity counts
* Average prediction confidence

### Analyst Review Queue

Displays records flagged for investigation.

### Record Detail Explorer

Allows deep inspection of suspicious activity.

### AI Coach

Provides investigation guidance and explanations.

### Incident Report Generator

Produces analyst notes and incident summaries.

---

# Example Suspicious Indicators

The system highlights patterns such as:

```
Directory traversal attempts
Automated scanning tools
Suspicious user agents
Unexpected protocols
Large abnormal data transfers
```

Example flagged event:

```
protocol: UDP
action: allowed
request_path: /?..\..\etc\passwd
prediction: suspicious
```

---

# Educational Purpose

HUNT-LITE demonstrates:

* Machine learning in cybersecurity
* SOC triage workflows
* Threat investigation reasoning
* AI-assisted analyst support

This project is **for educational and research purposes only** and **not designed for production threat detection systems**.

---

# Future Improvements

Potential enhancements include:

* Explainable AI feature attribution
* SIEM integration
* Real-time log ingestion
* Threat intelligence enrichment
* Analyst feedback loop retraining

---

# Authors

**Warren Kankwe**
**Sy Pretto**
University of Denver — MSc Cybersecurity

---

# License

This project is licensed under the MIT License.

See the LICENSE file for details.
