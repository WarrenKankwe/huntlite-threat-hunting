#!/bin/bash

set -e

echo "HUNT-LITE Asset Downloader"
echo "Choose what to download:"
echo "1) Raw data only"
echo "2) Processed data only"
echo "3) Project assets only (artifacts, model, notebook)"
echo "4) Everything"
read -p "Enter option [1-4]: " CHOICE

mkdir -p data/raw
mkdir -p data/processed
mkdir -p artifacts
mkdir -p models
mkdir -p notebooks

# -----------------------------
# Google Drive file IDs
# -----------------------------
RAW_DATA_ID="1yYBeynz5wzNzPnEwzkt_QQnH3K_IDXxN"

PROCESSED_DATASET_ID="1sBUb3BntALyxg1aIGkVPmrg8KfRKwjlG"
TEST_SAMPLES_ID="1kiW8PL_n7-dckZJ2aAhU1zjvHG19t3CO"

VERSION_INFO_ID="1Tpz6eXvC9D0Rxeg_Tg5S_upttRK7eo0a"
MODEL_ID="1sPXFJpeN1rNpALNmAYepla-0DhBJ5f97"
PREPROCESSOR_ID="1KKPl9WovvGWSBfBHA6dtgg2pP14oaeSq"
FEATURE_INFO_ID="13tXsf2VFudq0s3eMn9hAlVWmlv-LBOMx"
LABEL_MAPPING_ID="14xpkgZUkd5jQ8rGyj9rpmfJZsnoGmO6k"
NOTEBOOK_ID="1NVWiE-tIW1dlwbiiosFpyzVhOkzlybMl"
LABEL_ENCODER_ID="1Y0mNZV7ZdlBjGsKTF0ng5qbrJg9RVtIv"

download_file () {
  FILEID=$1
  OUTPUT=$2

  echo "Downloading $OUTPUT ..."
  wget --no-check-certificate "https://drive.google.com/uc?export=download&id=${FILEID}" -O "$OUTPUT"
}

download_raw_data () {
  download_file "$RAW_DATA_ID" "data/raw/cybersecurity_threat_detection_logs.csv"
}

download_processed_data () {
  download_file "$PROCESSED_DATASET_ID" "data/processed/huntlite_ml_dataset.csv"
  download_file "$TEST_SAMPLES_ID" "data/processed/huntlite_streamlit_test_samples.csv"
}

download_project_assets () {
  download_file "$MODEL_ID" "models/huntlite_threat_detection_model.keras"
  download_file "$PREPROCESSOR_ID" "artifacts/preprocessor.joblib"
  download_file "$FEATURE_INFO_ID" "artifacts/feature_info.json"
  download_file "$LABEL_MAPPING_ID" "artifacts/label_mapping.json"
  download_file "$VERSION_INFO_ID" "artifacts/version_info.json"
  download_file "$LABEL_ENCODER_ID" "artifacts/label_encoder.joblib"
  download_file "$NOTEBOOK_ID" "notebooks/huntlite_full_training.ipynb"
}

case $CHOICE in
  1)
    download_raw_data
    ;;
  2)
    download_processed_data
    ;;
  3)
    download_project_assets
    ;;
  4)
    download_raw_data
    download_processed_data
    download_project_assets
    ;;
  *)
    echo "Invalid option. Please run the script again and choose 1, 2, 3, or 4."
    exit 1
    ;;
esac

echo "Download complete."
