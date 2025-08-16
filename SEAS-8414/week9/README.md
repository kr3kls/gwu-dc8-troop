# GenAI-Powered URL Analysis

This application is an AI-driven domain analysis tool that combines predictive modeling, explainable AI (XAI), and generative AI (GenAI). It takes a domain name as input, computes key statistical features such as string length and entropy, and evaluates the domain against an H2O MOJO model trained to detect Domain Generation Algorithm (DGA) domains. If the model predicts the domain as malicious, the system uses SHAP values to interpret which features most influenced the classification and produces a structured, human-readable explanation. This explanation is then passed to Google Gemini, which generates a concise, prescriptive incident response playbook tailored for Tier 1 security analysts.

## Features

-   **Domain Feature Extraction**: Calculates key statistical measures from the input domain name to characterize its randomness and structure.
-   **Machine Learning Classification**: Loads and applies an H2O MOJO model trained to distinguish between legitimate and DGA-generated domains.
-   **Explainable AI (XAI) with SHAP**: Generates SHAP force plots and textual explanations that identify how features influenced the model’s prediction.
-   **Generative AI (Gemini) Integration**: Converts model explanations into a prescriptive incident response playbook using Google Gemini.
-   **Automated Output & Audit Trail**: Ensures findings and guidance are reproducible for audit and escalation.

## Prerequisites

Before you begin, ensure you have the following installed on your system:
-   API key for the Gemini Generative AI service.

## Setup & Installation

Installation instructions located in [INSTALL.md](INSTALL.md).

## Running the Application

Run the application with one command line arguemnt for the domain you want to check:

```python3.11 2_analyze_domain.py --domain google.com```

## Testing

Testing instructions located in [TESTING.md](TESTING.md).

## Project Structure
```
week9/
├── models
|   └── GBM_grid_1_AutoML_1_20250814_180359_model_1.zip
├── .env
├── data/
|   └── phishing_synthetic.csv
├── 1_train_and_export.py
├── 2_analyze_domain.py
├── dga_dataset_train.csv
├── explain_1qw0wj01buakpscg_com_shap_force.png
├── INSTALL.md
├── playbook_1qw0wj01buakpscg_com.txt
├── README.md
├── requirements.txt
├── TESTING.md
└── xai_findings_1qw0wj01buakpscg_com.txt
```
