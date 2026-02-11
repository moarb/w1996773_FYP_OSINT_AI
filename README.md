# AI-Assisted OSINT Tool (Prototype)

## Overview

This project is a prototype AI-assisted OSINT (Open Source Intelligence) analysis tool.

Implemented pipeline (IPD version):

- VirusTotal domain lookup (API integration)
- Data normalisation to a structured JSON schema
- Explainable rule-based risk scoring (0–100)
- Risk classification (LOW / MEDIUM / HIGH)
- Markdown report generation
- Streamlit web interface
- Basic automated smoke test

The system demonstrates a modular intelligence-processing pipeline that can later be extended with additional OSINT sources and machine learning / LLM-based classification.



## VirusTotal API Key (Required)

This prototype requires a free VirusTotal API key.

Steps:

1. Create an account at https://www.virustotal.com/
2. Log in and navigate to your profile
3. Copy your API key



## Setup Instructions (Windows PowerShell)

Open PowerShell in the project root folder.

### 1. Create and Activate Virtual Environment

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt



### 2. Create Environment File (.env)

The repository includes a template file: .env.example
Create your real .env file:

copy .env.example .env

Open .env and replace:

VIRUSTOTAL_API_KEY = YOUR_API_KEY_HERE

With:

VIRUSTOTAL_API_KEY = (PASTE_YOUR_REAL_KEY)

Save the file.

Note:
- .env is excluded from Git for security reasons.
- You must provide your own API key for the system to run.



## Running the Application

### Option A — Web Interface (Recommended)

streamlit run scripts/app.py

Then open your browser and go to:

http://localhost:8501

In the UI:

- Select query type = domain
- Enter a domain (e.g. bbc.co.uk)
- Click "Run scan"

The system will:

- Call the VirusTotal API
- Save raw JSON to data/raw/
- Normalise the data into structured format
- Apply rule-based risk scoring
- Generate a Markdown report in data/reports/
- Display risk level and score in the UI

---

### Option B — Command Line Version

python -m osint_tool.main domain bbc.co.uk

Expected output in terminal:

- Raw data saved to data/raw/
- Normalised data saved to data/normalised/
- Scored data saved to data/normalised/
- Report saved to data/reports/

---

## Running Tests

pytest -q

Expected output:

1 passed

---

## Project Structure

src/osint_tool/
- clients/ (API clients such as VirusTotal)
- pipeline/ (collect → normalise → score → report)
- config.py
- logging_setup.py
- main.py (CLI entry point)

data/
- raw/ (Raw VirusTotal JSON responses)
- normalised/ (Normalised + scored JSON files)
- reports/ (Generated Markdown reports)

scripts/
- app.py (Streamlit web UI)
- demo_run.ps1 (Demo script for Windows)

tests/
- test_smoke.py (Basic pipeline validation test)

.env (Private API key — not committed)
.env.example (Template for API key)
requirements.txt
README.md

---

## Risk Scoring Logic (IPD Version)

The current prototype uses an explainable rule-based scoring model:

- Malicious detections significantly increase risk
- Suspicious detections moderately increase risk
- No malicious or suspicious detections results in LOW risk
- Final score is mapped to LOW / MEDIUM / HIGH
- The system records short textual reasons explaining the risk score

This provides transparency and interpretability suitable for cybersecurity analysis.

---

## Security Considerations

- API keys are stored in .env and excluded from version control
- Raw OSINT data is stored locally
- Modular separation between collection, processing, and scoring
- No sensitive user data is stored by the system

---

## Future Work

- Integrate additional OSINT sources (Shodan, Censys)
- Add classical ML classifier baseline
- Experiment with LLM-based reasoning layer
- Improve UI design and deployment
- Deploy hosted version (Streamlit Cloud / university server)

