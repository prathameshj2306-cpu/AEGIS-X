# AEGIS-X
### Offline Security Investigation & Threat Intelligence Platform

**From Raw Security Logs to Explainable Cyber Threat Investigations.**

> **Problem Statement:** PS 02 — Offline Security Incident Triage Assistant  
> **Domain:** Cybersecurity | Small Language Models (SLMs)

---

## 1. Overview

AEGIS-X is an offline-first security investigation platform designed to help security analysts identify, correlate, and investigate suspicious activities from authentication and endpoint logs.

The platform combines deterministic threat detection with a locally running Small Language Model (SLM) to generate explainable, evidence-backed incident investigations without depending on cloud-based AI services.

### Key Capabilities

- Ingest authentication and endpoint logs in CSV and JSON formats.
- Detect suspicious activities using deterministic detection rules.
- Correlate related events by user, device, and time.
- Classify incidents into CRITICAL, HIGH, MEDIUM, and LOW severity levels.
- Generate AI-assisted incident explanations using a local SLM.
- Independently verify AI-generated explanations against investigation evidence.
- Generate standalone HTML and JSON investigation reports.
- Maintain investigation history using batch management.
- Operate locally without external cloud AI APIs.

## 2. System Workflow

```text
CSV / JSON Security Logs
          |
          v
   Log Ingestion
          |
          v
Normalization & Validation
          |
          v
  Threat Detection Engine
          |
          v
   Event Correlation
          |
          v
 Severity Classification
          |
          v
 Local SLM Explanation
   (Ollama + Qwen2.5)
          |
          v
 Evidence Verification
          |
          v
 Investigation Reports
    (HTML / JSON)
```

## 3. Implemented Features

| Module | Status | Description |
|---|---|---|
| Log Ingestion | Complete | CSV/JSON parsing, validation, and normalization |
| Threat Detection | Complete | Four deterministic detection rules |
| Event Correlation | Complete | Correlates events by user, device, and time |
| Severity Classification | Complete | CRITICAL, HIGH, MEDIUM, LOW |
| SQLite Database | Complete | Local persistence of investigation data |
| Batch Management | Complete | Unique batch IDs and isolated investigation history |
| FastAPI Backend | Complete | REST APIs for platform functionality |
| Local SLM Integration | Complete | Ollama with Qwen2.5 1.5B Instruct |
| Evidence Verification | Complete | Checks AI-generated explanations against evidence |
| Report Generation | Complete | Standalone HTML and JSON reports with SHA-256 sidecars |
| React Dashboard | Complete | Web-based security investigation interface |
| Automated Tests | Complete | Backend unit and integration test suite |

## 4. Threat Detection Rules

AEGIS-X currently implements four deterministic detection rules:

1. **Brute-Force Login:** Detects five or more failed login attempts within ten minutes for the same user.
2. **Unusual Login Time:** Identifies login activity outside the configured normal login window (08:00–20:00 UTC).
3. **Privilege Escalation:** Identifies suspicious privilege-change and escalation events.
4. **Suspicious Process Execution:** Detects known malicious tools and suspicious PowerShell arguments.

Detection and severity classification are handled deterministically rather than relying on AI-generated decisions.

## 5. Technology Stack

| Layer | Technologies |
|---|---|
| Backend | Python 3.12, FastAPI |
| Data Validation | Pydantic |
| Database | SQLite |
| AI Integration | Ollama, Qwen2.5 1.5B Instruct |
| Frontend | React 19, Vite |
| API Communication | HTTPX |
| Reporting | HTML, JSON, SHA-256 |
| Testing | Pytest |

## 6. Project Architecture

```text
AEGIS-X/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/
│   │   ├── reporting/
│   │   ├── verification/
│   │   ├── detection/
│   │   ├── ingestion/
│   │   ├── correlation/
│   │   ├── severity/
│   │   ├── database/
│   │   └── schemas/
│   │
│   ├── tests/
│   └── generate_report.py
│
├── frontend/
│   ├── public/
│   └── src/
│       ├── assets/
│       └── components/
│
├── data/
│   └── demo/
│
├── DEMO_GUIDE.md
└── README.md
```

## 7. Installation and Execution

### Prerequisites

- Python 3.12
- Node.js and npm
- Ollama
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/prathameshj2306-cpu/AEGIS-X.git
cd AEGIS-X
```

### Step 2: Set Up the Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Start the backend:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 3: Set Up the Local AI Model

Install Ollama and download the model:

```bash
ollama pull qwen2.5:1.5b-instruct
```

Ensure the Ollama service is running locally.

### Step 4: Set Up the Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

### Step 5: Access the Application

| Service | URL |
|---|---|
| Frontend Dashboard | http://127.0.0.1:5173 |
| Backend API | http://127.0.0.1:8000 |
| API Documentation | http://127.0.0.1:8000/api/docs |
| Health Check | http://127.0.0.1:8000/api/health |

## 8. Demo and Testing

The repository includes synthetic demonstration datasets under `data/demo/`.

These datasets can be used to demonstrate suspicious authentication activity and endpoint compromise scenarios.

For detailed demonstration instructions, refer to **[DEMO_GUIDE.md](DEMO_GUIDE.md)**.

Run the backend test suite:

```powershell
cd backend
python -m pytest tests/ -v
```

## 9. Offline Architecture

AEGIS-X is designed with an offline-first architecture.

- Security log processing happens locally.
- Detection and correlation use local Python logic.
- Investigation data is stored in SQLite.
- AI explanations are generated through a locally hosted Ollama model.
- Reports are generated locally.
- No cloud-based AI API is required for the core investigation workflow.

**Note:** Initial installation and model download require internet access. Subsequent local operation does not require external AI API connectivity.

## 10. Evaluation and Limitations

The project includes a synthetic evaluation dataset containing ten held-out scenarios: five malicious and five benign.

The evaluation achieved zero false positives and zero false negatives on this small synthetic test set. These results demonstrate the tested scenarios and should not be interpreted as real-world detection accuracy.

AEGIS-X is an academic prototype. Its detection rules and AI explanations should be validated further against diverse real-world security logs before operational deployment.

## 11. Future Scope

- Integration of additional security log sources.
- Expanded threat detection rules.
- More extensive evaluation using real-world datasets.
- Advanced anomaly detection and machine learning.
- Improved threat intelligence enrichment.
- Enhanced investigation visualization.

## 12. Project Information

**Project:** AEGIS-X — Offline Security Investigation & Threat Intelligence Platform

**Problem Statement:** PS 02 — Offline Security Incident Triage Assistant

**Repository:** https://github.com/prathameshj2306-cpu/AEGIS-X

**Branch:** `prathamesh-dev`

---

*AEGIS-X — From Raw Security Logs to Explainable Cyber Threat Investigations.*
