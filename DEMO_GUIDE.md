# AEGIS-X — Demonstration & Operator Guide
**Offline Security Investigation & Threat Intelligence Platform**
*From Raw Security Logs to Explainable Cyber Threat Investigations.*

---

## 1. System Overview & Architecture

AEGIS-X is an enterprise-grade, **100% offline-capable** threat detection and explainable investigation platform. It transforms unnormalized authentication and endpoint telemetry into correlated, MITRE ATT&CK-aligned security incidents, provides SLM-driven attack explanations audited by an independent evidence verification engine, and produces tamper-evident investigation reports with cryptographic SHA-256 checksums.

```
+-----------------------------------------------------------------------------------+
|                            AEGIS-X DARK SOC DASHBOARD                             |
|                        React 19 + Vite (Port 5173)                                |
+----------------------------------------+------------------------------------------+
                                         | REST API (JSON / Multipart)
                                         v
+-----------------------------------------------------------------------------------+
|                               FASTAPI REST BACKEND                                |
|                               Uvicorn (Port 8000)                                 |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  | ASGI 10MB Limiter  |  | Ingestion & Source   |  | Monotonic Atomic SQLite   |  |
|  | (Early Body Drop)  |  | Inference Engine     |  | Transaction Locking       |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  | 4 Detection Rules  |  | Correlation Engine   |  | Deterministic Severity    |  |
|  | (BF, PE, SP, Auth) |  | (Incident Builder)   |  | Mathematical Multipliers  |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  | Local Ollama SLM   |  | Offline Fallback     |  | Independent Evidence      |  |
|  | (Qwen2.5 1.5B)     |  | Rule Narrative Engine|  | Ground-Truth Verifier     |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Cryptographic Reporting: HTML, JSON, SHA-256 Checksum Sidecars              |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Quick Start (2-Minute Startup)

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- *(Optional)* Ollama running locally with `qwen2.5:1.5b` (If offline or stopped, AEGIS-X automatically falls back to its deterministic cybersecurity rule narrative engine without interrupting operations).

---

### Step 1: Start the Backend (Terminal 1)
Open a PowerShell terminal in `C:\AEGIS-X`:

```powershell
# Navigate to project root
cd C:\AEGIS-X

# Start the FastAPI application with Uvicorn
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
```

Expected backend terminal output:
```
INFO:     Started server process [...]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

---

### Step 2: Start the Frontend (Terminal 2)
Open a second PowerShell terminal in `C:\AEGIS-X`:

```powershell
# Navigate to frontend directory
cd C:\AEGIS-X\frontend

# Start Vite development server
npm run dev
```

Expected frontend terminal output:
```
  VITE v8.3.6  ready in ~200 ms

  ➜  Local:   http://127.0.0.1:5173/
  ➜  Network: use --host to expose
```

---

### Step 3: Open the Platform
Open your browser and navigate to:
👉 **`http://127.0.0.1:5173`**

---

## 3. Recommended 5-Minute Demonstration Walkthrough

Follow this scripted sequence to demonstrate every capability required by the evaluation jury:

### Minute 1: System Telemetry & Dark SOC Overview
1. Open `http://127.0.0.1:5173`.
2. Observe the top **Header telemetry**:
   - Platform Status badge (`HEALTHY` or `DEGRADED`).
   - SQLite status with live stored events count.
   - Local SLM Engine status:
     - If Ollama is running: Shows `SLM: qwen2.5:1.5b`.
     - If Ollama is offline: Shows `AI Fallback Engine Ready` (honest, transparent disclosure).
3. Click on the **System Status** tab in the sidebar:
   - Walk through the architecture cards: FastAPI REST Backend, SQLite Persistence, Local SLM Engine, Evidence Verifier, Cryptographic Controls, and Model Evaluation (100% Precision, Recall, F1).

### Minute 2: Log Ingestion & Drag-and-Drop Upload
1. Click on **Log Ingestion** in the sidebar.
2. Select **Auto-detect Source** or specify **Authentication**.
3. Drag & drop or select the sample demo log file:
   - `C:\AEGIS-X\data\demo\auth_attack_demo.csv`
4. Click **Upload & Normalize Events**:
   - Point out the instant feedback: Events parsed, schema normalized, and stored in SQLite.
   - Point out the atomic monotonic event IDs assigned (`E000001`, `E000002`...).
5. Repeat for endpoint log:
   - `C:\AEGIS-X\data\demo\endpoint_compromise_demo.csv` (Source: Endpoint).
6. Point out the early ASGI 10 MB payload protection and signature validation that rejects non-security logs.

### Minute 3: Threat Detection Pipeline & Incident Triage Matrix
1. Click the glowing **"RUN THREAT INVESTIGATION"** button.
2. The platform executes:
   - 4 Detection Rules (Brute-Force, Privilege Escalation, Suspicious Process, Lateral Movement).
   - Event Correlation Engine (groups related attack indicators into coherent incidents).
   - Deterministic Severity Scoring (calculates mathematical base score, asset weight, and pattern multiplier).
3. The platform navigates automatically to the **Incident Matrix**:
   - Filter by Severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
   - Use the live search bar to search for `admin` or `SRV-FINANCE01`.
   - Point out the transparent pattern tags (e.g., `multi_stage_attack`, `brute_force_with_success`).

### Minute 4: Deep Investigation, SLM Threat Narrative & Evidence Verification
1. Click **"Investigate"** on the `CRITICAL` multi-stage incident.
2. Walk through the **Deterministic Severity Rationale** card:
   - Explain how severity is calculated mathematically from detection confidence and asset criticality—never guessed.
3. Click **"Analyze Incident with AI"**:
   - AEGIS-X triggers the local SLM (`qwen2.5:1.5b`) or offline deterministic fallback engine.
   - Observe the structured findings:
     - Executive Threat Summary
     - Tactical Attack Interpretation
     - Potential Business & Security Impact
     - Prioritized Remediation Steps (numbered actionable checklist)
4. Highlight the **Independent Evidence Verification Panel**:
   - Point out the `VERIFIED` status.
   - Show the breakdown: Total references checked, valid references, and discrepancy audits.
   - Explain how this guarantees that AI narrative claims cannot hallucinate non-existent evidence IDs.
5. Scroll down to the **Chronological Evidence Chain**:
   - Click on any event row to expand and inspect the full raw JSON record from SQLite.

### Minute 5: Cryptographic Investigation Reports & Tamper-Proofing
1. Click **"Export Reports"** (or select the **Reports** tab).
2. Select format: **Both (HTML & JSON)** with **SHA-256 Sidecar Checksums** enabled.
3. Click **"Generate Investigation Report"**:
   - The platform creates executive HTML and machine-readable JSON reports.
   - Computes deterministic SHA-256 digest sidecars (`.sha256`).
4. Click **Download HTML Report** and open it in the browser:
   - Display the clean, executive-ready investigation summary.
5. Click **Download .sha256**:
   - Demonstrate the cryptographic checksum ensuring auditability and tamper evidence.

---

## 4. Subsystem Verification & CLI Regression

To demonstrate platform integrity from the command line:

### 1. Run Complete Pytest Suite (317 Tests Passing)
```powershell
python -m pytest backend\tests\ -v
```

### 2. Run Ground-Truth Evaluation Benchmark (F1 = 1.0)
```powershell
python backend\evaluate.py
```
Expected output:
```
Confusion Matrix:      TP=5 | FP=0 | FN=0 | TN=5
Precision:             1.0000
Recall:                1.0000
F1 Score:              1.0000
Overall Accuracy:      1.0000
All 10 Scenarios:      PASSED
```

### 3. Verify Dataset Immutability (Byte-for-Byte SHA-256 Match)
```powershell
Get-FileHash data\evaluation\* | Format-List Path, Hash
```
Approved baseline hashes:
- `data/evaluation/auth_events.csv`: `834361C1CD799D7C3AD22D7D62D9DC86155DD48F7B214920BF2463CBFE34C8A3`
- `data/evaluation/endpoint_events.csv`: `50CC2F267CC09E1F92C4E0EB78E632403C714192A2E8CA93CE8EC7F4D67777DA`
- `data/evaluation/scenarios.json`: `8C58C339714F5E4CD70EC4B5F8F8E2727A7E1685A9ACB85378611569633A0104`

---

## 5. Troubleshooting & FAQ

| Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| **"AI Fallback Engine Ready" badge shown** | Ollama is not running on port 11434. | This is normal and intentional! AEGIS-X is 100% offline-ready. If you wish to run real SLM inference, run `ollama serve` and ensure `qwen2.5:1.5b` is pulled (`ollama pull qwen2.5:1.5b`). |
| **Port 8000 already in use** | A previous uvicorn instance is active. | Terminate the process: `Stop-Process -Name python -Force` or run on an alternate port and update `frontend/vite.config.js`. |
| **Port 5173 already in use** | Another frontend Vite server is active. | Kill existing node process or let Vite choose the next available port. |
| **CORS error in browser** | Accessing backend directly from an origin other than `http://127.0.0.1:5173`. | Always access through `http://127.0.0.1:5173` where Vite proxies `/api` to `127.0.0.1:8000`. |
| **Upload returns HTTP 413** | File exceeds 10 MB limit. | Enforced at ASGI streaming boundary to prevent memory exhaustion DoS attacks. Upload security logs under 10 MB. |
