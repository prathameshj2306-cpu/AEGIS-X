# AEGIS-X

**Offline Security Investigation & Threat Intelligence Platform**

*From Raw Security Logs to Explainable Cyber Threat Investigations.*

## Overview

AEGIS-X is a locally running security incident triage assistant that:
- Accepts authentication and endpoint logs (CSV/JSON).
- Detects suspicious activity using deterministic rules.
- Correlates events by user, device, and time.
- Classifies incident severity.
- Generates evidence-backed investigation reports.
- Uses a local Small Language Model (SLM) for incident explanation.

All core functionality works **offline** after initial setup.

## Current Status: Phase 1 — Backend Core ✅

### What's Built

| Module | Status | Description |
|---|---|---|
| Schemas | ✅ | Pydantic models for events, detections, incidents |
| Ingestion | ✅ | CSV/JSON parsing, validation, normalization |
| Detection | ✅ | 4 rules: brute-force, unusual login, priv esc, suspicious process |
| Correlation | ✅ | Groups detections by user/device/time into incidents |
| Severity | ✅ | Deterministic CRITICAL/HIGH/MEDIUM/LOW classification |
| Simulator | ✅ | Synthetic data generator (5 malicious + 5 benign scenarios) |
| Database | ✅ | SQLite persistence for events, detections, incidents |
| Tests | ✅ | 67 unit + integration tests, all passing |

### Quick Start

```bash
# From the project root
cd backend

# Install dependencies
pip install pydantic==2.10.6 pytest==8.3.4 pytest-cov==6.0.0 python-dateutil==2.9.0.post0

# Run the full pipeline (generates data + analyzes + persists)
python run_pipeline.py

# Run tests
python -m pytest tests/ -v

# Generate data only
python run_pipeline.py --generate-only
```

### Project Structure

```
AEGIS-X/
├── backend/
│   ├── app/
│   │   ├── config.py          — Central configuration
│   │   ├── schemas/           — Pydantic data models
│   │   ├── ingestion/         — CSV/JSON ingestion
│   │   ├── detection/         — 4 detection rules + engine
│   │   ├── correlation/       — Event correlation
│   │   ├── severity/          — Severity classification
│   │   ├── simulator/         — Synthetic data generator
│   │   └── database/          — SQLite persistence
│   ├── tests/                 — 67 unit + integration tests
│   ├── run_pipeline.py        — CLI entry point
│   └── requirements.txt
├── data/
│   ├── development/           — Dev dataset (seed=42)
│   └── evaluation/            — Held-out eval dataset (seed=7777)
├── docs/
│   └── data_contract.md       — Schema documentation
├── .gitignore
├── .env.example
└── README.md
```

## Technology Stack

- **Python 3.12** — Backend language
- **Pydantic** — Data validation and schemas
- **SQLite** — Local persistence
- **Pytest** — Testing framework

### Planned (Phase 2+)
- **FastAPI** — HTTP API
- **Ollama + Qwen2.5 1.5B** — Local SLM for incident explanation
- **React 19 + Vite + Tailwind** — SOC Dashboard (Phase 4)

## Detection Rules

1. **Brute-Force Login** — ≥5 failed logins within 10 minutes per user
2. **Unusual Login Time** — Logins outside 08:00–20:00 (with schedule exceptions)
3. **Privilege Escalation** — Privilege change/escalation events
4. **Suspicious Process** — Known malicious tools + suspicious PowerShell args

## License

Internal project — not for distribution.
