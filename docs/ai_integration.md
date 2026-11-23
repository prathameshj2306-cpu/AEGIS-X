# AEGIS-X — Local Small Language Model (SLM) & Deterministic Fallback

## 1. Architectural Role & Principles
In AEGIS-X, the Small Language Model (SLM) is strictly an **explainability and triage enhancement tool**. It is decoupled from the deterministic core detection and correlation engine.

### Strict Security & Reliability Invariants:
1. **The SLM never decides detections, severity, or evidence.** Detections and severity classifications are computed deterministically by the rules engine and severity classifier.
2. **100% Offline Operation:** All inference runs against a local Ollama daemon (`http://127.0.0.1:11434`) using quantized open-weights models (`qwen2.5:1.5b-instruct`). No external cloud APIs, telemetry, or remote dependencies are used.
3. **Fail-Safe Graceful Fallback:** SLM unavailability, timeouts, non-JSON output, or validation failures NEVER interrupt incident creation or pipeline processing. When an anomaly occurs, high-quality, pattern-grounded deterministic explanations are generated seamlessly.
4. **Status Transparency:** Every generated analysis clearly carries its execution status:
   - `SUCCESS`: Valid, schema-compliant JSON produced by Ollama.
   - `FALLBACK`: Ollama timed out, produced invalid JSON, or returned an error; deterministic template used.
   - `UNAVAILABLE`: Local Ollama daemon was offline or unreachable.

---

## 2. Configuration & Resource Profiles
All AI parameters are centrally configured in `app.config.AegisConfig`:

| Configuration Key | Default Value | Description |
| :--- | :--- | :--- |
| `ollama_base_url` | `http://127.0.0.1:11434` | Local Ollama API server endpoint |
| `ollama_model` | `qwen2.5:1.5b-instruct` | Quantized local SLM |
| `ollama_timeout` | `60` | Request timeout in seconds |
| `temperature` | `0.1` | Low sampling temperature for factual consistency |

### Resource Constraint (Target: 8 GB RAM Laptop)
- `qwen2.5:1.5b-instruct` requires ~1.0 GB to 1.3 GB of VRAM / RAM in 4-bit/8-bit quantization.
- Only a single model instance is queried sequentially.
- No background workers or continuous polling services are created.

---

## 3. Ollama Installation & Setup Guide

### Step 1: Verify / Install Ollama
Download and install Ollama for Windows from [ollama.com](https://ollama.com).

### Step 2: Pull the Model
Run the following in PowerShell:
```powershell
ollama pull qwen2.5:1.5b-instruct
```

### Step 3: Verify Model Execution
Test that the model runs locally:
```powershell
ollama run qwen2.5:1.5b-instruct "Hello! Are you running locally?"
```

---

## 4. Structured Output Contract

The model response and fallback generator strictly adhere to the `AIAnalysisOutput` Pydantic model (`app/ai/schemas.py`):

```json
{
  "summary": "<concise executive summary of what occurred in the incident>",
  "attack_interpretation": "<technical explanation of the observed attack sequence and tactics>",
  "potential_impact": "<explanation of potential business and system security impact, blast radius>",
  "recommended_actions": [
    "<action 1: immediate containment>",
    "<action 2: credential/host remediation>",
    "<action 3: investigation/monitoring recommendation>"
  ],
  "cited_event_ids": ["<event_id_1>", "<event_id_2>"]
}
```

---

## 5. Testing & Verification

The test suite does not require a live model or running Ollama daemon. All network interactions are mocked:

```powershell
# Run the AI unit tests
pytest backend/tests/test_ai_fallback.py -v

# Run the complete test suite
pytest backend/tests/ -v
```
