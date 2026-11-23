"""
Ollama Async Client for AEGIS-X.

Provides robust, offline interaction with the local Small Language Model (SLM),
enforcing:
- Configurable base URL (default: http://127.0.0.1:11434)
- Configurable model (default: qwen2.5:1.5b-instruct)
- Temperature 0.1 for deterministic, factual outputs
- Configurable timeout (default: 60s)
- Format: "json" in Ollama request
- Robust JSON extraction (handles raw JSON or markdown-fenced ```json blocks)
- Strict Pydantic validation via AIAnalysisOutput
- Strict verification of AI-cited event IDs against incident evidence event IDs
- Graceful deterministic fallback when Ollama is offline, unreachable, times out, or produces invalid output
- Never raises unhandled network exceptions to caller (returns AIStatus and AIAnalysisOutput)
"""

import json
import logging
import re
from typing import Optional, Tuple

import httpx

from app.ai.fallback import generate_deterministic_fallback
from app.ai.prompts import SYSTEM_PROMPT, build_incident_prompt
from app.ai.schemas import AIAnalysisOutput, AIStatus
from app.config import AegisConfig
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection, Incident

logger = logging.getLogger("aegis.ai")


def sanitize_error_text(text: str, max_length: int = 150) -> str:
    """Sanitize untrusted error response text for safe logging and status reporting.

    - Normalizes newlines, carriage returns, tabs, and control characters to single spaces.
    - Removes non-printable characters.
    - Collapses consecutive whitespace.
    - Truncates output to a bounded maximum length (default 150 characters).
    - Ensures no raw prompts or sensitive security records leak into error details.
    """
    if not text:
        return ""
    # Replace control characters (0-31, 127) including CR, LF, and TAB with spaces
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text))
    # Filter any remaining non-printable characters
    cleaned = "".join(ch if (ch == " " or ch.isprintable()) else " " for ch in cleaned)
    # Collapse multiple spaces and strip ends
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip() + "..."
    return cleaned


def find_all_valid_json_objects(text: str) -> list[str]:
    """Find all complete, top-level valid JSON objects in text using balanced brace tracking.

    Correctly tracks quotes, escape sequences, and nested braces so that braces
    inside strings or nested objects are handled properly.
    """
    objects = []
    length = len(text)
    i = 0
    while i < length:
        if text[i] == "{":
            start_idx = i
            depth = 1
            in_string = False
            escape = False
            j = i + 1
            matched = False
            while j < length:
                char = text[j]
                if escape:
                    escape = False
                elif in_string:
                    if char == "\\":
                        escape = True
                    elif char == '"':
                        in_string = False
                else:
                    if char == '"':
                        in_string = True
                    elif char == "{":
                        depth += 1
                    elif char == "}":
                        depth -= 1
                        if depth == 0:
                            candidate = text[start_idx : j + 1].strip()
                            try:
                                parsed = json.loads(candidate)
                                if isinstance(parsed, dict):
                                    objects.append(candidate)
                                    matched = True
                                    i = j  # advance past this object
                            except Exception:
                                pass
                            break
                j += 1
            if matched:
                i += 1
                continue
        i += 1
    return objects


def extract_balanced_json_object(text: str) -> Optional[str]:
    """Extract a single complete, valid JSON object from text using brace tracking.

    Returns the JSON object string if exactly one valid JSON object is found.
    If zero or multiple valid JSON objects are found (ambiguous), returns None.
    Rejects incomplete, unbalanced, or non-object structures.
    """
    objects = find_all_valid_json_objects(text)
    if len(objects) == 1:
        return objects[0]
    return None


def clean_json_response(raw_text: str) -> str:
    """Extract and sanitize JSON from model output string.

    Handles:
    - Raw JSON objects.
    - JSON enclosed in markdown code fences (```json ... ``` or ``` ... ```).
    - Harmless surrounding text before or after a single valid JSON object.
    - Nested JSON objects and curly braces inside JSON strings.
    - Rejects ambiguous responses: if multiple valid JSON objects are detected
      (across multiple fenced blocks or in surrounding text), returns empty string
      so inference safely falls back.
    - Rejects incomplete, unmatched, or non-object JSON.
    """
    text = raw_text.strip()
    if not text:
        return ""

    # Check for markdown code fences first
    fenced_blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fenced_blocks:
        fenced_objects = []
        for block in fenced_blocks:
            fenced_objects.extend(find_all_valid_json_objects(block))

        # Multiple valid JSON objects across fenced blocks -> ambiguous, reject!
        if len(fenced_objects) > 1:
            return ""

        if len(fenced_objects) == 1:
            # Check if there are also valid JSON objects outside code fences
            text_without_fences = re.sub(r"```(?:json)?\s*[\s\S]*?\s*```", " ", text)
            outside_objects = find_all_valid_json_objects(text_without_fences)
            if outside_objects:
                # Ambiguous: valid object inside fence AND outside fence
                return ""
            return fenced_objects[0]

    # No valid objects found in fences (or no fences present)
    # Search the entire text for valid JSON objects
    all_objects = find_all_valid_json_objects(text)
    if len(all_objects) == 1:
        return all_objects[0]
    if len(all_objects) > 1:
        # Ambiguous: multiple valid JSON objects in text
        return ""

    # 0 valid objects found -> return stripped text so caller/json.loads fails closed
    return text


class OllamaClient:
    """Client for local Ollama SLM inference with fallback guarantees."""

    def __init__(self, config: Optional[AegisConfig] = None):
        self.config = config or AegisConfig()
        self.base_url = self.config.ollama_base_url.rstrip("/")
        self.model = self.config.ollama_model
        self.timeout = float(self.config.ollama_timeout)
        self.temperature = 0.1

    async def check_health(self) -> bool:
        """Check if local Ollama daemon is reachable.

        Returns:
            True if Ollama responded with HTTP 200, False otherwise.
        """
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    async def analyze_incident(
        self,
        incident: Incident,
        events: Optional[list[NormalizedEvent]] = None,
        detections: Optional[list[Detection]] = None,
    ) -> Tuple[AIAnalysisOutput, AIStatus, Optional[str]]:
        """Analyze an incident using local SLM, falling back to deterministic template on any failure.

        Args:
            incident: Correlated incident instance.
            events: Optional list of supporting events.
            detections: Optional list of triggering detections.

        Returns:
            Tuple of (AIAnalysisOutput, AIStatus, error_message_or_None)
        """
        prompt = build_incident_prompt(incident, events, detections)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )

            if response.status_code != 200:
                sanitized_text = sanitize_error_text(response.text, max_length=150)
                err_msg = f"Ollama HTTP error {response.status_code}: {sanitized_text}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            try:
                data = response.json()
            except Exception as ex:
                sanitized_ex = sanitize_error_text(str(ex), max_length=150)
                err_msg = f"Ollama response envelope is not valid JSON: {sanitized_ex}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            if not isinstance(data, dict):
                err_msg = f"Ollama response envelope must be a JSON object, got {type(data).__name__}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            if "response" not in data:
                err_msg = "Ollama response envelope missing required 'response' field"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            raw_response = data["response"]
            if not isinstance(raw_response, str):
                err_msg = f"Ollama returned non-string response: {type(raw_response).__name__}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            if not raw_response.strip():
                err_msg = "Ollama returned empty response string"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            cleaned = clean_json_response(raw_response)
            if not cleaned:
                err_msg = "Model response is empty or contains ambiguous JSON objects"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            parsed_dict = json.loads(cleaned)

            if not isinstance(parsed_dict, dict):
                err_msg = f"Model response must be a JSON object, got {type(parsed_dict).__name__}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            # Strict Pydantic validation
            try:
                analysis_output = AIAnalysisOutput(**parsed_dict)
            except Exception as ex:
                sanitized_ex = sanitize_error_text(str(ex), max_length=150)
                err_msg = f"Model analysis validation error: {sanitized_ex}"
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            # Requirement 1: Validate AI-cited event IDs against actual incident evidence event IDs
            valid_evidence_ids = set(incident.evidence_event_ids)
            invalid_citations = []
            seen_citations = set()
            deduped_citations = []

            for eid in analysis_output.cited_event_ids:
                if eid not in valid_evidence_ids:
                    invalid_citations.append(eid)
                elif eid not in seen_citations:
                    seen_citations.add(eid)
                    deduped_citations.append(eid)

            if invalid_citations:
                err_msg = (
                    f"Model hallucinated/cited untrusted event IDs not present in incident evidence: "
                    f"{invalid_citations}. Expected subset of: {list(valid_evidence_ids)}"
                )
                logger.warning(err_msg)
                fallback = generate_deterministic_fallback(incident, events, detections)
                return fallback, AIStatus.FALLBACK, err_msg

            # Update with deduplicated valid citations
            analysis_output.cited_event_ids = deduped_citations

            return analysis_output, AIStatus.SUCCESS, None

        except (httpx.ConnectError, httpx.ConnectTimeout) as ex:
            sanitized_ex = sanitize_error_text(str(ex), max_length=150)
            err_msg = f"Ollama is unavailable or offline at {self.base_url}: {sanitized_ex}"
            logger.info(err_msg)
            fallback = generate_deterministic_fallback(incident, events, detections)
            return fallback, AIStatus.UNAVAILABLE, err_msg

        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as ex:
            sanitized_ex = sanitize_error_text(str(ex), max_length=150)
            err_msg = f"Ollama inference timed out after {self.timeout}s: {sanitized_ex}"
            logger.warning(err_msg)
            fallback = generate_deterministic_fallback(incident, events, detections)
            return fallback, AIStatus.FALLBACK, err_msg

        except (httpx.HTTPStatusError, httpx.ProtocolError, httpx.TransportError, httpx.RequestError) as ex:
            sanitized_ex = sanitize_error_text(str(ex), max_length=150)
            err_msg = f"Ollama HTTP/transport error: {sanitized_ex}"
            logger.warning(err_msg)
            fallback = generate_deterministic_fallback(incident, events, detections)
            return fallback, AIStatus.FALLBACK, err_msg

        except json.JSONDecodeError as ex:
            sanitized_ex = sanitize_error_text(str(ex), max_length=150)
            err_msg = f"Model response is not valid JSON: {sanitized_ex}"
            logger.warning(err_msg)
            fallback = generate_deterministic_fallback(incident, events, detections)
            return fallback, AIStatus.FALLBACK, err_msg

        except Exception as ex:
            sanitized_ex = sanitize_error_text(str(ex), max_length=150)
            err_msg = f"Model analysis validation error: {sanitized_ex}"
            logger.warning(err_msg)
            fallback = generate_deterministic_fallback(incident, events, detections)
            return fallback, AIStatus.FALLBACK, err_msg
