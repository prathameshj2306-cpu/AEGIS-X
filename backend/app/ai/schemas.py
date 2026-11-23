"""
Schemas for SLM analysis output and status tracking in AEGIS-X.

All inference results (from Ollama or deterministic fallback) are strictly validated
against AIAnalysisOutput.
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class AIStatus(str, Enum):
    """Execution status of the SLM analysis pipeline."""
    SUCCESS = "SUCCESS"          # Ollama responded with valid, schema-compliant JSON
    FALLBACK = "FALLBACK"        # Ollama failed/timed out/malformed; deterministic fallback used
    UNAVAILABLE = "UNAVAILABLE"  # Ollama service is offline/unreachable; fallback used


class AIAnalysisOutput(BaseModel):
    """Rigid Pydantic schema for structured incident explanations.

    Enforces that both the SLM and deterministic fallback supply all required fields
    with non-empty structured strings and actionable lists. Rejects empty or whitespace-only
    strings.
    """
    summary: str = Field(
        ...,
        description="Concise executive summary of what occurred in the incident"
    )
    attack_interpretation: str = Field(
        ...,
        description="Technical breakdown and tactical interpretation of the attack pattern"
    )
    potential_impact: str = Field(
        ...,
        description="Potential security risk, blast radius, and system impact"
    )
    recommended_actions: list[str] = Field(
        ...,
        description="Prioritized list of remediation and containment steps"
    )
    cited_event_ids: list[str] = Field(
        default_factory=list,
        description="Explicit event IDs cited in support of this analysis"
    )

    @field_validator("summary", "attack_interpretation", "potential_impact")
    @classmethod
    def validate_non_empty_strings(cls, v: str, info) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"Field '{info.field_name}' must be a non-empty string and cannot be whitespace-only.")
        return v.strip()

    @field_validator("recommended_actions")
    @classmethod
    def validate_recommended_actions(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list) or len(v) == 0:
            raise ValueError("Field 'recommended_actions' must be a non-empty list of actions.")
        cleaned = []
        for i, item in enumerate(v):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Entry {i} in 'recommended_actions' is empty or whitespace-only.")
            cleaned.append(item.strip())
        return cleaned

    @field_validator("cited_event_ids")
    @classmethod
    def validate_cited_event_ids(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list):
            raise ValueError("Field 'cited_event_ids' must be a list of strings.")
        cleaned = []
        for i, item in enumerate(v):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Entry {i} in 'cited_event_ids' is empty or whitespace-only.")
            cleaned.append(item.strip())
        return cleaned

    model_config = {"frozen": False, "extra": "forbid"}
