"""
AI integration module for AEGIS-X.
"""

from app.ai.client import OllamaClient, clean_json_response
from app.ai.fallback import generate_deterministic_fallback
from app.ai.prompts import SYSTEM_PROMPT, build_incident_prompt
from app.ai.schemas import AIAnalysisOutput, AIStatus

__all__ = [
    "AIAnalysisOutput",
    "AIStatus",
    "OllamaClient",
    "clean_json_response",
    "generate_deterministic_fallback",
    "build_incident_prompt",
    "SYSTEM_PROMPT",
]
