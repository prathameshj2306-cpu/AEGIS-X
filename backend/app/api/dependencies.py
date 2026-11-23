"""
FastAPI dependencies for AEGIS-X REST API.

Provides clean dependency injection for:
- Central AegisConfig
- Database connection lifecycle management
- Local Ollama SLM client
"""

import os
from typing import Generator
from fastapi import Request

from app.ai.client import OllamaClient
from app.config import AegisConfig
from app.database.store import AegisDatabase


def get_config(request: Request) -> AegisConfig:
    """Retrieve AegisConfig from application state."""
    return getattr(request.app.state, "config", AegisConfig())


def get_db(request: Request) -> Generator[AegisDatabase, None, None]:
    """Yield an active AegisDatabase connection with guaranteed closure."""
    db_path = getattr(request.app.state, "db_path", "backend/aegis.db")
    db = AegisDatabase(db_path)
    try:
        yield db
    finally:
        db.close()


def get_ollama_client(request: Request) -> OllamaClient:
    """Retrieve or construct OllamaClient using application configuration."""
    config = get_config(request)
    return OllamaClient(config=config)
