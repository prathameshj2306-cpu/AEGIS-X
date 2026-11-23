"""
Global exception handlers and structured error responses for AEGIS-X REST API.
"""

import logging
from datetime import datetime, timezone
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from app.api.middleware import PayloadTooLargeError
from app.api.schemas import ErrorResponse

logger = logging.getLogger("aegis.api")


def register_exception_handlers(app: FastAPI) -> None:
    """Register uniform structured error handlers on the FastAPI application."""

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        error_payload = ErrorResponse(
            error="HTTP Exception",
            detail=str(exc.detail),
            status_code=exc.status_code,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        error_payload = ErrorResponse(
            error="HTTP Exception",
            detail=str(exc.detail),
            status_code=exc.status_code,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Sanitize validation error details to avoid raw payload leakage
        sanitized_errors = []
        for err in exc.errors():
            sanitized_errors.append({
                "loc": [str(loc_item) for loc_item in err.get("loc", [])],
                "msg": err.get("msg", "Invalid input"),
                "type": err.get("type", "value_error"),
            })

        error_payload = ErrorResponse(
            error="Validation Error",
            detail=sanitized_errors,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(FileNotFoundError)
    async def not_found_handler(request: Request, exc: FileNotFoundError) -> JSONResponse:
        error_payload = ErrorResponse(
            error="Resource Not Found",
            detail=str(exc),
            status_code=status.HTTP_404_NOT_FOUND,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(PayloadTooLargeError)
    async def payload_too_large_handler(request: Request, exc: PayloadTooLargeError) -> JSONResponse:
        error_payload = ErrorResponse(
            error="Payload Too Large",
            detail=str(exc),
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        error_payload = ErrorResponse(
            error="Bad Request",
            detail=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_payload.model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
        error_payload = ErrorResponse(
            error="Internal Server Error",
            detail="An internal server error occurred during request processing.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_payload.model_dump(mode="json"),
        )
