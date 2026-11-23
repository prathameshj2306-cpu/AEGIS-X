"""
ASGI Request Size Limit Middleware for AEGIS-X.

Provides true request-level upload size enforcement at the ASGI transport boundary.

Design & Security Guarantees:
1. Early Content-Length Header Check:
   If the incoming request declares a Content-Length > 10 MB (10,485,760 bytes),
   the middleware immediately rejects the request with HTTP 413 and our canonical
   ErrorResponse envelope, without forwarding the request to downstream routers or parsers.

2. Dynamic ASGI Stream Byte Counting:
   If Content-Length is missing (e.g. chunked transfer encoding) or misleading,
   the middleware intercepts ASGI receive() calls and maintains a running counter of
   incoming body bytes. As soon as accumulated chunks exceed 10 MB, reading is halted,
   preventing Starlette's multipart parser (python-multipart) from buffering or spooling
   oversized files to disk or memory.

3. Complete Request Overhead Scope:
   Note: This limit applies to the complete HTTP request payload received by ASGI,
   which for multipart uploads includes the multipart boundary and header overhead
   (typically ~200-400 bytes).

4. Transparent Pass-through:
   Non-mutating HTTP methods (GET, HEAD, OPTIONS) and requests below the size ceiling
   pass through with zero overhead.
"""

import json
import logging
from datetime import datetime, timezone
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.schemas import ErrorResponse

logger = logging.getLogger("aegis.api.middleware")

MAX_REQUEST_BYTES = 10 * 1024 * 1024  # 10 MB in bytes


class PayloadTooLargeError(Exception):
    """Internal exception raised when dynamic ASGI chunk read exceeds size limit."""

    def __init__(self, bytes_received: int, max_bytes: int):
        self.bytes_received = bytes_received
        self.max_bytes = max_bytes
        super().__init__(
            f"Request payload exceeded maximum permitted size of {max_bytes} bytes (10 MB)."
        )


class RequestSizeLimitMiddleware:
    """ASGI middleware that enforces a strict ceiling on incoming request body size."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # 1. Early Content-Length check
        content_length: int | None = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    content_length = int(value.decode("latin-1"))
                except ValueError:
                    pass
                break

        if content_length is not None and content_length > self.max_bytes:
            logger.warning(
                f"Rejecting oversized request early: Content-Length {content_length} > {self.max_bytes} bytes."
            )
            await self._send_413_response(
                scope,
                send,
                f"Request size ({content_length} bytes) exceeds maximum permitted limit of {self.max_bytes} bytes (10 MB).",
            )
            return

        # 2. Dynamic stream byte counting via wrapped receive
        bytes_received = 0
        payload_exceeded = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal bytes_received, payload_exceeded
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                bytes_received += len(chunk)
                if bytes_received > self.max_bytes:
                    payload_exceeded = True
                    logger.warning(
                        f"Dynamic request payload exceeded limit while reading: {bytes_received} > {self.max_bytes} bytes."
                    )
                    raise PayloadTooLargeError(bytes_received, self.max_bytes)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if payload_exceeded:
                if message["type"] == "http.response.start" and not response_started:
                    response_started = True
                    await self._send_413_response(
                        scope,
                        send,
                        f"Request payload exceeded maximum permitted limit of {self.max_bytes} bytes (10 MB) while streaming.",
                    )
                return

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except PayloadTooLargeError:
            if not response_started:
                await self._send_413_response(
                    scope,
                    send,
                    f"Request payload exceeded maximum permitted limit of {self.max_bytes} bytes (10 MB) while streaming.",
                )

    async def _send_413_response(self, scope: Scope, send: Send, detail: str) -> None:
        """Send a structured HTTP 413 response conforming to ErrorResponse schema."""
        error_payload = ErrorResponse(
            error="Payload Too Large",
            detail=detail,
            status_code=413,
            timestamp=datetime.now(timezone.utc),
        )
        body = json.dumps(error_payload.model_dump(mode="json")).encode("utf-8")

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("latin-1")),
        ]

        # Preserve CORS origin header for authorized frontend
        for name, value in scope.get("headers", []):
            if name.lower() == b"origin" and value == b"http://127.0.0.1:5173":
                headers.append((b"access-control-allow-origin", b"http://127.0.0.1:5173"))
                headers.append((b"access-control-allow-credentials", b"true"))
                break

        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
