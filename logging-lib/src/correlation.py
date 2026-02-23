"""
Correlation ID middleware and context variable.
Injects X-Correlation-ID into every request and binds it to structlog context.
"""

import uuid
from collections.abc import Callable
from contextvars import ContextVar

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")

HEADER_NAME = "X-Correlation-ID"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Reads or generates a correlation ID per request.
    Binds it to structlog context so every log line includes it.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = request.headers.get(HEADER_NAME) or str(uuid.uuid4())
        token = correlation_id_var.set(correlation_id)

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        try:
            response = await call_next(request)
            response.headers[HEADER_NAME] = correlation_id
            return response
        finally:
            correlation_id_var.reset(token)
            structlog.contextvars.clear_contextvars()
