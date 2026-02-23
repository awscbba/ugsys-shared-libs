"""
Structured logging configuration using structlog.
Outputs JSON in production, pretty-printed in development.
"""

import logging
import os
import sys

import structlog


def configure_logging(service_name: str, level: str = "INFO") -> None:
    """
    Configure structlog for the service.
    Call once at application startup.

    Args:
        service_name: Injected into every log record as 'service'.
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    is_dev = os.getenv("ENVIRONMENT", "production").lower() in ("development", "local", "dev")

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _add_service_name(service_name),
    ]

    if is_dev:
        renderer = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)


def _add_service_name(service_name: str):
    """Structlog processor that injects the service name."""

    def processor(logger, method, event_dict):
        event_dict.setdefault("service", service_name)
        return event_dict

    return processor


def get_logger(name: str | None = None) -> structlog.BoundLogger:
    """Get a bound structlog logger."""
    return structlog.get_logger(name)
