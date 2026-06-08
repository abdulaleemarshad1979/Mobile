"""
CyberSentinel — Structured Logging
Uses Python's logging module with structured output.
Production: JSON lines.  Development: colored console.
"""

import logging
import sys
from config import settings


def _setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    # Prevent duplicate handlers on reload
    if logger.handlers:
        return logger

    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if settings.is_production:
        # JSON-style format for log aggregators (Datadog, Loki, etc.)
        fmt = (
            '{"time":"%(asctime)s","level":"%(levelname)s",'
            '"module":"%(name)s","msg":%(message)s}'
        )
    else:
        # Human-readable for local dev
        fmt = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"

    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    return _setup_logger(name)
