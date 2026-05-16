"""
Structured logging configuration for the security platform.
Provides scan-aware logging with trace IDs and structured output.
"""

import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ScanContextFilter(logging.Filter):
    """Adds scan context fields to log records."""

    def filter(self, record):
        if not hasattr(record, "scan_id"):
            record.scan_id = "-"
        if not hasattr(record, "target"):
            record.target = "-"
        if not hasattr(record, "duration"):
            record.duration = "-"
        return True


class StructuredFormatter(logging.Formatter):
    """Structured log formatter for production use."""

    def format(self, record):
        timestamp = datetime.utcfromtimestamp(record.created).isoformat() + "Z"
        scan_id = getattr(record, "scan_id", "-")
        target = getattr(record, "target", "-")

        base = (
            f"{timestamp} | {record.levelname:<8} | "
            f"{record.name} | scan={scan_id} | target={target} | "
            f"{record.getMessage()}"
        )

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            base += f"\n{record.exc_text}"

        return base


def configure_logging(
    level: str = "INFO",
    log_dir: Optional[str] = None,
    enable_file_logging: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
        log_dir: Directory for log files
        enable_file_logging: Whether to write logs to files
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(StructuredFormatter())
    console_handler.addFilter(ScanContextFilter())
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if enable_file_logging and log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path / "safeguard.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter())
        file_handler.addFilter(ScanContextFilter())
        root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    root_logger.info("Logging configured", extra={"scan_id": "system", "target": "init"})
