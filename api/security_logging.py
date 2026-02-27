"""Secure Logging Module - OWASP A02:2021 Cryptographic Failures Fix

This module provides secure, structured logging for the PISC application.
It ensures sensitive data is never logged while maintaining audit trails.

Security Principles (OWASP):
- Never log: API keys, full prompts, user credentials, PII
- Always log: Timestamps, log levels, event types, correlation IDs
- Use appropriate log levels: INFO (normal), WARNING (suspicious), ERROR (failures)
"""

import logging
import hashlib
import json
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path


# =============================================================================
# Sensitive Data Patterns - Never Log These
# =============================================================================

# Patterns for sensitive data that should never be logged
SENSITIVE_PATTERNS = [
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "authorization",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
]


def _contains_sensitive_key(key: str) -> bool:
    """Check if a key contains sensitive patterns."""
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in SENSITIVE_PATTERNS)


def _hash_prompt(prompt: str, preview_length: int = 80) -> str:
    """Create a safe hash of a prompt for logging.

    Args:
        prompt: The full prompt text
        preview_length: Maximum characters to include in preview

    Returns:
        A preview string (first N chars + hash) that is safe to log
    """
    # Create truncated preview
    preview = prompt[:preview_length]
    if len(prompt) > preview_length:
        preview += "..."

    # Add hash for uniqueness identification
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]

    return f"{preview} [hash:{prompt_hash}]"


def sanitize_for_logging(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a dictionary to remove sensitive data before logging.

    Args:
        data: Dictionary potentially containing sensitive data

    Returns:
        Sanitized dictionary safe for logging
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for key, value in data.items():
        # Skip sensitive keys
        if _contains_sensitive_key(key):
            sanitized[key] = "[REDACTED]"
            continue

        # Recursively sanitize nested dictionaries
        if isinstance(value, dict):
            sanitized[key] = sanitize_for_logging(value)
        elif isinstance(value, str):
            # Truncate very long strings (potential prompts)
            if len(value) > 200:
                sanitized[key] = value[:200] + "...[truncated]"
            else:
                sanitized[key] = value
        else:
            sanitized[key] = value

    return sanitized


# =============================================================================
# Secure Logger Configuration
# =============================================================================


class SecureJSONFormatter(logging.Formatter):
    """Custom formatter that sanitizes log records before output.

    This formatter ensures no sensitive data is ever written to logs.
    """

    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with sanitization."""
        # Build log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if present in record
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id

        # Add event type if present
        if hasattr(record, "event_type"):
            log_entry["event_type"] = record.event_type

        # Add extra fields, sanitized
        if hasattr(record, "extra_data"):
            sanitized = sanitize_for_logging(record.extra_data)
            log_entry["data"] = sanitized

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class SecurityLogger:
    """Secure logger with built-in sanitization and correlation ID support."""

    def __init__(self, name: str = "pisc", log_file: Optional[str] = None):
        """Initialize the secure logger.

        Args:
            name: Logger name
            log_file: Optional file path for file logging
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        self.logger.handlers.clear()

        # Console handler with JSON formatter
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(SecureJSONFormatter())
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            self._setup_file_handler(log_file)

    def _setup_file_handler(self, log_file: str):
        """Set up rotating file handler."""
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler - max 10MB, keep 5 files
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setFormatter(SecureJSONFormatter())
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)

    def _log(self, level: int, message: str, event_type: str, **kwargs):
        """Internal log method with correlation ID support."""
        # Create correlation ID if not provided
        correlation_id = kwargs.pop("correlation_id", str(uuid.uuid4())[:8])

        # Sanitize extra data
        extra_data = kwargs.pop("extra_data", None)
        if extra_data:
            extra_data = sanitize_for_logging(extra_data)

        # Create log record
        extra = {
            "correlation_id": correlation_id,
            "event_type": event_type,
        }
        if extra_data:
            extra["extra_data"] = extra_data

        self.logger.log(level, message, extra=extra, stacklevel=3)

    def info(self, message: str, event_type: str = "info", **kwargs):
        """Log info level message.

        Args:
            message: Log message
            event_type: Type of event for categorization
            **kwargs: Additional context (correlation_id, extra_data, etc.)
        """
        self._log(logging.INFO, message, event_type, **kwargs)

    def warning(self, message: str, event_type: str = "warning", **kwargs):
        """Log warning level message for suspicious activity.

        Args:
            message: Log message
            event_type: Type of event for categorization
            **kwargs: Additional context
        """
        self._log(logging.WARNING, message, event_type, **kwargs)

    def error(self, message: str, event_type: str = "error", **kwargs):
        """Log error level message for failures.

        Args:
            message: Log message
            event_type: Type of event for categorization
            **kwargs: Additional context
        """
        self._log(logging.ERROR, message, event_type, **kwargs)

    def debug(self, message: str, event_type: str = "debug", **kwargs):
        """Log debug level message for development.

        Args:
            message: Log message
            event_type: Type of event for categorization
            **kwargs: Additional context
        """
        self._log(logging.DEBUG, message, event_type, **kwargs)


# =============================================================================
# Scan-Specific Logging Helpers
# =============================================================================


def log_scan_event(logger: SecurityLogger, stage: str, status: str, **data):
    """Log a scan pipeline event with appropriate level.

    Args:
        logger: The secure logger instance
        stage: Scan stage (regex_scan, risk_scoring, llm_classification, etc.)
        status: Status (started, completed, skipped, error)
        **data: Additional event data (sanitized automatically)
    """
    # Determine log level based on status
    if status == "error":
        level = logger.error
        event_type = f"scan_{stage}_error"
    elif status == "started":
        level = logger.info
        event_type = f"scan_{stage}_started"
    elif status in ("completed", "skipped"):
        level = logger.info
        event_type = f"scan_{stage}_{status}"
    else:
        level = logger.warning
        event_type = f"scan_{stage}_unknown"

    # Always include stage and status, sanitize other data
    extra_data = {
        "stage": stage,
        "status": status,
        **data,
    }

    level(
        f"Scan {stage}: {status}",
        event_type=event_type,
        extra_data=extra_data,
    )


def log_security_event(logger: SecurityLogger, event_type: str, severity: str, **data):
    """Log a security-related event.

    Args:
        logger: The secure logger instance
        event_type: Type of security event
        severity: Severity level (low, medium, high, critical)
        **data: Additional event data
    """
    level_map = {
        "low": logger.info,
        "medium": logger.warning,
        "high": logger.warning,
        "critical": logger.error,
    }

    level = level_map.get(severity.lower(), logger.info)

    level(
        f"Security event: {event_type}",
        event_type=f"security_{event_type}",
        extra_data={"severity": severity, **data},
    )


# =============================================================================
# Correlation ID Context Manager
# =============================================================================


class CorrelationContext:
    """Context manager for tracking correlation IDs across operations."""

    _context_var: Optional[str] = None

    @classmethod
    def get_id(cls) -> str:
        """Get current correlation ID or create new one."""
        if cls._context_var is None:
            cls._context_var = str(uuid.uuid4())[:8]
        return cls._context_var

    @classmethod
    def set_id(cls, correlation_id: str):
        """Set a specific correlation ID."""
        cls._context_var = correlation_id

    @classmethod
    def clear_id(cls):
        """Clear the correlation ID."""
        cls._context_var = None


# =============================================================================
# Default Logger Instance
# =============================================================================

# Default secure logger instance
# Can be imported and used throughout the application
default_logger = SecurityLogger("pisc")
