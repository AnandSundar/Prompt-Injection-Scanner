"""Security Audit Module - OWASP A08 & A09: Data Integrity & Security Logging

This module provides comprehensive security audit logging with:
- Structured audit events
- Integrity verification
- Security incident tracking
- Compliance-friendly logging
- Attack detection patterns

Security Features:
- A08: Data Integrity - Hash verification, tamper detection
- A09: Security Logging - Complete audit trail for security events
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
import uuid


# =============================================================================
# Audit Event Types
# =============================================================================


class AuditEventType(str, Enum):
    """Types of audit events."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_INVALID_KEY = "auth_invalid_key"
    AUTH_MISSING_KEY = "auth_missing_key"

    # Authorization events
    ACCESS_DENIED = "access_denied"
    ACCESS_GRANTED = "access_granted"

    # Request events
    REQUEST_RECEIVED = "request_received"
    REQUEST_COMPLETED = "request_completed"
    REQUEST_FAILED = "request_failed"

    # Security events
    INJECTION_DETECTED = "injection_detected"
    SSRF_ATTEMPT = "ssrf_attempt"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_INPUT = "invalid_input"
    THREAT_DETECTED = "threat_detected"

    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGE = "config_change"

    # Scan events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# =============================================================================
# Audit Event
# =============================================================================


@dataclass
class AuditEvent:
    """Represents a security audit event.

    This dataclass captures all relevant information about an event
    for security auditing and compliance.
    """

    # Required fields
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: AuditEventType = AuditEventType.REQUEST_RECEIVED
    severity: AuditSeverity = AuditSeverity.INFO

    # Context fields
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None

    # Request fields
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None

    # Event-specific data
    data: Dict[str, Any] = field(default_factory=dict)

    # Outcome
    success: bool = True
    error_message: Optional[str] = None

    # Integrity
    integrity_hash: Optional[str] = None

    def __post_init__(self):
        """Generate integrity hash after initialization."""
        self.integrity_hash = self._generate_hash()

    def _generate_hash(self) -> str:
        """Generate hash for event integrity verification."""
        # Create a copy without the hash field
        event_copy = {k: v for k, v in asdict(self).items() if k != "integrity_hash"}
        # Create deterministic JSON
        event_json = json.dumps(event_copy, sort_keys=True, default=str)
        return hashlib.sha256(event_json.encode()).hexdigest()[:16]

    def verify_integrity(self) -> bool:
        """Verify event integrity.

        Returns:
            True if hash is valid
        """
        expected_hash = self._generate_hash()
        return self.integrity_hash == expected_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# =============================================================================
# Security Audit Logger
# =============================================================================


class SecurityAuditLogger:
    """Comprehensive security audit logger.

    This logger provides:
    - Structured JSON logging
    - Event categorization
    - Severity levels
    - Integrity verification
    - Easy querying and alerting
    """

    def __init__(self, logger_name: str = "pisc.audit"):
        """Initialize the audit logger.

        Args:
            logger_name: Name for the logger
        """
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)

        # Remove existing handlers
        self.logger.handlers.clear()

        # Console handler with JSON formatter
        handler = logging.StreamHandler()
        handler.setFormatter(AuditJSONFormatter())
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)

        # File handler for persistent audit logs
        self._setup_file_handler()

    def _setup_file_handler(self):
        """Set up file handler for audit logs."""
        log_dir = os.getenv("AUDIT_LOG_DIR", "logs")
        log_file = os.path.join(log_dir, "security_audit.log")

        # Create directory if needed
        os.makedirs(log_dir, exist_ok=True)

        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10,
        )
        handler.setFormatter(AuditJSONFormatter())
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)

    def log_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        success: bool = True,
        **kwargs
    ) -> AuditEvent:
        """Log a security audit event.

        Args:
            event_type: Type of event
            severity: Severity level
            success: Whether the operation succeeded
            **kwargs: Additional event data

        Returns:
            The created AuditEvent
        """
        event = AuditEvent(
            event_type=event_type, severity=severity, success=success, **kwargs
        )

        # Log at appropriate level
        log_method = {
            AuditSeverity.DEBUG: self.logger.debug,
            AuditSeverity.INFO: self.logger.info,
            AuditSeverity.WARNING: self.logger.warning,
            AuditSeverity.ERROR: self.logger.error,
            AuditSeverity.CRITICAL: self.logger.critical,
        }.get(severity, self.logger.info)

        log_method(json.dumps(event.to_dict()))

        return event

    # Convenience methods for common events

    def log_auth_success(self, user_id: str, **kwargs):
        """Log successful authentication."""
        return self.log_event(
            AuditEventType.AUTH_SUCCESS,
            AuditSeverity.INFO,
            user_id=user_id,
            success=True,
            **kwargs
        )

    def log_auth_failure(self, user_id: str, reason: str, **kwargs):
        """Log failed authentication."""
        return self.log_event(
            AuditEventType.AUTH_FAILURE,
            AuditSeverity.WARNING,
            user_id=user_id,
            success=False,
            error_message=reason,
            **kwargs
        )

    def log_invalid_api_key(self, key_prefix: str, **kwargs):
        """Log invalid API key attempt."""
        return self.log_event(
            AuditEventType.AUTH_INVALID_KEY,
            AuditSeverity.WARNING,
            success=False,
            data={"key_prefix": key_prefix[:8] + "..."},
            error_message="Invalid API key",
            **kwargs
        )

    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str, **kwargs):
        """Log rate limit exceeded."""
        return self.log_event(
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditSeverity.WARNING,
            ip_address=ip_address,
            endpoint=endpoint,
            success=False,
            error_message="Rate limit exceeded",
            **kwargs
        )

    def log_injection_detected(
        self, prompt_hash: str, detected_patterns: List[str], **kwargs
    ):
        """Log prompt injection detection."""
        return self.log_event(
            AuditEventType.INJECTION_DETECTED,
            AuditSeverity.WARNING,
            success=True,
            data={
                "prompt_hash": prompt_hash,
                "detected_patterns": detected_patterns,
            },
            **kwargs
        )

    def log_threat_detected(self, threat_type: str, details: Dict[str, Any], **kwargs):
        """Log general threat detection."""
        return self.log_event(
            AuditEventType.THREAT_DETECTED,
            AuditSeverity.ERROR,
            success=True,
            data={"threat_type": threat_type, **details},
            **kwargs
        )

    def log_invalid_input(
        self, field: str, reason: str, ip_address: Optional[str] = None, **kwargs
    ):
        """Log invalid input detection."""
        return self.log_event(
            AuditEventType.INVALID_INPUT,
            AuditSeverity.WARNING,
            success=False,
            ip_address=ip_address,
            data={"field": field, "reason": reason},
            error_message=reason,
            **kwargs
        )

    def log_ssrf_attempt(
        self, url: str, blocked_reason: str, ip_address: Optional[str] = None, **kwargs
    ):
        """Log SSRF attempt blocked."""
        return self.log_event(
            AuditEventType.SSRF_ATTEMPT,
            AuditSeverity.CRITICAL,
            success=False,
            ip_address=ip_address,
            data={"url": url, "blocked_reason": blocked_reason},
            error_message="SSRF attempt blocked",
            **kwargs
        )

    def log_scan_started(self, prompt_hash: str, correlation_id: str, **kwargs):
        """Log scan started."""
        return self.log_event(
            AuditEventType.SCAN_STARTED,
            AuditSeverity.INFO,
            correlation_id=correlation_id,
            data={"prompt_hash": prompt_hash},
            **kwargs
        )

    def log_scan_completed(
        self, correlation_id: str, verdict: str, duration_ms: float, **kwargs
    ):
        """Log scan completed."""
        return self.log_event(
            AuditEventType.SCAN_COMPLETED,
            AuditSeverity.INFO,
            correlation_id=correlation_id,
            data={"verdict": verdict, "duration_ms": duration_ms},
            **kwargs
        )

    def log_access_denied(
        self, endpoint: str, reason: str, ip_address: Optional[str] = None, **kwargs
    ):
        """Log access denied."""
        return self.log_event(
            AuditEventType.ACCESS_DENIED,
            AuditSeverity.WARNING,
            success=False,
            endpoint=endpoint,
            ip_address=ip_address,
            error_message=reason,
            **kwargs
        )


# =============================================================================
# JSON Formatter for Audit Logs
# =============================================================================


class AuditJSONFormatter(logging.Formatter):
    """JSON formatter for audit logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Try to parse the message as JSON (our audit events are JSON)
        try:
            return record.getMessage()
        except Exception:
            # Fallback to regular formatting
            return super().format(record)


# =============================================================================
# Default Audit Logger Instance
# =============================================================================

# Default audit logger instance
audit_logger = SecurityAuditLogger()
