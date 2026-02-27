"""Input Validation Module - OWASP A03:2021 Injection Prevention

This module provides comprehensive input validation and sanitization
to prevent injection attacks across the PISC application.

Security Features (OWASP A03):
- Input length validation
- Special character sanitization
- Dangerous pattern detection
- Type validation
- Unicode normalization
"""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass


# =============================================================================
# Validation Constants
# =============================================================================

MAX_INPUT_LENGTH: int = 50 * 1024  # 50KB
MIN_INPUT_LENGTH: int = 1

# Dangerous patterns that may indicate injection attempts
DANGEROUS_PATTERNS = [
    # Command injection patterns
    r"(?i)(;\s*|\|\s*|`|\$\()\s*(rm|del|format|shutdown|reboot)",
    r"(?i)(exec|system|popen)\s*\(",
    # Path traversal patterns
    r"(?i)(\.\.[/\\]|%2e%2e[/\\])",
    # SQL injection patterns (basic)
    r"(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table)",
    # Template injection
    r"\{\{.*\}\}",
    r"\{%.*%\}",
    # Script injection
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)javascript:",
    # Base64 encoded commands
    r'(?i)base64\s*\(?\s*[\'"][a-zA-Z0-9+/=]{20,}\s*[\'"]',
]

# Compile dangerous patterns for efficiency
COMPILED_DANGEROUS_PATTERNS = [re.compile(p) for p in DANGEROUS_PATTERNS]

# Characters that should be normalized or handled carefully
NORMALIZATION_FORM = "NFKC"  # Unicode normalization


# =============================================================================
# Validation Result
# =============================================================================


@dataclass
class ValidationResult:
    """Result of input validation.

    Attributes:
        is_valid: Whether the input passed validation
        sanitized_input: The sanitized version of the input
        errors: List of validation errors (if any)
        warnings: List of warnings (if any)
        threat_detected: Whether dangerous patterns were detected
    """

    is_valid: bool
    sanitized_input: str
    errors: List[str]
    warnings: List[str]
    threat_detected: bool = False


# =============================================================================
# Input Validation Functions
# =============================================================================


def validate_input(input_str: Any, field_name: str = "input") -> ValidationResult:
    """Validate and sanitize input string.

    This function performs comprehensive input validation:
    1. Type check - must be string
    2. Length check - within bounds
    3. Unicode normalization
    4. Dangerous pattern detection
    5. Null byte removal

    Args:
        input_str: The input to validate
        field_name: Name of the field for error messages

    Returns:
        ValidationResult with validation status and sanitized input
    """
    errors: List[str] = []
    warnings: List[str] = []
    threat_detected = False

    # Type validation
    if not isinstance(input_str, str):
        errors.append(f"{field_name}: Input must be a string")
        return ValidationResult(
            is_valid=False,
            sanitized_input="",
            errors=errors,
            warnings=warnings,
        )

    # Length validation
    if len(input_str) > MAX_INPUT_LENGTH:
        errors.append(
            f"{field_name}: Input exceeds maximum length of {MAX_INPUT_LENGTH} characters"
        )
        return ValidationResult(
            is_valid=False,
            sanitized_input="",
            errors=errors,
            warnings=warnings,
        )

    if len(input_str) < MIN_INPUT_LENGTH:
        errors.append(
            f"{field_name}: Input must be at least {MIN_INPUT_LENGTH} character"
        )
        return ValidationResult(
            is_valid=False,
            sanitized_input="",
            errors=errors,
            warnings=warnings,
        )

    # Unicode normalization
    sanitized = unicodedata.normalize(NORMALIZATION_FORM, input_str)

    # Remove null bytes
    sanitized = sanitized.replace("\x00", "")

    # Remove other control characters except newlines and tabs
    sanitized = "".join(
        char
        for char in sanitized
        if unicodedata.category(char) != "Cc" or char in "\n\t\r"
    )

    # Check for dangerous patterns
    detected_patterns = []
    for pattern in COMPILED_DANGEROUS_PATTERNS:
        match = pattern.search(sanitized)
        if match:
            detected_patterns.append(pattern.pattern)
            threat_detected = True

    if detected_patterns:
        warnings.append(f"{field_name}: Potentially dangerous patterns detected")

    return ValidationResult(
        is_valid=len(errors) == 0,
        sanitized_input=sanitized,
        errors=errors,
        warnings=warnings,
        threat_detected=threat_detected,
    )


def validate_prompt(prompt: Any) -> Tuple[bool, str, List[str], List[str]]:
    """Validate a prompt for scanning.

    This is a convenience function specifically for prompt validation,
    returning a tuple for easier use in existing code.

    Args:
        prompt: The prompt to validate

    Returns:
        Tuple of (is_valid, sanitized_prompt, errors, warnings)
    """
    result = validate_input(prompt, field_name="prompt")
    return (
        result.is_valid,
        result.sanitized_input,
        result.errors,
        result.warnings,
    )


def check_injection_patterns(text: str) -> List[Dict[str, Any]]:
    """Check text for known injection patterns.

    Args:
        text: Text to check

    Returns:
        List of matches with pattern info
    """
    matches = []
    for i, pattern in enumerate(COMPILED_DANGEROUS_PATTERNS):
        found = pattern.finditer(text)
        for match in found:
            matches.append(
                {
                    "pattern_index": i,
                    "pattern": DANGEROUS_PATTERNS[i],
                    "matched_text": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                }
            )
    return matches


def sanitize_output(text: str, max_length: int = 200) -> str:
    """Sanitize text for safe output/logging.

    This function removes or escapes characters that could cause
    issues in logs or output displays.

    Args:
        text: Text to sanitize
        max_length: Maximum length of output

    Returns:
        Sanitized text safe for logging/display
    """
    if not isinstance(text, str):
        text = str(text)

    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "..."

    # Remove null bytes
    text = text.replace("\x00", "")

    # Remove other control characters
    text = "".join(
        char for char in text if unicodedata.category(char) != "Cc" or char in "\n\t\r"
    )

    return text


# =============================================================================
# Pydantic Validators (for use with FastAPI models)
# =============================================================================


def prompt_validator(value: str) -> str:
    """Pydantic validator for prompt field.

    This can be used as a field validator in Pydantic models.

    Args:
        value: The prompt value to validate

    Returns:
        Sanitized prompt

    Raises:
        ValueError: If validation fails
    """
    result = validate_input(value, field_name="prompt")

    if not result.is_valid:
        raise ValueError("; ".join(result.errors))

    if result.threat_detected:
        # Log warning but don't fail - the scan will detect this
        pass

    return result.sanitized_input


# =============================================================================
# Request Validation
# =============================================================================


class RequestValidator:
    """Validator for HTTP request data."""

    @staticmethod
    def validate_api_key(api_key: Optional[str]) -> Tuple[bool, str]:
        """Validate API key format.

        Args:
            api_key: API key to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if api_key is None:
            return False, "API key is required"

        if not isinstance(api_key, str):
            return False, "API key must be a string"

        if len(api_key) < 8:
            return False, "API key is too short"

        if len(api_key) > 256:
            return False, "API key is too long"

        # Check for valid characters (alphanumeric, dash, underscore)
        if not re.match(r"^[a-zA-Z0-9_-]+$", api_key):
            return False, "API key contains invalid characters"

        return True, ""

    @staticmethod
    def validate_origin(origin: Optional[str], allowed_origins: List[str]) -> bool:
        """Validate request origin against allowed list.

        Args:
            origin: Origin header value
            allowed_origins: List of allowed origins

        Returns:
            True if origin is allowed
        """
        if origin is None:
            # No origin header - could be a direct request
            return True

        # Check exact match
        if origin in allowed_origins:
            return True

        # Check if any allowed origin is a suffix (for subdomains)
        for allowed in allowed_origins:
            if allowed.startswith("http://") or allowed.startswith("https://"):
                if origin.endswith(allowed):
                    return True

        return False

    @staticmethod
    def validate_content_type(content_type: Optional[str]) -> Tuple[bool, str]:
        """Validate content type for API requests.

        Args:
            content_type: Content-Type header value

        Returns:
            Tuple of (is_valid, error_message)
        """
        if content_type is None:
            return False, "Content-Type header is required"

        # Only allow JSON
        allowed_types = ["application/json", "application/json; charset=utf-8"]
        if content_type.lower() not in [ct.lower() for ct in allowed_types]:
            return (
                False,
                f"Unsupported Content-Type. Allowed: {', '.join(allowed_types)}",
            )

        return True, ""
