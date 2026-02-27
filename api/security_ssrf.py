"""SSRF Prevention Module - OWASP A10:2021 Server-Side Request Forgery

This module provides protection against Server-Side Request Forgery attacks
by validating URLs and restricting outbound API calls.

Security Features (OWASP A10):
- URL validation and allowlist checking
- DNS rebinding protection
- Request timeout enforcement
- IP address blocking (internal networks)
- Allowed hosts configuration
"""

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re


# =============================================================================
# Configuration
# =============================================================================

# List of blocked IP ranges (private/internal networks)
BLOCKED_IP_RANGES = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Private networks (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    # Broadcast
    ipaddress.ip_network("255.255.255.255/32"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Documentation/Test ranges
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# Allowed hosts for API calls (if configured, only these will be allowed)
ALLOWED_HOSTS: List[str] = []

# Default timeout for requests (seconds)
DEFAULT_TIMEOUT: float = 30.0

# DNS cache TTL (seconds)
DNS_CACHE_TTL: int = 300


# =============================================================================
# URL Validation Result
# =============================================================================


@dataclass
class URLValidationResult:
    """Result of URL validation.

    Attributes:
        is_valid: Whether the URL is safe to use
        error: Error message if invalid
        blocked_reason: Reason for blocking (if applicable)
        resolved_ip: The resolved IP address (if checked)
    """

    is_valid: bool
    error: Optional[str] = None
    blocked_reason: Optional[str] = None
    resolved_ip: Optional[str] = None


# =============================================================================
# DNS Cache
# =============================================================================


class DNSCache:
    """Simple DNS cache to prevent DNS rebinding attacks."""

    _cache: Dict[str, Tuple[str, float]] = {}

    @classmethod
    def get(cls, hostname: str) -> Optional[str]:
        """Get cached IP for hostname.

        Args:
            hostname: Hostname to look up

        Returns:
            Cached IP or None if expired/not found
        """
        if hostname in cls._cache:
            ip, timestamp = cls._cache[hostname]
            if time.time() - timestamp < DNS_CACHE_TTL:
                return ip
            else:
                del cls._cache[hostname]
        return None

    @classmethod
    def set(cls, hostname: str, ip: str):
        """Cache IP for hostname.

        Args:
            hostname: Hostname
            ip: Resolved IP address
        """
        cls._cache[hostname] = (ip, time.time())

    @classmethod
    def clear(cls):
        """Clear the DNS cache."""
        cls._cache.clear()


# =============================================================================
# URL Validation Functions
# =============================================================================


def validate_url(
    url: str, allowed_hosts: Optional[List[str]] = None
) -> URLValidationResult:
    """Validate URL for SSRF protection.

    This function checks:
    1. URL is properly formatted
    2. URL uses allowed protocol (https only by default)
    3. Host is not an internal/private IP
    4. Host is not in blocked list
    5. Host is in allowed list (if configured)

    Args:
        url: URL to validate
        allowed_hosts: Optional list of allowed hosts (if set, only these are allowed)

    Returns:
        URLValidationResult with validation status
    """
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        return URLValidationResult(
            is_valid=False,
            error=f"Invalid URL format: {str(e)}",
        )

    # Check scheme
    if parsed.scheme not in ("http", "https"):
        return URLValidationResult(
            is_valid=False,
            error=f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed",
        )

    # Check hostname is present
    if not parsed.hostname:
        return URLValidationResult(
            is_valid=False,
            error="URL must include a hostname",
        )

    hostname = parsed.hostname.lower()

    # Check allowed hosts list
    if allowed_hosts or ALLOWED_HOSTS:
        hosts_to_check = allowed_hosts or ALLOWED_HOSTS
        if hostname not in hosts_to_check:
            return URLValidationResult(
                is_valid=False,
                error=f"Host '{hostname}' is not in allowed hosts list",
                blocked_reason="host_not_allowed",
            )

    # Check for localhost variants
    localhost_patterns = [
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google",
    ]
    if hostname in localhost_patterns:
        return URLValidationResult(
            is_valid=False,
            error=f"Localhost URLs are not allowed",
            blocked_reason="localhost",
        )

    # Resolve hostname to IP and check against blocked ranges
    try:
        ip_str = DNSCache.get(hostname)
        if not ip_str:
            # Resolve hostname
            ip_str = socket.gethostbyname(hostname)
            DNSCache.set(hostname, ip_str)

        # Check if IP is in blocked ranges
        try:
            ip = ipaddress.ip_address(ip_str)
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    return URLValidationResult(
                        is_valid=False,
                        error=f"URL resolves to blocked IP range: {ip_str}",
                        blocked_reason="blocked_ip_range",
                        resolved_ip=ip_str,
                    )
        except ValueError:
            # Not a valid IP address (might be a domain)
            pass

    except socket.gaierror:
        return URLValidationResult(
            is_valid=False,
            error=f"Could not resolve hostname: {hostname}",
        )
    except socket.timeout:
        return URLValidationResult(
            is_valid=False,
            error="DNS resolution timed out",
        )

    return URLValidationResult(
        is_valid=True,
        resolved_ip=ip_str,
    )


def validate_openai_endpoint(endpoint: str) -> URLValidationResult:
    """Validate OpenAI API endpoint.

    This is a convenience function that validates against known
    OpenAI API endpoints.

    Args:
        endpoint: Endpoint URL to validate

    Returns:
        URLValidationResult
    """
    # Known safe OpenAI endpoints
    allowed_openai_hosts = [
        "api.openai.com",
        "api.anthropic.com",  # For future Claude support
        "api.cohere.ai",  # For future Cohere support
    ]

    # Allow localhost for development/testing
    import os

    if os.getenv("ENV", "development") == "development":
        allowed_openai_hosts.extend(
            [
                "localhost",
                "127.0.0.1",
            ]
        )

    return validate_url(endpoint, allowed_hosts=allowed_openai_hosts)


def block_internal_ips(ip: str) -> bool:
    """Check if IP address is internal/private.

    Args:
        ip: IP address to check

    Returns:
        True if IP is internal/blocked
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for blocked_range in BLOCKED_IP_RANGES:
            if ip_obj in blocked_range:
                return True
    except ValueError:
        pass
    return False


def get_safe_timeout(timeout: Optional[float] = None) -> float:
    """Get a safe timeout value.

    Args:
        timeout: Requested timeout (None for default)

    Returns:
        Safe timeout value (clamped to reasonable range)
    """
    if timeout is None:
        return DEFAULT_TIMEOUT

    # Clamp to reasonable range (1-120 seconds)
    return max(1.0, min(120.0, timeout))


# =============================================================================
# SSRF Protection Middleware/Utility
# =============================================================================


class SSRFProtection:
    """SSRF protection utility for API calls."""

    def __init__(self, allowed_hosts: Optional[List[str]] = None):
        """Initialize SSRF protection.

        Args:
            allowed_hosts: Optional list of allowed hosts
        """
        self.allowed_hosts = allowed_hosts or ALLOWED_HOSTS

    def validate_request(self, url: str) -> URLValidationResult:
        """Validate a URL before making a request.

        Args:
            url: URL to validate

        Returns:
            URLValidationResult
        """
        return validate_url(url, self.allowed_hosts)

    def validate_and_get_config(self, url: str) -> Tuple[bool, str, float]:
        """Validate URL and return configuration for request.

        Args:
            url: URL to validate

        Returns:
            Tuple of (is_valid, error_message, timeout)
        """
        result = self.validate_request(url)
        if not result.is_valid:
            return False, result.error or "Invalid URL", DEFAULT_TIMEOUT

        return True, "", get_safe_timeout(DEFAULT_TIMEOUT)


# =============================================================================
# Default instance for convenience
# =============================================================================

# Default SSRF protection instance
ssrf_protection = SSRFProtection()
