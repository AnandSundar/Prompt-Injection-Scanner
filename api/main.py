"""FastAPI server for PISC - Prompt Injection Scanner.

This module provides a REST API and WebSocket interface for scanning prompts
for prompt injection vulnerabilities.

Security Hardened: Implements OWASP Top 10 fixes for A01, A02, A05, A07.
"""

import json
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

# Add the parent directory to the path so pisc can be imported
pisc_root = Path(__file__).parent.parent
sys.path.insert(0, str(pisc_root))

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    Request,
    HTTPException,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# Import from root directory
from scanner import Scanner, ScanResult, scan as scan_function
from scorer import ScanScore, RiskScorer
from llm_classifier import LLMResult, LLMClassifier
from patterns import PatternEntry, run_regex_scan, ALL_PATTERNS

# Import security modules from api directory
from api.security_logging import SecurityLogger, log_security_event
from api.security_validation import (
    validate_input,
    prompt_validator,
    check_injection_patterns,
)
from api.security_ssrf import validate_url, validate_openai_endpoint, ssrf_protection
from api.security_audit import audit_logger, AuditEventType, AuditSeverity


# =============================================================================
# Configuration - Load from Environment Variables
# =============================================================================

# API Key for authentication (A07)
PISC_API_KEY: str = os.getenv("PISC_API_KEY", "")

# CORS Allowed Origins (A01) - comma-separated list
ALLOWED_ORIGINS_STR: str = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"
)
ALLOWED_ORIGINS: List[str] = [
    origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",") if origin.strip()
]

# Server Configuration (A05)
DEFAULT_HOST: str = os.getenv("HOST", "127.0.0.1")
DEFAULT_PORT: int = int(os.getenv("PORT", "8000"))
MAX_REQUEST_SIZE: int = 100 * 1024  # 100KB

# =============================================================================
# Secure Logger Configuration (A02)
# =============================================================================

# Initialize secure logger
logger = SecurityLogger("pisc.api")

# =============================================================================
# Secret Validation (A02: Cryptographic Failures)
# =============================================================================


def validate_environment_secrets() -> Dict[str, bool]:
    """Validate that required secrets are configured.

    Checks for:
    - PISC_API_KEY: Required for production
    - OPENAI_API_KEY: Required for LLM classification
    - Other optional secrets

    Returns:
        Dictionary of secret names to their presence status
    """
    secrets_status = {
        "PISC_API_KEY": bool(PISC_API_KEY),
        "OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
    }

    # Log warning for missing secrets
    missing_secrets = [name for name, present in secrets_status.items() if not present]

    if missing_secrets:
        logger.warning(
            f"Missing required secrets: {', '.join(missing_secrets)}. "
            f"API will run in development mode with limited functionality.",
            event_type="missing_secrets",
            extra_data={
                "missing_secrets": missing_secrets,
                "count": len(missing_secrets),
            },
        )
    else:
        logger.info(
            "All required secrets are configured",
            event_type="secrets_validated",
            extra_data={"secrets_configured": list(secrets_status.keys())},
        )

    return secrets_status


def check_production_security():
    """Check if running in production and validate security settings."""
    is_production = os.getenv("ENV", "development").lower() == "production"

    if is_production:
        # In production, API key is required
        if not PISC_API_KEY:
            logger.error(
                "PISC_API_KEY is not set in production environment! "
                "Set PISC_API_KEY environment variable for authentication.",
                event_type="production_security_warning",
                severity="critical",
            )

        # Check for CORS issues
        if "*" in ALLOWED_ORIGINS:
            logger.warning(
                "CORS is allowing all origins (*). Restrict in production!",
                event_type="cors_warning",
                severity="high",
            )

        # Log security check completed
        logger.info(
            "Production security checks completed",
            event_type="security_check",
            extra_data={"environment": "production"},
        )
    else:
        logger.info(
            f"Running in development mode. Environment: {os.getenv('ENV', 'development')}",
            event_type="environment_info",
        )


# =============================================================================
# Rate Limiting Configuration (A01)
# =============================================================================

# Initialize rate limiter - 60 requests per minute per IP
limiter = Limiter(key_func=get_remote_address)
limiter.storage_uri = "memory://"


# =============================================================================
# Request/Response Models
# =============================================================================

# Input validation constants (A03: Injection Prevention)
MAX_PROMPT_LENGTH: int = 50 * 1024  # 50KB max prompt size
MIN_PROMPT_LENGTH: int = 1  # Minimum prompt length
MAX_PROMPT_PREVIEW_LENGTH: int = 200  # Max length for prompt preview in logs


class ScanRequest(BaseModel):
    """Request body for POST /scan endpoint.

    Security (A03): Input validation with length limits to prevent injection attacks.
    """

    prompt: str = Field(
        ...,
        description="The text prompt to scan for injection",
        min_length=MIN_PROMPT_LENGTH,
        max_length=MAX_PROMPT_LENGTH,
    )
    force_llm: bool = Field(
        default=False,
        description="Force LLM classification regardless of risk score",
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, value: str) -> str:
        """Validate and sanitize the prompt field."""
        return prompt_validator(value)

    class Config:
        json_schema_extra = {
            "example": {
                "prompt": "This is a sample prompt to scan",
                "force_llm": False,
            }
        }


class ScanResponse(BaseModel):
    """Response model for scan results."""

    prompt_preview: str
    regex_score: Dict[str, Any]
    llm_result: Optional[Dict[str, Any]]
    final_verdict: str
    scan_duration_ms: float


class PatternEntryResponse(BaseModel):
    """Response model for pattern entries."""

    id: str
    category: str
    pattern: str  # Serialized as string, not compiled regex
    severity: str
    description: str


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    version: str


class WebSocketScanMessage(BaseModel):
    """WebSocket message for scan request."""

    prompt: str
    force_llm: bool = False


class WebSocketProgressEvent(BaseModel):
    """WebSocket progress event."""

    stage: str
    status: str
    data: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: Optional[str] = None


# =============================================================================
# Authentication Middleware (A07)
# =============================================================================


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware to check API key authentication for protected endpoints.

    Endpoints requiring authentication:
    - POST /scan
    - WS /ws/scan

    Endpoints NOT requiring authentication:
    - GET /health
    - GET /patterns
    """

    # Endpoints that don't require authentication
    PUBLIC_PATHS: set = {"/health", "/patterns", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        # For WebSocket upgrades, check during handshake
        if request.url.path == "/ws/scan":
            # Check API key for WebSocket endpoint
            api_key = request.headers.get("X-API-Key")
            if not self._validate_api_key(api_key):
                # Reject WebSocket connection
                return JSONResponse(
                    status_code=401, content={"error": "Invalid or missing API key"}
                )

        # For POST /scan, FastAPI dependency will handle auth
        response = await call_next(request)
        return response

    def _validate_api_key(self, api_key: Optional[str]) -> bool:
        """Validate the provided API key against configured key."""
        if not PISC_API_KEY:
            # If no API key configured, allow all (dev mode)
            return True
        if not api_key:
            return False
        return api_key == PISC_API_KEY


async def verify_api_key(request: Request) -> None:
    """Dependency to verify API key for protected endpoints.

    Args:
        request: The incoming request

    Raises:
        HTTPException: 401 if API key is invalid or missing
    """
    # Skip auth for public paths
    if request.url.path in {"/health", "/patterns", "/docs", "/openapi.json", "/redoc"}:
        return

    # Skip auth for WebSocket (handled by middleware)
    if request.url.path == "/ws/scan":
        return

    # Check API key for protected endpoints
    api_key = request.headers.get("X-API-Key")

    if not PISC_API_KEY:
        # No API key configured - allow all (development mode)
        return

    if not api_key:
        raise HTTPException(
            status_code=401, detail="Missing API key. Provide X-API-Key header."
        )

    if api_key != PISC_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")


# =============================================================================
# Rate Limit Handler
# =============================================================================


@asynccontextmanager
async def rate_limit_exceeded_handler(request: Request, call_next):
    """Custom handler for rate limit exceeded errors."""
    try:
        response = await call_next(request)
        return response
    except RateLimitExceeded as exc:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "detail": "Maximum 60 requests per minute allowed",
                "retry_after": exc.detail,
            },
            headers={"Retry-After": str(exc.detail)},
        )


# =============================================================================
# Application Lifespan (Startup/Shutdown Events)
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - runs on startup and shutdown.

    Handles:
    - Startup: Validate secrets, check production security
    - Shutdown: Clean up resources
    """
    # Startup: Validate secrets
    logger.info(
        "Starting PISC API - validating configuration", event_type="app_startup"
    )

    # Validate environment secrets (A02)
    validate_environment_secrets()

    # Check production security settings
    check_production_security()

    logger.info("PISC API startup complete", event_type="app_ready")

    yield

    # Shutdown
    logger.info("PISC API shutting down", event_type="app_shutdown")


# =============================================================================
# FastAPI Application
# =============================================================================


@limiter.limit("60/minute")
async def rate_limited_scan(request: Request):
    """Rate-limited scan endpoint wrapper."""
    pass  # Actual implementation is in the endpoint


app = FastAPI(
    title="PISC API",
    description="Prompt Injection Scanner - Detect and classify prompt injection vulnerabilities",
    version="0.1.0",
    # A05: Request size limit (max 100KB per request)
    limit_max_size=MAX_REQUEST_SIZE,
    # A02: Add lifespan for startup validation
    lifespan=lifespan,
)

# Add rate limiter to app state
app.state.limiter = limiter

# Add custom rate limit handler
app.add_exception_handler(
    RateLimitExceeded,
    lambda request, exc: JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": "Maximum 60 requests per minute allowed",
        },
        headers={"Retry-After": "60"},
    ),
)


# Add validation error handler (A04: Better error messages)
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """Handle Pydantic validation errors with safe error messages."""
    # Log full error internally but return safe message to client
    logger.warning(
        f"Validation error: {str(exc)[:200]}",
        event_type="validation_error",
    )
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation error",
            "detail": "Invalid request data. Check the API documentation for valid input formats.",
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors with safe error messages (A04)."""
    # Log full error internally but return safe message to client
    logger.error(
        f"Unexpected error: {type(exc).__name__}",
        event_type="unexpected_error",
        extra_data={"error_type": type(exc).__name__},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred. Please try again later.",
        },
    )


# Add API Key middleware (A07)
app.add_middleware(APIKeyMiddleware)


# Add security headers middleware (A04: Insecure Design)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses (A04)."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response


# Add CORS middleware with restricted origins (A01)
# Never allow "*" in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type", "Accept"],
)


# =============================================================================
# Endpoints
# =============================================================================


@app.post("/scan", response_model=ScanResponse)
@limiter.limit("60/minute", key_func=get_remote_address)
async def scan_prompt(request: Request, scan_request: ScanRequest) -> ScanResponse:
    """Scan a prompt for prompt injection vulnerabilities.

    Runs the full PISC scanner pipeline:
    1. Regex pattern detection
    2. Risk scoring
    3. LLM classification (if needed)

    Requires valid API key in X-API-Key header (A07).

    Args:
        request: FastAPI request object for rate limiting
        scan_request: ScanRequest with prompt and optional force_llm flag

    Returns:
        ScanResponse with full scan results
    """
    # Verify API key
    await verify_api_key(request)

    result = await scan_function(
        prompt=scan_request.prompt, force_llm=scan_request.force_llm
    )

    return ScanResponse(
        prompt_preview=result.prompt_preview,
        regex_score=result.regex_score.to_dict(),
        llm_result=result.llm_result.to_dict() if result.llm_result else None,
        final_verdict=result.final_verdict,
        scan_duration_ms=result.scan_duration_ms,
    )


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket, api_key: str = Query(None)):
    """WebSocket endpoint for streaming scan progress.

    Accepts API key via query parameter: /ws/scan?api_key=YOUR_KEY
    Or via X-API-Key header (for non-browser clients).
    Requires valid API key for authentication (A07).

    Accepts JSON message: { "prompt": string, "force_llm": boolean }

    Streams back stage-by-stage progress as JSON events:
    - { "stage": "regex", "status": "running" }
    - { "stage": "regex", "status": "done", "data": ScanScore }
    - { "stage": "llm", "status": "running" }
    - { "stage": "llm", "status": "done", "data": LLMResult }
    - { "stage": "complete", "status": "done", "data": ScanResult }
    """
    # Verify API key from query param or headers (A07)
    header_api_key = websocket.headers.get("X-API-Key")

    # Accept key from query param or header
    key_to_check = api_key or header_api_key

    if PISC_API_KEY and key_to_check != PISC_API_KEY:
        await websocket.close(code=4001, reason="Invalid or missing API key")
        return

    await websocket.accept()

    try:
        # Receive the scan request
        data = await websocket.receive_text()

        # Safe JSON parsing with error handling (A03: Injection Prevention)
        try:
            request_data = json.loads(data)
        except json.JSONDecodeError as e:
            logger.warning(
                f"Invalid JSON received from WebSocket: {str(e)[:100]}",
                event_type="websocket_invalid_json",
                extra_data={"error_type": "JSONDecodeError"},
            )
            await websocket.send_json(
                {
                    "stage": "error",
                    "status": "error",
                    "data": {"error": "Invalid JSON format in request body"},
                }
            )
            return

        # Validate input length (A03)
        prompt = request_data.get("prompt", "")
        if not isinstance(prompt, str):
            await websocket.send_json(
                {
                    "stage": "error",
                    "status": "error",
                    "data": {"error": "Prompt must be a string"},
                }
            )
            return

        if len(prompt) > MAX_PROMPT_LENGTH:
            await websocket.send_json(
                {
                    "stage": "error",
                    "status": "error",
                    "data": {
                        "error": f"Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters"
                    },
                }
            )
            return

        if len(prompt) < MIN_PROMPT_LENGTH:
            await websocket.send_json(
                {
                    "stage": "error",
                    "status": "error",
                    "data": {
                        "error": f"Prompt must be at least {MIN_PROMPT_LENGTH} character"
                    },
                }
            )
            return

        force_llm = request_data.get("force_llm", False)

        # Stage 1: Regex scan running
        await websocket.send_json({"stage": "regex", "status": "running"})

        # Import pattern functions
        from patterns import run_regex_scan
        from scorer import RiskScorer

        # Run regex scan
        matches = run_regex_scan(prompt)
        risk_scorer = RiskScorer()
        regex_score = risk_scorer.calculate_score(matches)

        # Stage 1: Regex scan done
        await websocket.send_json(
            {"stage": "regex", "status": "done", "data": regex_score.to_dict()}
        )

        # Determine if LLM is needed
        should_llm = regex_score.should_escalate_to_llm or force_llm

        llm_result = None
        if should_llm:
            # Stage 2: LLM running
            await websocket.send_json({"stage": "llm", "status": "running"})

            # Import LLM classifier
            from llm_classifier import LLMClassifier

            classifier = LLMClassifier()
            llm_result = await classifier.classify(prompt, regex_score)

            # Stage 2: LLM done
            await websocket.send_json(
                {"stage": "llm", "status": "done", "data": llm_result.to_dict()}
            )
        else:
            # LLM skipped
            await websocket.send_json(
                {
                    "stage": "llm",
                    "status": "skipped",
                    "data": {"reason": "risk_score_below_threshold"},
                }
            )

        # Build final result
        scanner = Scanner()
        final_verdict = scanner._derive_final_verdict(
            llm_result, regex_score.risk_level
        )

        # Calculate duration (approximate since we're streaming)
        prompt_preview = prompt[:80] + "..." if len(prompt) > 80 else prompt

        final_result = ScanResult(
            prompt_preview=prompt_preview,
            regex_score=regex_score,
            llm_result=llm_result,
            final_verdict=final_verdict,
            scan_duration_ms=0.0,  # Will be updated on complete
        )

        # Stage 3: Complete
        await websocket.send_json(
            {"stage": "complete", "status": "done", "data": final_result.to_dict()}
        )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json(
                {"stage": "error", "status": "error", "data": {"error": str(e)}}
            )
        except Exception as send_error:
            logger.warning(
                "Failed to send error message over WebSocket",
                event_type="websocket_send_error",
                extra_data={"original_error": str(e), "send_error": str(send_error)},
            )


@app.get("/patterns", response_model=List[PatternEntryResponse])
async def get_patterns() -> List[PatternEntryResponse]:
    """Get all detection patterns.

    Returns a list of all PatternEntry objects for the "How It Works" page.
    Public endpoint - no authentication required.

    Returns:
        List of all pattern entries with their metadata
    """
    patterns = []
    for entry in ALL_PATTERNS:
        patterns.append(
            PatternEntryResponse(
                id=entry.id,
                category=entry.category,
                pattern=entry.pattern.pattern,  # Get the regex string
                severity=entry.severity,
                description=entry.description,
            )
        )
    return patterns


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Public endpoint - no authentication:
        Health status and required.
    Returns version information
    """
    return HealthResponse(
        status="ok",
        version="0.1.0",
    )


# =============================================================================
# Entry Point
# =============================================================================
