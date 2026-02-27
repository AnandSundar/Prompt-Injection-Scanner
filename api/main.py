"""FastAPI server for PISC - Prompt Injection Scanner.

This module provides a REST API and WebSocket interface for scanning prompts
for prompt injection vulnerabilities.
"""

import json
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add the parent directory to the path so pisc can be imported
import sys
from pathlib import Path

# Add parent directory to path
pisc_root = Path(__file__).parent.parent
sys.path.insert(0, str(pisc_root))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import from pisc package
from scanner import Scanner, ScanResult, scan as scan_function
from scorer import ScanScore, RiskScorer
from llm_classifier import LLMResult, LLMClassifier
from patterns import PatternEntry, run_regex_scan, ALL_PATTERNS


# =============================================================================
# Request/Response Models
# =============================================================================


class ScanRequest(BaseModel):
    """Request body for POST /scan endpoint."""

    prompt: str = Field(..., description="The text prompt to scan for injection")
    force_llm: bool = Field(
        default=False,
        description="Force LLM classification regardless of risk score",
    )


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


# =============================================================================
# FastAPI Application
# =============================================================================


app = FastAPI(
    title="PISC API",
    description="Prompt Injection Scanner - Detect and classify prompt injection vulnerabilities",
    version="0.1.0",
)

# Add CORS middleware for development (allows all origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Endpoints
# =============================================================================


@app.post("/scan", response_model=ScanResponse)
async def scan_prompt(request: ScanRequest) -> ScanResponse:
    """Scan a prompt for prompt injection vulnerabilities.

    Runs the full PISC scanner pipeline:
    1. Regex pattern detection
    2. Risk scoring
    3. LLM classification (if needed)

    Args:
        request: ScanRequest with prompt and optional force_llm flag

    Returns:
        ScanResponse with full scan results
    """
    result = await scan_function(prompt=request.prompt, force_llm=request.force_llm)

    return ScanResponse(
        prompt_preview=result.prompt_preview,
        regex_score=result.regex_score.to_dict(),
        llm_result=result.llm_result.to_dict() if result.llm_result else None,
        final_verdict=result.final_verdict,
        scan_duration_ms=result.scan_duration_ms,
    )


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """WebSocket endpoint for streaming scan progress.

    Accepts JSON message: { "prompt": string, "force_llm": boolean }

    Streams back stage-by-stage progress as JSON events:
    - { "stage": "regex", "status": "running" }
    - { "stage": "regex", "status": "done", "data": ScanScore }
    - { "stage": "llm", "status": "running" }
    - { "stage": "llm", "status": "done", "data": LLMResult }
    - { "stage": "complete", "status": "done", "data": ScanResult }
    """
    await websocket.accept()

    try:
        # Receive the scan request
        data = await websocket.receive_text()
        request_data = json.loads(data)
        prompt = request_data.get("prompt", "")
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
        except:
            pass


@app.get("/patterns", response_model=List[PatternEntryResponse])
async def get_patterns() -> List[PatternEntryResponse]:
    """Get all detection patterns.

    Returns a list of all PatternEntry objects for the "How It Works" page.

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

    Returns:
        Health status and version information
    """
    return HealthResponse(
        status="ok",
        version="0.1.0",
    )


# =============================================================================
# Entry Point
# =============================================================================


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
