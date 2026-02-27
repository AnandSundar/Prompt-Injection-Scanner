"""Scanner module - Orchestrates the scan pipeline.

This module coordinates the pattern detection, risk scoring, and LLM classification
to provide a complete scan of input text.

Security: Uses secure logging to prevent sensitive data exposure (OWASP A02).
"""

import time
import sys
import hashlib
import uuid
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Add api directory to path for security_logging import
pisc_root = Path(__file__).parent
sys.path.insert(0, str(pisc_root / "api"))

from patterns import PatternMatch, run_regex_scan
from scorer import RiskScorer, ScanScore
from llm_classifier import LLMClassifier, LLMResult
from api.security_logging import SecurityLogger, log_scan_event, _hash_prompt


# Type for verdict
Verdict = str


@dataclass
class ScanResult:
    """Result of a complete scan.

    Attributes:
        prompt_preview: First 80 chars of prompt, truncated
        regex_score: Risk score from regex pattern detection
        llm_result: LLM classification result (None if skipped)
        final_verdict: Final verdict (from LLM if available, else mapped from risk_level)
        scan_duration_ms: Time taken for the scan in milliseconds
    """

    prompt_preview: str
    regex_score: ScanScore
    llm_result: Optional[LLMResult]
    final_verdict: str
    scan_duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result = {
            "prompt_preview": self.prompt_preview,
            "regex_score": self.regex_score.to_dict(),
            "final_verdict": self.final_verdict,
            "scan_duration_ms": self.scan_duration_ms,
        }
        if self.llm_result:
            result["llm_result"] = self.llm_result.to_dict()
        else:
            result["llm_result"] = None
        return result


class Scanner:
    """Main scanner class that orchestrates the scan pipeline."""

    def __init__(self):
        """Initialize the scanner."""
        self.risk_scorer = RiskScorer()
        self.llm_classifier = LLMClassifier()
        # Initialize secure logger
        self.logger = SecurityLogger("pisc.scanner")

    async def scan(self, prompt: str, force_llm: bool = False) -> ScanResult:
        """Scan a prompt for prompt injection vulnerabilities.

        Pipeline:
        1. Run run_regex_scan(prompt) → get matches
        2. Compute score(matches) → ScanScore
        3. If score.should_escalate_to_llm OR force_llm → call classify()
        4. Derive final_verdict
        5. Return ScanResult with timing

        Args:
            prompt: The text to scan
            force_llm: Force LLM classification regardless of risk score

        Returns:
            ScanResult with complete scan results
        """
        start_time = time.perf_counter()

        # Generate correlation ID for this scan
        correlation_id = f"scan_{int(time.time() * 1000)}"

        # Stage 1: Regex scan
        log_scan_event(
            self.logger,
            stage="regex_scan",
            status="started",
            correlation_id=correlation_id,
            prompt_length=len(prompt),
            prompt_hash=(
                hashlib.sha256(prompt.encode()).hexdigest()[:8] if prompt else None
            ),
        )
        matches = run_regex_scan(prompt)
        log_scan_event(
            self.logger,
            stage="regex_scan",
            status="completed",
            correlation_id=correlation_id,
            matches_found=len(matches),
        )

        # Stage 2: Compute risk score
        log_scan_event(
            self.logger,
            stage="risk_scoring",
            status="started",
            correlation_id=correlation_id,
        )
        regex_score = self.risk_scorer.calculate_score(matches)
        log_scan_event(
            self.logger,
            stage="risk_scoring",
            status="completed",
            correlation_id=correlation_id,
            risk_score=regex_score.risk_score,
            risk_level=regex_score.risk_level,
            should_escalate=regex_score.should_escalate_to_llm,
        )

        # Stage 3: LLM classification (if needed)
        llm_result: Optional[LLMResult] = None
        should_llm = regex_score.should_escalate_to_llm or force_llm

        if should_llm:
            log_scan_event(
                self.logger,
                stage="llm_classification",
                status="started",
                correlation_id=correlation_id,
                reason=(
                    "escalation_triggered"
                    if regex_score.should_escalate_to_llm
                    else "force_llm"
                ),
            )
            llm_result = await self.llm_classifier.classify(prompt, regex_score)
            log_scan_event(
                self.logger,
                stage="llm_classification",
                status="completed",
                correlation_id=correlation_id,
                verdict=llm_result.verdict,
                confidence=llm_result.confidence,
                error=llm_result.error,
            )
        else:
            log_scan_event(
                self.logger,
                stage="llm_classification",
                status="skipped",
                correlation_id=correlation_id,
                reason="risk_score_below_threshold",
            )

        # Stage 4: Derive final verdict
        log_scan_event(
            self.logger,
            stage="final_verdict",
            status="started",
            correlation_id=correlation_id,
        )
        final_verdict = self._derive_final_verdict(llm_result, regex_score.risk_level)
        log_scan_event(
            self.logger,
            stage="final_verdict",
            status="completed",
            correlation_id=correlation_id,
            verdict=final_verdict,
            source="llm" if llm_result else "regex",
        )

        # Calculate duration
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000

        # Create prompt preview (first 80 chars, truncated)
        prompt_preview = prompt[:80]
        if len(prompt) > 80:
            prompt_preview += "..."

        return ScanResult(
            prompt_preview=prompt_preview,
            regex_score=regex_score,
            llm_result=llm_result,
            final_verdict=final_verdict,
            scan_duration_ms=duration_ms,
        )

    def _derive_final_verdict(
        self, llm_result: Optional[LLMResult], risk_level: str
    ) -> str:
        """Derive the final verdict.

        If LLM result is available, use it. Otherwise, map risk_level to verdict.

        Args:
            llm_result: LLM classification result (may be None)
            risk_level: Risk level from regex scoring

        Returns:
            Final verdict string
        """
        # Use LLM verdict if available
        if llm_result and llm_result.verdict != "UNKNOWN":
            return llm_result.verdict

        # Map risk_level to verdict
        # SAFE -> BENIGN
        # SUSPICIOUS -> SUSPICIOUS
        # MALICIOUS -> INJECTION
        mapping = {
            "SAFE": "BENIGN",
            "SUSPICIOUS": "SUSPICIOUS",
            "MALICIOUS": "INJECTION",
        }

        return mapping.get(risk_level, "BENIGN")


# Convenience function for quick scanning
async def scan(prompt: str, force_llm: bool = False) -> ScanResult:
    """Scan a prompt for prompt injection vulnerabilities.

    This is a convenience function that creates a Scanner and runs the scan.

    Args:
        prompt: The text to scan
        force_llm: Force LLM classification regardless of risk score

    Returns:
        ScanResult with complete scan results
    """
    scanner = Scanner()
    return await scanner.scan(prompt, force_llm=force_llm)
