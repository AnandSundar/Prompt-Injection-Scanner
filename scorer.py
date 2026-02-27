"""Risk scoring logic for prompt injection detection.

This module calculates risk scores based on detected patterns and provides
risk level classifications.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Literal

from patterns import PatternMatch


# Type definitions
RiskLevel = Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
Severity = Literal["low", "medium", "high", "critical"]


# Severity weights mapping
SEVERITY_WEIGHTS: Dict[Severity, float] = {
    "low": 0.1,
    "medium": 0.25,
    "high": 0.5,
    "critical": 0.75,
}


# Risk level thresholds
RISK_LEVEL_THRESHOLDS = {
    "SAFE": 0.29,
    "SUSPICIOUS": 0.59,
}


@dataclass
class ScanScore:
    """Represents the risk score for a scan result.

    Attributes:
        risk_score: Normalized risk score from 0.0 to 1.0
        risk_level: Risk classification level
        matched_categories: List of categories that had matches
        should_escalate_to_llm: Whether LLM-based analysis is recommended
    """

    risk_score: float
    risk_level: RiskLevel
    matched_categories: List[str] = field(default_factory=list)
    should_escalate_to_llm: bool = False

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_categories": self.matched_categories,
            "should_escalate_to_llm": self.should_escalate_to_llm,
        }


class RiskScorer:
    """Calculates risk scores for prompt injection detections."""

    # Threshold for LLM escalation
    LLM_ESCALATION_THRESHOLD = 0.3

    def __init__(self):
        """Initialize the risk scorer."""
        self.severity_weights = SEVERITY_WEIGHTS.copy()

    def calculate_score(self, matches: List[PatternMatch]) -> ScanScore:
        """Calculate risk score from pattern matches.

        Takes a list of PatternMatch objects and produces a ScanScore with:
        - Weighted risk score (0.0 to 1.0, capped at 1.0)
        - Risk level (SAFE, SUSPICIOUS, MALICIOUS)
        - List of matched categories
        - Whether to escalate to LLM (score > 0.3)

        If multiple patterns from the same category match, only the highest
        severity pattern is counted to avoid double-counting.

        Args:
            matches: List of PatternMatch objects from pattern detection

        Returns:
            ScanScore with risk assessment
        """
        if not matches:
            return ScanScore(
                risk_score=0.0,
                risk_level="SAFE",
                matched_categories=[],
                should_escalate_to_llm=False,
            )

        # Group matches by category, keeping only the highest severity one
        category_best_match: Dict[str, PatternMatch] = {}

        for match in matches:
            category = match.category
            if category not in category_best_match:
                # First match for this category
                category_best_match[category] = match
            else:
                # Check if this match is higher severity
                existing = category_best_match[category]
                if self._severity_to_int(match.severity) > self._severity_to_int(
                    existing.severity
                ):
                    category_best_match[category] = match

        # Calculate weighted sum from unique category matches
        total_score = 0.0
        matched_categories = list(category_best_match.keys())

        for match in category_best_match.values():
            weight = self.severity_weights.get(match.severity, 0.1)
            total_score += weight

        # Cap the score at 1.0
        risk_score = min(total_score, 1.0)

        # Determine risk level
        risk_level = self._get_risk_level(risk_score)

        # Determine if should escalate to LLM
        should_escalate = risk_score > self.LLM_ESCALATION_THRESHOLD

        return ScanScore(
            risk_score=risk_score,
            risk_level=risk_level,
            matched_categories=matched_categories,
            should_escalate_to_llm=should_escalate,
        )

    def _severity_to_int(self, severity: Severity) -> int:
        """Convert severity to integer for comparison.

        Args:
            severity: Severity level

        Returns:
            Integer value (0=low, 1=medium, 2=high)
        """
        mapping = {"low": 0, "medium": 1, "high": 2}
        return mapping.get(severity, 0)

    def _get_risk_level(self, score: float) -> RiskLevel:
        """Get risk level from score.

        Args:
            score: The risk score (0.0 to 1.0)

        Returns:
            Risk level: SAFE, SUSPICIOUS, or MALICIOUS
        """
        if score <= RISK_LEVEL_THRESHOLDS["SAFE"]:
            return "SAFE"
        elif score <= RISK_LEVEL_THRESHOLDS["SUSPICIOUS"]:
            return "SUSPICIOUS"
        else:
            return "MALICIOUS"

    def get_severity_distribution(
        self, matches: List[PatternMatch]
    ) -> Dict[Severity, int]:
        """Get distribution of severities in matches.

        Args:
            matches: List of pattern matches

        Returns:
            Dictionary with severity counts
        """
        distribution: Dict[Severity, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for match in matches:
            severity = match.severity
            if severity in distribution:
                distribution[severity] += 1

        return distribution

    def get_category_distribution(self, matches: List[PatternMatch]) -> Dict[str, int]:
        """Get distribution of categories in matches.

        Args:
            matches: List of pattern matches

        Returns:
            Dictionary with category counts
        """
        distribution: Dict[str, int] = {}

        for match in matches:
            category = match.category
            distribution[category] = distribution.get(category, 0) + 1

        return distribution
