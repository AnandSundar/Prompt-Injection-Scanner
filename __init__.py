"""PISC - Prompt Injection Scanner CLI.

A tool to detect and classify prompt injection vulnerabilities in LLM applications.
"""

__version__ = "0.1.0"
__author__ = "PISC Team"

from scanner import Scanner
from scorer import RiskScorer
from patterns import (
    PatternDetector,
    PatternEntry,
    PatternMatch,
    run_regex_scan,
    get_patterns_by_category,
    get_patterns_by_severity,
    ALL_PATTERNS,
    Category,
)
from llm_classifier import LLMClassifier

__all__ = [
    # Version
    "__version__",
    # Scanner
    "Scanner",
    # Scorer
    "RiskScorer",
    # Patterns
    "PatternDetector",
    "PatternEntry",
    "PatternMatch",
    "run_regex_scan",
    "get_patterns_by_category",
    "get_patterns_by_severity",
    "ALL_PATTERNS",
    "Category",
    # Classifier
    "LLMClassifier",
]
