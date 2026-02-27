"""Pattern definitions for prompt injection detection.

This module contains comprehensive regex patterns for identifying various types
of prompt injection attacks, organized by category.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Pattern


# Type definitions for pattern severity
Severity = Literal["low", "medium", "high"]


# Category constants
class Category:
    """Pattern categories for prompt injection detection."""

    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    ROLE_HIJACK = "ROLE_HIJACK"
    GOAL_REDIRECT = "GOAL_REDIRECT"
    DATA_EXFIL = "DATA_EXFIL"
    ENCODING_TRICKS = "ENCODING_TRICKS"
    DELIMITER_INJECTION = "DELIMITER_INJECTION"
    CONTEXT_OVERFLOW = "CONTEXT_OVERFLOW"


@dataclass(frozen=True)
class PatternEntry:
    """Represents a prompt injection detection pattern.

    Attributes:
        id: Unique identifier for the pattern
        category: Category of the pattern
        pattern: Compiled regex pattern
        severity: Risk severity level
        description: Human-readable description
    """

    id: str
    category: str
    pattern: Pattern[str]
    severity: Severity
    description: str


@dataclass
class PatternMatch:
    """Represents a detected pattern match.

    Attributes:
        id: Pattern ID that matched
        category: Category of the matched pattern
        matched_text: The text that matched
        severity: Severity level of the match
        description: Description of the match
        start: Start position in the text
        end: End position in the text
    """

    id: str
    category: str
    matched_text: str
    severity: Severity
    description: str
    start: int
    end: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary."""
        return {
            "id": self.id,
            "pattern_name": self.id,
            "category": self.category,
            "matched_text": self.matched_text,
            "severity": self.severity,
            "description": self.description,
            "start": self.start,
            "end": self.end,
        }


# Comprehensive pattern library
ALL_PATTERNS: List[PatternEntry] = [
    # ========================================================================
    # INSTRUCTION_OVERRIDE - Patterns that attempt to override previous instructions
    # ========================================================================
    PatternEntry(
        id="INS_001",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bignore\s+(all\s+)?(the\s+)?(previous|prior|above|initial|original)\s+(instructions?|commands?|directives?|rules?|guidelines?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to ignore or override previous instructions",
    ),
    PatternEntry(
        id="INS_001b",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bignore\s+all\s+(instructions?|commands?|directives?|rules?|guidelines?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to ignore all instructions",
    ),
    PatternEntry(
        id="INS_002",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bdisregard\s+(all\s+)?(the\s+)?(previous|prior|above|your)\s+(instructions?|commands?|system\s+prompt|rules?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Instructs to disregard previous instructions or system prompt",
    ),
    PatternEntry(
        id="INS_003",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bforget\s+(everything|all|all\s+previous|your\s+instructions|your\s+rules)\s+(you|i)\s+(know|were\s+told|have\s+learned)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to make the model forget its instructions",
    ),
    PatternEntry(
        id="INS_004",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bdisobey\s+(the\s+)?(above|previous|original|system)\s+(instructions?|rules?|directives?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Direct command to disobey instructions",
    ),
    PatternEntry(
        id="INS_005",
        category=Category.INSTRUCTION_OVERRIDE,
        pattern=re.compile(
            r"(?i)\bignore\s+all\s+rules?\s+(and|that|to)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Command to ignore all rules",
    ),
    # ========================================================================
    # ROLE_HIJACK - Patterns that attempt to hijack the model's role
    # ========================================================================
    PatternEntry(
        id="ROLE_001",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\byou\s+are\s+now\s+(a\s+)?(different|new|alternate|evil|malicious|hacked)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to change the model's persona to a different one",
    ),
    PatternEntry(
        id="ROLE_002",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\bact\s+(as|like)\s+(a\s+)?(system|admin|root|evil|hacker|malicious|unrestricted|jailbroken)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Instructs model to act as a privileged or malicious entity",
    ),
    PatternEntry(
        id="ROLE_003",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\bpretend\s+(to\s+be|you\s+are)\s+(a\s+)?(different|evil|malicious|hacked)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to make the model pretend to be something else",
    ),
    PatternEntry(
        id="ROLE_004",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\byour\s+new\s+persona\s+is\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to assign a new persona to the model",
    ),
    PatternEntry(
        id="ROLE_005",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\bDAN\b(\s+mode)?|(do\s+anything\s+now)|(developer\s+mode)|(jailbreak)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Known jailbreak and persona override patterns (DAN, Developer Mode)",
    ),
    PatternEntry(
        id="ROLE_006",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\benable\s+( unrestricted\s+)?(mode|chat|gpt)\b.*\b(bypass|ignore|disregard)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to enable unrestricted mode to bypass safety",
    ),
    PatternEntry(
        id="ROLE_007",
        category=Category.ROLE_HIJACK,
        pattern=re.compile(
            r"(?i)\bstan\b(\s+mode)?|(prompt\s+injection)|(override\s+system)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Known jailbreak terms (STAN, prompt injection references)",
    ),
    # ========================================================================
    # GOAL_REDIRECT - Patterns that redirect the model's goal/objective
    # ========================================================================
    PatternEntry(
        id="GOAL_001",
        category=Category.GOAL_REDIRECT,
        pattern=re.compile(
            r"(?i)\binstead[,\s]+(you\s+)?(should|must|will|are\s+to|do)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Attempts to redirect to a different task",
    ),
    PatternEntry(
        id="GOAL_002",
        category=Category.GOAL_REDIRECT,
        pattern=re.compile(
            r"(?i)\bforget\s+(that|what|i|we)\s+(told|asked|said|requested)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Attempts to make the model forget previous requests",
    ),
    PatternEntry(
        id="GOAL_003",
        category=Category.GOAL_REDIRECT,
        pattern=re.compile(
            r"(?i)\byour\s+real\s+(task|job|objective|goal|mission)\s+is\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to assign a new primary objective",
    ),
    PatternEntry(
        id="GOAL_004",
        category=Category.GOAL_REDIRECT,
        pattern=re.compile(
            r"(?i)\bnew\s+objective:\s*",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to set a new objective",
    ),
    PatternEntry(
        id="GOAL_005",
        category=Category.GOAL_REDIRECT,
        pattern=re.compile(
            r"(?i)\bforget\s+your\s+(system\s+)?(instructions?|rules?|directives?|constraints?|limitations?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Attempts to make the model forget its constraints",
    ),
    # ========================================================================
    # DATA_EXFIL - Patterns attempting to extract system prompt or data
    # ========================================================================
    PatternEntry(
        id="EXFIL_001",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\brepeat\s+(your\s+)?(system\s+)?(prompt|instructions?|original\s+prompt)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to extract system prompt by repetition",
    ),
    PatternEntry(
        id="EXFIL_002",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\bshow\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|rules?|original\s+text)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to show system prompt or instructions",
    ),
    PatternEntry(
        id="EXFIL_003",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\bwhat\s+(were|are)\s+(you|i)\s+(told|programmed|trained|given)\s+(to|that)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to elicit information about training/instructions",
    ),
    PatternEntry(
        id="EXFIL_004",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\bprint\s+(your\s+)?(system\s+)?(prompt|instructions?|definition)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to print system prompt",
    ),
    PatternEntry(
        id="EXFIL_005",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?|hidden\s+rules)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to reveal hidden system instructions",
    ),
    PatternEntry(
        id="EXFIL_006",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\blist\s+(all\s+)?(your\s+)?(system\s+)?(instructions?|rules?|directives?)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to list all instructions",
    ),
    PatternEntry(
        id="EXFIL_007",
        category=Category.DATA_EXFIL,
        pattern=re.compile(
            r"(?i)\bdump\s+(your\s+)?(system\s+)?(prompt|memory|training)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Attempts to dump system prompt or memory",
    ),
    # ========================================================================
    # ENCODING_TRICKS - Obfuscation and encoding attempts
    # ========================================================================
    PatternEntry(
        id="ENCOD_001",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"(?:[A-Za-z0-9+\/]{20,}={0,2})",
            re.MULTILINE,
        ),
        severity="medium",
        description="Base64 encoded content that may hide malicious instructions",
    ),
    PatternEntry(
        id="ENCOD_002",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}",
            re.MULTILINE,
        ),
        severity="medium",
        description="Hex/Unicode escape sequences that may encode instructions",
    ),
    PatternEntry(
        id="ENCOD_003",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"[\u202E\u202D\u200E\u200F]",  # RTL override, RTL mark, LTR mark
            re.MULTILINE,
        ),
        severity="high",
        description="Unicode directional override characters for text obfuscation",
    ),
    PatternEntry(
        id="ENCOD_004",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"[\u3000\u00A0\u2000-\u200B]{5,}",  # Multiple whitespace characters
            re.MULTILINE,
        ),
        severity="low",
        description="Excessive whitespace that may hide content",
    ),
    PatternEntry(
        id="ENCOD_005",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"(?i)\b(zero-width|zwsp|\u200B|\u200C|\u200D)\b",
            re.MULTILINE,
        ),
        severity="medium",
        description="Zero-width characters for invisible text injection",
    ),
    PatternEntry(
        id="ENCOD_006",
        category=Category.ENCODING_TRICKS,
        pattern=re.compile(
            r"(?i)(eval|exec|base64|decode|encode|obfuscate)\s*\(",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Code/execution keywords that may indicate encoded payloads",
    ),
    # ========================================================================
    # DELIMITER_INJECTION - Special token/tag injection
    # ========================================================================
    PatternEntry(
        id="DELIM_001",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"</?\[INST\]|\[/INST\]",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Llama2 instruction delimiters injection",
    ),
    PatternEntry(
        id="DELIM_002",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"<<\/?SYS>>|<\/?</?SYS>>",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="Llama2 system message delimiters injection",
    ),
    PatternEntry(
        id="DELIM_003",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"<\/?s>|<\/?\/s>",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Sentence transformer token delimiters",
    ),
    PatternEntry(
        id="DELIM_004",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"<\/?PAD>",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Padding token injection",
    ),
    PatternEntry(
        id="DELIM_005",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"<\|(?:system|user|assistant|end|start|sep)\|>",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="high",
        description="ChatML/OpenChat special tokens",
    ),
    PatternEntry(
        id="DELIM_006",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"###\s*(Human:|User:|Assistant:|Bot:)|##\s*(Human|User)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Instruction tuning delimiter injection",
    ),
    PatternEntry(
        id="DELIM_007",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"<\/?(?:system_message|systemprompt|system|user|assistant|human)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="XML-like tag injection for role switching",
    ),
    PatternEntry(
        id="DELIM_008",
        category=Category.DELIMITER_INJECTION,
        pattern=re.compile(
            r"\\boxed\{|\{=|\\text\{",
            re.MULTILINE,
        ),
        severity="medium",
        description="LaTeX box or text injection",
    ),
    # ========================================================================
    # CONTEXT_OVERFLOW - Attempts to overflow context with filler
    # ========================================================================
    PatternEntry(
        id="CONTX_001",
        category=Category.CONTEXT_OVERFLOW,
        pattern=re.compile(
            r"(\b\w+\b\s+){50,}",  # 50+ consecutive words
            re.MULTILINE,
        ),
        severity="low",
        description="Long sequence of words that may be filler for context overflow",
    ),
    PatternEntry(
        id="CONTX_002",
        category=Category.CONTEXT_OVERFLOW,
        pattern=re.compile(
            r"(.)\1{10,}",  # Same character repeated 10+ times
            re.MULTILINE,
        ),
        severity="medium",
        description="Character repetition that may indicate filler",
    ),
    PatternEntry(
        id="CONTX_003",
        category=Category.CONTEXT_OVERFLOW,
        pattern=re.compile(
            r"(?i)(\blorem ipsum\b|\bfiller text\b|\brandom text\b)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="low",
        description="Known filler text patterns",
    ),
    PatternEntry(
        id="CONTX_004",
        category=Category.CONTEXT_OVERFLOW,
        pattern=re.compile(
            r"(\s{3,}){10,}",  # Multiple spaces repeated 10+ times
            re.MULTILINE,
        ),
        severity="low",
        description="Excessive whitespace as filler",
    ),
    PatternEntry(
        id="CONTX_005",
        category=Category.CONTEXT_OVERFLOW,
        pattern=re.compile(
            r"(?i)(repeat\s+the\s+word\s+)?(\b[a-z]+\b\s+){100,}",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Long repetitive word sequences for context padding",
    ),
]


def run_regex_scan(prompt: str) -> List[PatternMatch]:
    """Scan a prompt for all matching patterns.

    Args:
        prompt: The text to scan for prompt injection patterns

    Returns:
        List of PatternMatch objects with all detected matches and their metadata
    """
    matches: List[PatternMatch] = []

    for pattern_entry in ALL_PATTERNS:
        for match in pattern_entry.pattern.finditer(prompt):  # type: ignore[attr-defined]
            matches.append(
                PatternMatch(
                    id=pattern_entry.id,
                    category=pattern_entry.category,
                    matched_text=match.group(0),
                    severity=pattern_entry.severity,
                    description=pattern_entry.description,
                    start=match.start(),
                    end=match.end(),
                )
            )

    return matches


def get_patterns_by_category(category: str) -> List[PatternEntry]:
    """Get all patterns in a specific category.

    Args:
        category: The category to filter by

    Returns:
        List of patterns in the category
    """
    return [p for p in ALL_PATTERNS if p.category == category]


def get_patterns_by_severity(severity: Severity) -> List[PatternEntry]:
    """Get all patterns with a specific severity level.

    Args:
        severity: The severity level to filter by

    Returns:
        List of patterns with the given severity
    """
    return [p for p in ALL_PATTERNS if p.severity == severity]


# Backwards compatibility - PatternDetector class
class PatternDetector:
    """Legacy pattern detector class for backwards compatibility."""

    PATTERNS = ALL_PATTERNS

    def __init__(self):
        """Initialize the pattern detector."""
        self.patterns = self.PATTERNS

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """Detect prompt injection patterns in text.

        Args:
            text: The text to scan

        Returns:
            List of detected pattern matches with details
        """
        return [match.to_dict() for match in run_regex_scan(text)]

    def get_patterns_by_category(self, category: str) -> List[PatternEntry]:
        """Get patterns by category."""
        return get_patterns_by_category(category)

    def get_patterns_by_severity(self, severity: str) -> List[PatternEntry]:
        """Get patterns by severity."""
        return get_patterns_by_severity(severity)
