"""Urgency detection utilities.

Provides three layers of functionality:
1. check_urgency(text) -> bool         (quick binary flag)
2. urgency_score(text) -> int          (aggregate weight of matched terms)
3. classify_urgency(text) -> (label, score)

Design goals:
- Avoid naive substring false positives (word boundaries or explicit phrases)
- Allow easy extension of keywords / weights
- Keep zero external dependencies for fast, offline use

Labels returned by classify_urgency:
  'emergency' : high priority / immediate attention
  'elevated'  : above normal but not top priority
  'normal'    : no urgent terms detected

This module is intentionally lightweight. For more advanced triage (negation
handling like "no chest pain", multi-symptom rules, or ML models), extend the
logic in a separate advanced component.
"""

from __future__ import annotations
import re
from typing import Tuple

# Ordered phrases/terms (regex fragments) combined into a single pattern
EMERGENCY_TERMS = [
    r"chest pain",   # phrase must appear as-is
    r"severe\b",     # whole word 'severe'
    r"\bbleeding\b", # whole word 'bleeding'
    r"\burgent\b"    # whole word 'urgent'
]

_EMERGENCY_PATTERN = re.compile("|".join(EMERGENCY_TERMS), re.IGNORECASE)

# Weighted mapping for scoring (same conceptual set; can diverge if needed)
KEYWORDS_WEIGHTS = {
    "chest pain": 5,
    "severe": 3,
    "bleeding": 4,
    "urgent": 2,
}

def check_urgency(visit_description: str) -> bool:
    """Return True if any emergency term is detected.

    Safe for None / empty input (returns False).
    """
    if not visit_description:
        return False
    return bool(_EMERGENCY_PATTERN.search(visit_description))

def urgency_score(text: str) -> int:
    """Return a cumulative weight based on matched keywords.

    Each keyword adds its weight once if present (no multi-count for repeats).
    """
    if not text:
        return 0
    lt = text.lower()
    score = 0
    for k, w in KEYWORDS_WEIGHTS.items():
        if k in lt:
            score += w
    return score

def classify_urgency(text: str) -> Tuple[str, int]:
    """Classify text into (label, score) using thresholds.

    Thresholds (heuristic):
      score >= 5 -> emergency
      score >= 2 -> elevated
      else       -> normal
    """
    s = urgency_score(text)
    if s >= 5:
        return "emergency", s
    if s >= 2:
        return "elevated", s
    return "normal", s

__all__ = [
    'check_urgency', 'urgency_score', 'classify_urgency', 'KEYWORDS_WEIGHTS'
]
