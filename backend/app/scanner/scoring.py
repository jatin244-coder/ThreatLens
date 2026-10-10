"""Deterministic scoring for persisted scanner findings."""

from dataclasses import dataclass
from typing import Iterable, Mapping, cast

from app.scanner.models import Finding


DEDUCTIONS: dict[str, int] = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}


@dataclass(frozen=True)
class ScoreResult:
    """A bounded score and its deterministic risk classification."""

    score: int
    risk: str


def classify_risk(score: int) -> str:
    """Classify a score using inclusive, stable risk bands."""
    bounded_score = max(0, min(100, score))
    if bounded_score >= 90:
        return "low"
    if bounded_score >= 70:
        return "moderate"
    if bounded_score >= 40:
        return "high"
    return "critical"


def _finding_value(finding: Finding | Mapping[str, object], key: str) -> object:
    if isinstance(finding, Mapping):
        return finding.get(key)
    return getattr(finding, key)


def calculate_score(findings: Iterable[Finding | Mapping[str, object]]) -> ScoreResult:
    """Calculate a score from unique confirmed failures.

    Findings are deduplicated by ``check_name``. For one check, only the
    highest-severity FAIL is counted. PASS, ERROR, and UNKNOWN are ignored.
    """
    highest_deduction_by_check: dict[str, int] = {}
    for finding in findings:
        if _finding_value(finding, "status") != "FAIL":
            continue
        check_name = str(_finding_value(finding, "check_name"))
        severity = str(_finding_value(finding, "severity"))
        deduction = DEDUCTIONS.get(severity, 0)
        highest_deduction_by_check[check_name] = max(
            highest_deduction_by_check.get(check_name, 0), deduction
        )
    score = max(0, min(100, 100 - sum(highest_deduction_by_check.values())))
    return ScoreResult(score=score, risk=classify_risk(score))
