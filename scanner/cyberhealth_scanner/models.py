from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["pass", "fail", "warning", "unknown", "error"]
ScanStatus = Literal["complete", "partial", "failed"]


class Finding(BaseModel):
    """One security result produced by the scanner."""

    check: str
    severity: Severity
    status: Status
    title: str
    evidence: str
    recommendation: str


class ScanResult(BaseModel):
    """Complete result returned by the CyberHealth scanner."""

    domain: str
    score: int = Field(ge=0, le=100)
    findings: list[Finding]
    scan_status: ScanStatus = "complete"
    errors: list[str] = Field(default_factory=list)
    questionnaire: dict[str, bool | None] | None = None
    score_reasons: list[str] = Field(default_factory=list)