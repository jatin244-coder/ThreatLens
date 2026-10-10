"""Minimal FastAPI integration for the CyberHealth scanner."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cyberhealth_scanner.demo import demo_scan
from cyberhealth_scanner.models import ScanResult
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scanner import scan_domain
from cyberhealth_scanner.validation import UnsafeDomainError, validate_domain


class DomainScanRequest(BaseModel):
    domain: str
    questionnaire: QuestionnaireAnswers | None = None


app = FastAPI(title="CyberHealth Scanner API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan/demo", response_model=ScanResult)
def scan_demo() -> ScanResult:
    return demo_scan()


@app.post("/scan/domain", response_model=ScanResult)
def scan_authorized_domain(request: DomainScanRequest) -> ScanResult:
    try:
        domain = validate_domain(request.domain)
    except UnsafeDomainError as error:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_domain", "message": str(error)},
        ) from error

    return scan_domain(domain, request.questionnaire)