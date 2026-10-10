from pydantic import BaseModel, Field

from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers


SEVERITY_DEDUCTIONS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


QUESTIONNAIRE_DEDUCTIONS = {
    "mfa_enabled": 20,
    "backups_performed": 15,
    "backups_tested": 10,
    "employee_training_completed": 10,
}


class ScoreResult(BaseModel):
    """The final security score and the reasons for deductions."""

    score: int = Field(ge=0, le=100)
    total_deduction: int = Field(ge=0)
    reasons: list[str]


def calculate_score(
    findings: list[Finding],
    answers: QuestionnaireAnswers | None = None,
) -> ScoreResult:
    """Calculate a deterministic score from 0 to 100."""

    total_deduction = 0
    reasons = []

    for finding in findings:
        if finding.status not in {"fail", "warning"}:
            continue

        deduction = SEVERITY_DEDUCTIONS[finding.severity]

        if deduction == 0:
            continue

        total_deduction += deduction
        reasons.append(
            f"{finding.title}: -{deduction} points"
        )

    if answers is not None:
        for field_name, deduction in QUESTIONNAIRE_DEDUCTIONS.items():
            answer = getattr(answers, field_name)

            # Unknown answers do not reduce the score.
            if answer is False:
                total_deduction += deduction
                reasons.append(
                    f"{field_name} is not enabled or completed: "
                    f"-{deduction} points"
                )

    score = max(0, 100 - total_deduction)

    return ScoreResult(
        score=score,
        total_deduction=total_deduction,
        reasons=reasons,
    )