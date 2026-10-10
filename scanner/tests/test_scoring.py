from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scoring import calculate_score


def test_score_is_deterministic():
    findings = [
        Finding(
            check="https",
            severity="high",
            status="fail",
            title="HTTPS failed",
            evidence="Test evidence",
            recommendation="Test recommendation",
        ),
        Finding(
            check="headers",
            severity="medium",
            status="warning",
            title="Header missing",
            evidence="Test evidence",
            recommendation="Test recommendation",
        ),
    ]

    answers = QuestionnaireAnswers(
        mfa_enabled=False,
        backups_performed=True,
        backups_tested=None,
        employee_training_completed=False,
    )

    result = calculate_score(findings, answers)

    # 100 - 20 - 10 - 20 - 10 = 40
    assert result.score == 40
    assert result.total_deduction == 60
    assert len(result.reasons) == 4


def test_unknown_answers_do_not_reduce_score():
    answers = QuestionnaireAnswers()

    result = calculate_score([], answers)

    assert result.score == 100
    assert result.total_deduction == 0
    assert result.reasons == []


def test_error_and_unknown_findings_do_not_reduce_score():
    findings = [
        Finding(
            check="https",
            severity="critical",
            status="error",
            title="HTTPS could not be checked",
            evidence="Connection failed",
            recommendation="Retry the scan.",
        ),
        Finding(
            check="headers",
            severity="high",
            status="unknown",
            title="Headers could not be confirmed",
            evidence="No response was available.",
            recommendation="Retry the scan.",
        ),
    ]

    result = calculate_score(findings)

    assert result.score == 100
    assert result.total_deduction == 0
    assert result.reasons == []


def test_score_never_goes_below_zero():
    findings = [
        Finding(
            check=f"check_{number}",
            severity="critical",
            status="fail",
            title="Critical failure",
            evidence="Test evidence",
            recommendation="Test recommendation",
        )
        for number in range(10)
    ]

    result = calculate_score(findings)

    assert result.score == 0