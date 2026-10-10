import pytest
from pydantic import ValidationError

from cyberhealth_scanner.questionnaire import (
    QuestionnaireAnswers,
)


def test_questionnaire_accepts_true_and_false():
    answers = QuestionnaireAnswers(
        mfa_enabled=True,
        backups_performed=True,
        backups_tested=False,
        employee_training_completed=False,
    )

    assert answers.mfa_enabled is True
    assert answers.backups_tested is False


def test_unanswered_questions_are_unknown():
    answers = QuestionnaireAnswers()

    assert answers.mfa_enabled is None
    assert answers.backups_performed is None
    assert answers.backups_tested is None
    assert answers.employee_training_completed is None


def test_non_boolean_answers_are_rejected():
    with pytest.raises(ValidationError):
        QuestionnaireAnswers(
            mfa_enabled="yes",
        )