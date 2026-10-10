from typing import Optional

from pydantic import BaseModel, StrictBool


class QuestionnaireAnswers(BaseModel):
    """
    Security questionnaire answers.

    None means the user did not answer or the answer is unknown.
    """

    mfa_enabled: Optional[StrictBool] = None
    backups_performed: Optional[StrictBool] = None
    backups_tested: Optional[StrictBool] = None
    employee_training_completed: Optional[StrictBool] = None