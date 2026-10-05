from typing import Literal

from pydantic import BaseModel, Field


class AIInvestigationResult(BaseModel):

    verdict: Literal[
        "true_positive",
        "false_positive",
        "suspicious",
        "needs_further_investigation"
    ]

    confidence: int = Field(
        ge=0,
        le=100
    )

    summary: str

    findings: list[str]

    recommended_actions: list[str]