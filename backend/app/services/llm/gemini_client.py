import json
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from app.schemas.investigation import AIInvestigationResult


# --------------------------------------------------
# Load environment variables
# --------------------------------------------------

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[4]
)

load_dotenv(
    PROJECT_ROOT / ".env"
)


# --------------------------------------------------
# Create Gemini client
# --------------------------------------------------

def get_gemini_client():

    api_key = os.getenv(
        "GEMINI_API_KEY"
    )

    if not api_key:

        raise RuntimeError(
            "GEMINI_API_KEY is not configured"
        )

    return genai.Client(
        api_key=api_key
    )


# --------------------------------------------------
# Analyze SOC evidence
# --------------------------------------------------

def analyze_security_evidence(
    evidence: dict
):

    client = get_gemini_client()

    model = os.getenv(
        "GEMINI_MODEL",
        "gemini-3.8-flash"
    )


    # --------------------------------------------------
    # Security analyst instructions
    # --------------------------------------------------

    prompt = f"""
You are an experienced Security Operations Center analyst.

Your job is to analyze security evidence that has already
been collected by deterministic security systems.

IMPORTANT RULES:

1. Use only the evidence supplied below.

2. Do not invent IP reputation or threat intelligence.

3. Do not invent MITRE ATT&CK techniques.

4. Do not change the deterministic risk score.

5. Do not claim an action was performed.

6. Recommended response actions require analyst review.

7. Clearly distinguish evidence from conclusions.

8. If there is insufficient evidence, use the verdict:
   needs_further_investigation.

9. Keep the investigation concise and useful for a SOC analyst.


SECURITY EVIDENCE:

{json.dumps(evidence, indent=2)}


Analyze the evidence and produce:

- verdict
- confidence
- summary
- findings
- recommended_actions
"""


    # --------------------------------------------------
    # Ask Gemini for STRUCTURED output
    # --------------------------------------------------

    interaction = client.interactions.create(

        model=model,

        input=prompt,

        response_format={
            "type": "text",

            "mime_type":
                "application/json",

            "schema":
                AIInvestigationResult
                .model_json_schema()
        }
    )


    # --------------------------------------------------
    # Validate Gemini response
    # --------------------------------------------------

    result = (
        AIInvestigationResult
        .model_validate_json(
            interaction.output_text
        )
    )


    return result.model_dump()