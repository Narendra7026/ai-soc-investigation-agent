import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai


# --------------------------------------------------
# Load .env from project root
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")


# --------------------------------------------------
# Read configuration
# --------------------------------------------------

api_key = os.getenv("GEMINI_API_KEY")

model = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.8-flash"
)


if not api_key:
    raise RuntimeError(
        "GEMINI_API_KEY is not configured"
    )


# --------------------------------------------------
# Create Gemini client
# --------------------------------------------------

client = genai.Client(
    api_key=api_key
)


# --------------------------------------------------
# Send simple test
# --------------------------------------------------

interaction = client.interactions.create(
    model=model,
    input=(
        "Reply with exactly: "
        "Gemini connection successful"
    )
)


print(interaction.output_text)