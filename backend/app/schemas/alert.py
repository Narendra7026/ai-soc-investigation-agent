from pydantic import BaseModel
from typing import Optional, Literal


class SecurityAlert(BaseModel):
    alert_id: str
    alert_name: str

    severity: Literal[
        "low",
        "medium",
        "high",
        "critical"
    ]

    source: str

    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None

    failed_attempts: Optional[int] = None
    time_window_minutes: Optional[int] = None