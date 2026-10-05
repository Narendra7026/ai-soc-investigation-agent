from typing import Literal, Optional

from pydantic import BaseModel


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

    description: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None