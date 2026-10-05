def map_mitre(alert: dict):
    mappings = []

    # --------------------------------------------------
    # Rule 1: Repeated authentication failures
    # --------------------------------------------------

    failed_attempts = alert.get("failed_attempts", 0) or 0

    if failed_attempts >= 5:

        evidence = [
            f"{failed_attempts} failed authentication attempts observed"
        ]

        time_window = alert.get("time_window_minutes")

        if time_window:
            evidence.append(
                f"Failures occurred within {time_window} minutes"
            )

        mappings.append({
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "confidence": "high",
            "evidence": evidence
        })


    # --------------------------------------------------
    # Rule 2: PowerShell execution
    # --------------------------------------------------

    process_name = (
        alert.get("process_name") or ""
    ).lower()

    command_line = (
        alert.get("command_line") or ""
    ).lower()


    if (
        "powershell" in process_name
        or "powershell" in command_line
        or "pwsh" in process_name
    ):

        evidence = []

        if process_name:
            evidence.append(
                f"Observed process: {process_name}"
            )

        if command_line:
            evidence.append(
                f"Observed command line: {command_line}"
            )

        mappings.append({
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": "high",
            "evidence": evidence
        })


    return mappings