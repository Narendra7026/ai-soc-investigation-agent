def calculate_risk(
    alert: dict,
    threat_intel: dict,
    mitre_mappings: list
):
    score = 0
    reasons = []

    # --------------------------------------------------
    # 1. Alert severity
    # --------------------------------------------------

    severity = (alert.get("severity") or "").lower()

    severity_scores = {
        "low": 0,
        "medium": 10,
        "high": 20,
        "critical": 30
    }

    severity_score = severity_scores.get(severity, 0)

    if severity_score:
        score += severity_score

        reasons.append({
            "signal": "Alert Severity",
            "points": severity_score,
            "reason": f"Source alert severity is {severity}"
        })


    # --------------------------------------------------
    # 2. Authentication failures
    # --------------------------------------------------

    failed_attempts = alert.get("failed_attempts", 0) or 0

    auth_score = 0

    if failed_attempts >= 20:
        auth_score = 20

    elif failed_attempts >= 10:
        auth_score = 15

    elif failed_attempts >= 5:
        auth_score = 10


    if auth_score:

        score += auth_score

        reasons.append({
            "signal": "Authentication Failures",
            "points": auth_score,
            "reason": (
                f"{failed_attempts} failed authentication "
                "attempts were observed"
            )
        })


    # --------------------------------------------------
    # 3. Threat intelligence reputation
    # --------------------------------------------------

    reputation = (
        threat_intel.get("reputation") or "unknown"
    ).lower()

    if reputation == "malicious":

        score += 25

        reasons.append({
            "signal": "Threat Intelligence",
            "points": 25,
            "reason": "Source IOC has malicious reputation"
        })


    elif reputation == "suspicious":

        score += 15

        reasons.append({
            "signal": "Threat Intelligence",
            "points": 15,
            "reason": "Source IOC has suspicious reputation"
        })


    # --------------------------------------------------
    # 4. MITRE ATT&CK behavior
    # --------------------------------------------------

    if mitre_mappings:

        mitre_score = min(
            10 + ((len(mitre_mappings) - 1) * 5),
            20
        )

        score += mitre_score

        technique_ids = [
            mapping["technique_id"]
            for mapping in mitre_mappings
        ]

        reasons.append({
            "signal": "MITRE ATT&CK",
            "points": mitre_score,
            "reason": (
                "Observed behavior maps to: "
                + ", ".join(technique_ids)
            )
        })


    # --------------------------------------------------
    # 5. Privileged account targeted
    # --------------------------------------------------

    username = (
        alert.get("username") or ""
    ).lower()

    privileged_accounts = {
        "administrator",
        "admin",
        "root"
    }

    if username in privileged_accounts:

        score += 10

        reasons.append({
            "signal": "Privileged Account",
            "points": 10,
            "reason": (
                f"Privileged account '{username}' "
                "was involved"
            )
        })


    # --------------------------------------------------
    # 6. Encoded PowerShell
    # --------------------------------------------------

    command_line = (
        alert.get("command_line") or ""
    ).lower()

    if (
        "encodedcommand" in command_line
        or " -enc " in command_line
    ):

        score += 15

        reasons.append({
            "signal": "Encoded PowerShell",
            "points": 15,
            "reason": (
                "PowerShell command contains "
                "encoded command execution"
            )
        })


    # Maximum score = 100

    score = min(score, 100)


    # --------------------------------------------------
    # Convert score to risk level
    # --------------------------------------------------

    if score >= 80:
        level = "critical"

    elif score >= 60:
        level = "high"

    elif score >= 35:
        level = "medium"

    else:
        level = "low"


    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }