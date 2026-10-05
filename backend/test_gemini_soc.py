from app.services.llm.gemini_client import (
    analyze_security_evidence
)


evidence = {

    "alert": {

        "alert_id":
            "SOC-1001",

        "alert_name":
            "Multiple Failed Login Attempts",

        "severity":
            "high",

        "source":
            "Microsoft Sentinel",

        "source_ip":
            "185.220.101.10",

        "username":
            "administrator",

        "hostname":
            "WIN-SERVER-01",

        "failed_attempts":
            25,

        "time_window_minutes":
            5
    },


    "threat_intelligence": {

        "reputation":
            "malicious",

        "confidence":
            90,

        "tags": [
            "tor-exit-node",
            "brute-force"
        ],

        "source":
            "local-threat-intel"
    },


    "mitre_mappings": [

        {

            "technique_id":
                "T1110",

            "technique_name":
                "Brute Force",

            "tactic":
                "Credential Access",

            "confidence":
                "high",

            "evidence": [
                "25 failed authentication attempts observed"
            ]
        }

    ],


    "risk": {

        "score":
            85,

        "level":
            "critical",

        "reasons": [

            {
                "signal":
                    "Alert Severity",

                "points":
                    20
            },

            {
                "signal":
                    "Threat Intelligence",

                "points":
                    25
            },

            {
                "signal":
                    "MITRE ATT&CK",

                "points":
                    10
            }

        ]
    }

}


result = analyze_security_evidence(
    evidence
)


print()
print(
    "AI SOC INVESTIGATION"
)

print(
    "===================="
)


print()

print(
    f"Verdict: "
    f"{result['verdict']}"
)


print(
    f"Confidence: "
    f"{result['confidence']}%"
)


print()

print(
    "Summary:"
)

print(
    result["summary"]
)


print()

print(
    "Findings:"
)


for finding in result[
    "findings"
]:

    print(
        f"- {finding}"
    )


print()

print(
    "Recommended Actions:"
)


for action in result[
    "recommended_actions"
]:

    print(
        f"- {action}"
    )