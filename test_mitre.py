from backend.app.services.mitre_mapper import map_mitre


alert = {
    "alert_id": "SOC-1002",
    "alert_name": "Suspicious PowerShell Execution",
    "severity": "high",
    "source": "Microsoft Defender",
    "username": "john.doe",
    "hostname": "WIN-LAPTOP-22",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -EncodedCommand SQBFAFgA"
}


result = map_mitre(alert)


print("MITRE ATT&CK Mapping")
print("====================")


for mapping in result:

    print(f"Technique ID: {mapping['technique_id']}")
    print(f"Technique: {mapping['technique_name']}")
    print(f"Tactic: {mapping['tactic']}")
    print(f"Confidence: {mapping['confidence']}")

    print("Evidence:")

    for evidence in mapping["evidence"]:
        print(f" - {evidence}")

    print()