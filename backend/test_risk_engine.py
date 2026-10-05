from backend.app.services.risk_engine import calculate_risk
from backend.app.services.mitre_mapper import map_mitre
from backend.app.services.enrichment.threat_intel import enrich_ip
from app.services.risk_engine import calculate_risk


alert = {
    "alert_id": "SOC-1001",

    "alert_name": "Multiple Failed Login Attempts",

    "severity": "high",

    "source": "Microsoft Sentinel",

    "source_ip": "185.220.101.10",

    "username": "administrator",

    "hostname": "WIN-SERVER-01",

    "failed_attempts": 25,

    "time_window_minutes": 5
}


threat_intel = enrich_ip(
    alert["source_ip"]
)


mitre_mappings = map_mitre(
    alert
)


risk = calculate_risk(
    alert,
    threat_intel,
    mitre_mappings
)


print("AI SOC Risk Analysis")
print("====================")

print()

print(
    f"Alert: {alert['alert_name']}"
)

print(
    f"Risk Score: {risk['score']}/100"
)

print(
    f"Risk Level: {risk['level'].upper()}"
)


print()

print("Risk Reasons")
print("------------")


for reason in risk["reasons"]:

    print(
        f"+{reason['points']} "
        f"{reason['signal']}: "
        f"{reason['reason']}"
    )