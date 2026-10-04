from backend.app.services.enrichment.ioc_extractor import extract_iocs


with open(
    "data/alerts/malware_alert.txt",
    "r"
) as file:

    alert_text = file.read()


results = extract_iocs(alert_text)


print("IOC Extraction Results")
print("======================")

print(results)