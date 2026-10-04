from backend.app.services.enrichment.threat_intel import enrich_ip


test_ips = [
    "185.220.101.10",
    "8.8.8.8",
    "192.168.1.100",
    "999.999.999.999"	
]


for ip in test_ips:

    result = enrich_ip(ip)

    print("=" * 40)

    print(f"IOC: {ip}")
    print(f"Reputation: {result['reputation']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Tags: {result['tags']}")
    print(f"Source: {result['source']}")