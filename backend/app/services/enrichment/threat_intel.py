MOCK_THREAT_INTEL = {
    "185.220.101.10": {
        "reputation": "malicious",
        "confidence": 90,
        "tags": [
            "tor-exit-node",
            "brute-force"
        ],
        "source": "local-threat-intel"
    },

    "8.8.8.8": {
        "reputation": "benign",
        "confidence": 95,
        "tags": [
            "public-dns"
        ],
        "source": "local-threat-intel"
    }
}


def enrich_ip(ip: str):

    result = MOCK_THREAT_INTEL.get(ip)

    if result:
        return result

    return {
        "reputation": "unknown",
        "confidence": 0,
        "tags": [],
        "source": "local-threat-intel"
    }