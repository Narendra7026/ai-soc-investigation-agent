from fastapi import FastAPI

from app.schemas.alert import SecurityAlert

from app.services.enrichment.ioc_extractor import extract_iocs

from app.services.enrichment.threat_intel import enrich_ip

from fastapi.middleware.cors import CORSMiddleware

from app.services.mitre_mapper import map_mitre

from app.services.risk_engine import calculate_risk

from app.services.llm.gemini_client import (
    analyze_security_evidence
)


app = FastAPI(
    title="AI SOC Investigation Agent",
    description="AI-assisted SOC alert investigation platform",
    version="0.2.0"
)

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "message": "AI SOC Investigation Agent is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "AI SOC Investigation Agent"
    }


@app.post("/alerts")
def receive_alert(alert: SecurityAlert):
    return {
        "status": "received",
        "message": "Security alert received successfully",
        "alert": alert
    }

@app.post("/extract-iocs")
def extract_alert_iocs(alert_text: str):

    iocs = extract_iocs(alert_text)

    return {
        "status": "success",
        "iocs": iocs
    }

@app.get("/enrich/ip/{ip}")
def enrich_ip_address(ip: str):

    result = enrich_ip(ip)

    return {
        "ioc": ip,
        "type": "ipv4",
        "enrichment": result
    }

@app.post("/mitre/map")
def map_alert_to_mitre(alert: SecurityAlert):

    alert_data = alert.model_dump()

    mappings = map_mitre(alert_data)

    return {
        "alert_id": alert.alert_id,
        "alert_name": alert.alert_name,
        "mitre_mappings": mappings
    }

@app.post("/risk/score")
def calculate_alert_risk(alert: SecurityAlert):

    alert_data = alert.model_dump()

    source_ip = alert.source_ip


    if source_ip:

        threat_intel = enrich_ip(
            source_ip
        )

    else:

        threat_intel = {
            "reputation": "unknown",
            "confidence": 0,
            "tags": [],
            "source": "none"
        }


    mitre_mappings = map_mitre(
        alert_data
    )


    risk = calculate_risk(
        alert_data,
        threat_intel,
        mitre_mappings
    )


    return {
        "alert_id": alert.alert_id,
        "alert_name": alert.alert_name,
        "risk": risk,
        "threat_intelligence": threat_intel,
        "mitre_mappings": mitre_mappings
    }

@app.post("/ai/investigate")
def run_ai_investigation(
    alert: SecurityAlert
):

    # --------------------------------------------------
    # Convert Pydantic object to dictionary
    # --------------------------------------------------

    alert_data = (
        alert.model_dump()
    )


    # --------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------

    if alert.source_ip:

        threat_intel = enrich_ip(
            alert.source_ip
        )

    else:

        threat_intel = {

            "reputation":
                "unknown",

            "confidence":
                0,

            "tags":
                [],

            "source":
                "none"
        }


    # --------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------

    mitre_mappings = map_mitre(
        alert_data
    )


    # --------------------------------------------------
    # Deterministic Risk Engine
    # --------------------------------------------------

    risk = calculate_risk(

        alert_data,

        threat_intel,

        mitre_mappings
    )


    # --------------------------------------------------
    # Build evidence package
    # --------------------------------------------------

    evidence = {

        "alert":
            alert_data,

        "threat_intelligence":
            threat_intel,

        "mitre_mappings":
            mitre_mappings,

        "risk":
            risk
    }


    # --------------------------------------------------
    # Gemini analysis
    # --------------------------------------------------

    ai_analysis = (
        analyze_security_evidence(
            evidence
        )
    )


    # --------------------------------------------------
    # Final API response
    # --------------------------------------------------

    return {

        "alert_id":
            alert.alert_id,

        "alert_name":
            alert.alert_name,

        "provider":
            "Gemini",

        "evidence":
            evidence,

        "ai_analysis":
            ai_analysis
    }