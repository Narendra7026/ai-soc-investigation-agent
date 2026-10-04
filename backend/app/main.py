from fastapi import FastAPI

from app.schemas.alert import SecurityAlert

from app.services.enrichment.ioc_extractor import extract_iocs

from app.services.enrichment.threat_intel import enrich_ip

from fastapi.middleware.cors import CORSMiddleware


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