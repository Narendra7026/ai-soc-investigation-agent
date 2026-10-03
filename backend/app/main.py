from fastapi import FastAPI

from app.schemas.alert import SecurityAlert


app = FastAPI(
    title="AI SOC Investigation Agent",
    description="AI-assisted SOC alert investigation platform",
    version="0.2.0"
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