from fastapi import FastAPI


app = FastAPI(
    title="AI SOC Investigation Agent",
    description="AI-assisted SOC alert investigation platform",
    version="0.1.0"
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