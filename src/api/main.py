"""FastAPI main application"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import get_db
from api.routes import scans, targets, vulnerabilities, reports, devices, injection, auth

app = FastAPI(
    title="CyberSurX API",
    description="RedTeam Physical Security Suite API",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production'da sınırla
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["devices"])
app.include_router(injection.router, prefix="/api/v1/injection", tags=["injection"])

@app.get("/health")
def health_check():
    return {"status": "healthy", "app": "cybersurx"}

@app.get("/api/v1/status")
def api_status(db: Session = Depends(get_db)):
    return {
        "api_version": "1.0.0",
        "status": "operational",
        "database": "connected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
