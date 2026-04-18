"""Ollama integration endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from integrations.ollama_client import OllamaClient
from api.dependencies import get_current_user

router = APIRouter()

@router.get("/status")
def ollama_status(current_user = Depends(get_current_user)):
    """Check if Ollama is running"""
    client = OllamaClient()
    return {
        "running": client.check_ollama(),
        "models": client.list_models()
    }

@router.post("/analyze")
def analyze_with_llm(
    scan_id: int,
    current_user = Depends(get_current_user)
):
    """Analyze scan results using local LLM"""
    from database import get_db
    from database.models import ScanResult
    
    db = next(get_db())
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    client = OllamaClient()
    result = client.analyze_vulnerability({
        "id": scan.id,
        "scan_type": scan.scan_type,
        "target": scan.target_id,
        "findings": scan.findings
    })
    
    return result

@router.post("/payload")
def generate_payload(
    vulnerability_type: str,
    target_host: str,
    current_user = Depends(get_current_user)
):
    """Generate test payload using local LLM"""
    client = OllamaClient()
    result = client.generate_exploit_payload(
        vulnerability_type,
        {"host": target_host}
    )
    return result

@router.post("/report")
def generate_ai_report(
    scan_id: int,
    report_type: str = "executive",
    current_user = Depends(get_current_user)
):
    """Generate AI-powered security report"""
    from database import get_db
    from database.models import ScanResult
    
    db = next(get_db())
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    client = OllamaClient()
    result = client.generate_report(
        {"findings": scan.findings},
        report_type
    )
    
    return result
