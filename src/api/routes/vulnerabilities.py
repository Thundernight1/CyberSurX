"""Vulnerability endpoints"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from database.models import Vulnerability, RiskLevel

router = APIRouter()

@router.get("/")
def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    target_id: Optional[int] = Query(None),
    severity: Optional[RiskLevel] = Query(None),
    is_fixed: Optional[bool] = Query(None),
    db: Session = Depends(get_db)
):
    """List all vulnerabilities"""
    query = db.query(Vulnerability)
    if target_id:
        query = query.filter(Vulnerability.target_id == target_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if is_fixed is not None:
        query = query.filter(Vulnerability.is_fixed == is_fixed)
    
    total = query.count()
    vulns = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "data": [
            {
                "id": v.id,
                "target_id": v.target_id,
                "vuln_type": v.vuln_type,
                "severity": v.severity.value,
                "title": v.title,
                "description": v.description,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "is_fixed": v.is_fixed,
                "created_at": v.created_at
            }
            for v in vulns
        ]
    }

@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Get vulnerability by ID"""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {
        "id": vuln.id,
        "target_id": vuln.target_id,
        "vuln_type": vuln.vuln_type,
        "severity": vuln.severity.value,
        "title": vuln.title,
        "description": vuln.description,
        "evidence": vuln.evidence,
        "remediation": vuln.remediation,
        "cve_id": vuln.cve_id,
        "cvss_score": vuln.cvss_score,
        "is_fixed": vuln.is_fixed,
        "created_at": vuln.created_at
    }

@router.post("/")
def create_vulnerability(
    target_id: int,
    vuln_type: str,
    severity: RiskLevel,
    title: str,
    description: str,
    evidence: dict = None,
    remediation: str = None,
    cve_id: str = None,
    cvss_score: str = None,
    db: Session = Depends(get_db)
):
    """Create new vulnerability"""
    vuln = Vulnerability(
        target_id=target_id,
        vuln_type=vuln_type,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence or {},
        remediation=remediation,
        cve_id=cve_id,
        cvss_score=cvss_score
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return {"id": vuln.id, "message": "Vulnerability created successfully"}
