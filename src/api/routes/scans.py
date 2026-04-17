"""Scan endpoints"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from database.models import ScanResult, ScanStatus, Target

router = APIRouter()

@router.get("/")
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[ScanStatus] = Query(None),
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    """List all scan results"""
    query = db.query(ScanResult)
    if status:
        query = query.filter(ScanResult.status == status)
    if target_id:
        query = query.filter(ScanResult.target_id == target_id)
    
    total = query.count()
    scans = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "scan_type": s.scan_type,
                "status": s.status.value,
                "findings_count": len(s.findings),
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "error_message": s.error_message
            }
            for s in scans
        ]
    }

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan by ID"""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type,
        "status": scan.status.value,
        "parameters": scan.parameters,
        "findings": scan.findings,
        "raw_output": scan.raw_output,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message
    }

@router.post("/")
def create_scan(
    target_id: int,
    scan_type: str,
    parameters: dict = None,
    db: Session = Depends(get_db)
):
    """Start a new scan"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = ScanResult(
        target_id=target_id,
        scan_type=scan_type,
        status=ScanStatus.pending,
        parameters=parameters or {}
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type,
        "status": scan.status.value,
        "message": "Scan created successfully"
    }

@router.delete("/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete scan"""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}
