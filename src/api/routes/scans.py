"""Scan endpoints with real nmap integration"""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import datetime

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from database import get_db
from database.models import ScanResult, ScanStatus, Target, AuditLog
from api.dependencies import get_current_user
from redteam.modules.scanner import NmapScanner

router = APIRouter()
scanner = NmapScanner()

@router.get("/nmap-check")
def check_nmap_installation(
    current_user = Depends(get_current_user)
):
    """Check if nmap is installed on the system"""
    is_installed = scanner.check_nmap()
    return {
        "nmap_installed": is_installed,
        "message": "Nmap is ready" if is_installed else "Nmap not found. Install with: brew install nmap"
    }

@router.get("/")
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[ScanStatus] = Query(None),
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
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
                "status": s.status.value if hasattr(s.status, 'value') else s.status,
                "findings_count": len(s.findings) if s.findings else 0,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "error_message": s.error_message
            }
            for s in scans
        ]
    }

@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get scan by ID"""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type,
        "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
        "parameters": scan.parameters,
        "findings": scan.findings,
        "raw_output": scan.raw_output[:5000] if scan.raw_output else None,  # Limit output
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message
    }

def run_nmap_scan_task(
    scan_id: int,
    target_host: str,
    ports: Optional[str],
    db_session_factory
):
    """Background task to run actual nmap scan"""
    from database.connection import SessionLocal
    db = SessionLocal()
    try:
        # Update status to running
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if not scan:
            return
        
        scan.status = ScanStatus.running
        scan.started_at = datetime.datetime.utcnow()
        db.commit()
        
        # Run actual nmap scan
        result = scanner.scan_host(target_host, ports=ports, timeout=300)
        
        # Update scan with results
        scan.status = ScanStatus.completed if result["status"] == "success" else ScanStatus.failed
        scan.completed_at = datetime.datetime.utcnow()
        scan.findings = result.get("findings", [])
        scan.raw_output = result.get("raw_output", "")
        
        if result["status"] != "success":
            scan.error_message = result.get("error", "Unknown error")
        
        db.commit()
        
    except Exception as e:
        db.rollback()
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.failed
            scan.error_message = str(e)
            scan.completed_at = datetime.datetime.utcnow()
            db.commit()
    finally:
        db.close()

@router.post("/nmap")
def create_nmap_scan(
    target_id: int,
    ports: Optional[str] = Query(None, description="Port range (e.g., '80,443' or '1-1000')"),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start a real nmap scan on a target"""
    # Check nmap is installed
    if not scanner.check_nmap():
        raise HTTPException(
            status_code=503,
            detail="Nmap is not installed. Install it first: brew install nmap (macOS) or apt install nmap (Linux)"
        )
    
    # Validate target exists
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Create scan record
    scan = ScanResult(
        target_id=target_id,
        scan_type="nmap",
        status=ScanStatus.pending,
        parameters={
            "ports": ports or "default",
            "target": target.host,
            "initiated_by": current_user.username
        }
    )
    db.add(scan)
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="scan_start",
        resource_type="scan",
        details={"target_id": target_id, "scan_type": "nmap", "ports": ports}
    )
    db.add(audit_log)
    db.commit()
    db.refresh(scan)
    
    # Start background scan
    if background_tasks:
        background_tasks.add_task(
            run_nmap_scan_task,
            scan.id,
            target.host,
            ports,
            None
        )
    else:
        # Run synchronously for testing
        import threading
        thread = threading.Thread(
            target=run_nmap_scan_task,
            args=(scan.id, target.host, ports, None)
        )
        thread.daemon = True
        thread.start()
    
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type,
        "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        "message": "Nmap scan started. Poll /api/v1/scans/{id} for results.",
        "target_host": target.host
    }

@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete scan (only if not running)"""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if running
    current_status = scan.status.value if hasattr(scan.status, 'value') else str(scan.status)
    if current_status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete running scan")
    
    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action="scan_delete",
        resource_type="scan",
        resource_id=scan_id
    )
    db.add(audit_log)
    
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}
