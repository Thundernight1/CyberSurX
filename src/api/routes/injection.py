"""Injection testing with real HTTP scanning"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
import datetime

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from database import get_db
from database.models import InjectionTest, Target, AuditLog
from api.dependencies import get_current_user
from injection.scanners.web_vuln_scanner import WebVulnerabilityScanner

router = APIRouter()

@router.get("/tests")
def list_injection_tests(
    skip: int = 0,
    limit: int = 50,
    target: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all injection tests"""
    query = db.query(InjectionTest)
    if target:
        query = query.filter(InjectionTest.target.contains(target))
    
    tests = query.offset(skip).limit(limit).all()
    return {
        "total": query.count(),
        "data": [
            {
                "id": t.id,
                "target": t.target,
                "test_type": t.test_type,
                "payload_type": t.payload_type,
                "is_successful": t.is_successful,
                "vulnerability_detected": t.vulnerability_detected,
                "created_at": t.created_at
            }
            for t in tests
        ]
    }

def run_injection_scan_task(
    test_id: int,
    target_url: str,
    test_type: str
):
    """Background task for injection testing"""
    from database.connection import SessionLocal
    db = SessionLocal()
    
    try:
        test = db.query(InjectionTest).filter(InjectionTest.id == test_id).first()
        if not test:
            return
        
        scanner = WebVulnerabilityScanner()
        
        # Determine test to run
        if test_type in ["sqli", "sql_injection"]:
            result = scanner.test_sql_injection(target_url)
        elif test_type in ["xss", "cross_site_scripting"]:
            result = scanner.test_xss(target_url)
        elif test_type == "port_scan":
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            result = scanner.test_open_ports(parsed.netloc or parsed.path)
        else:
            result = {"error": "Unknown test type"}
        
        # Update test record
        test.response = str(result.get("results", []))[:1000]
        test.is_successful = result.get("results", [{}])[0].get("potential_vulnerable", False) if result.get("results") else False
        test.vulnerability_detected = result
        db.commit()
        
    except Exception as e:
        if test:
            test.response = f"Error: {str(e)}"
            db.commit()
    finally:
        db.close()

@router.post("/scan")
def create_injection_scan(
    target_url: str,
    test_type: str = "sqli",
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Run real injection test against a target URL"""
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = "http://" + target_url
    
    # Create test record
    test = InjectionTest(
        target=target_url,
        test_type=test_type,
        payload="PENDING-EXECUTION",
        payload_type="automated"
    )
    db.add(test)
    
    # Log
    audit = AuditLog(
        user_id=current_user.id,
        action="injection_test",
        resource_type="injection_test",
        details={"target": target_url, "type": test_type}
    )
    db.add(audit)
    db.commit()
    db.refresh(test)
    
    # Run in background
    import threading
    thread = threading.Thread(
        target=run_injection_scan_task,
        args=(test.id, target_url, test_type)
    )
    thread.daemon = True
    thread.start()
    
    return {
        "id": test.id,
        "target": target_url,
        "test_type": test_type,
        "status": "started",
        "message": f"{test_type} scan started. Check /api/v1/injection/tests/{test.id} for results."
    }

@router.get("/tests/{test_id}")
def get_injection_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get injection test result"""
    test = db.query(InjectionTest).filter(InjectionTest.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    return {
        "id": test.id,
        "target": test.target,
        "test_type": test.test_type,
        "payload": test.payload,
        "is_successful": test.is_successful,
        "vulnerability_detected": test.vulnerability_detected,
        "response": test.response,
        "created_at": test.created_at
    }

@router.get("/payloads")
def get_payloads(current_user = Depends(get_current_user)):
    """Get available attack payloads"""
    scanner = WebVulnerabilityScanner()
    return {
        "sqli_payloads": scanner.SQLI_PAYLOADS,
        "xss_payloads": scanner.XSS_PAYLOADS,
        "warning": "Only use on systems you own or have explicit permission to test"
    }
