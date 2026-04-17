"""Injection testing endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from database.models import InjectionTest

router = APIRouter()

@router.get("/tests")
def list_injection_tests(db: Session = Depends(get_db)):
    """List all injection tests"""
    tests = db.query(InjectionTest).all()
    return {
        "data": [{
            "id": t.id,
            "target": t.target,
            "test_type": t.test_type,
            "payload_type": t.payload_type,
            "is_successful": t.is_successful,
            "created_at": t.created_at
        } for t in tests]
    }

@router.post("/tests")
def create_injection_test(
    target: str,
    test_type: str,
    payload: str,
    payload_type: str = "single_turn",
    db: Session = Depends(get_db)
):
    """Create new injection test"""
    test = InjectionTest(
        target=target,
        test_type=test_type,
        payload=payload,
        payload_type=payload_type
    )
    db.add(test)
    db.commit()
    db.refresh(test)
    return {"id": test.id, "message": "Injection test recorded"}

@router.get("/payloads")
def get_payloads():
    """Get available payloads"""
    return {
        "sqli_payloads": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "') UNION SELECT * FROM users --"
        ],
        "xss_payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>"
        ]
    }
