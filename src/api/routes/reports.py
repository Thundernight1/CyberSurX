"""Report endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from database.models import Report

router = APIRouter()

@router.get("/")
def list_reports(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List all reports"""
    total = db.query(Report).count()
    reports = db.query(Report).offset(skip).limit(limit).all()
    return {
        "total": total,
        "data": [{
            "id": r.id,
            "title": r.title,
            "report_type": r.report_type,
            "format": r.format,
            "is_generated": r.is_generated,
            "generated_at": r.generated_at,
            "created_at": r.created_at
        } for r in reports]
    }

@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get report by ID"""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": report.id,
        "title": report.title,
        "content": report.content
    }

@router.post("/")
def create_report(
    user_id: int,
    title: str,
    report_type: str = "executive",
    report_format: str = "pdf",
    db: Session = Depends(get_db)
):
    """Generate new report"""
    report = Report(
        user_id=user_id,
        title=title,
        report_type=report_type,
        format=report_format
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"id": report.id, "message": "Report generation started"}
