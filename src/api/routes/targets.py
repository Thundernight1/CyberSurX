"""Target endpoints"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from database.models import Target

router = APIRouter()

@router.get("/")
def list_targets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = Query(None),
    db: Session = Depends(get_db)
):
    """List all targets"""
    query = db.query(Target)
    if is_active is not None:
        query = query.filter(Target.is_active == is_active)
    
    total = query.count()
    targets = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": [
            {
                "id": t.id,
                "name": t.name,
                "host": t.host,
                "port": t.port,
                "protocol": t.protocol,
                "description": t.description,
                "is_active": t.is_active,
                "created_at": t.created_at,
                "updated_at": t.updated_at
            }
            for t in targets
        ]
    }

@router.get("/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db)):
    """Get target by ID"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return {
        "id": target.id,
        "name": target.name,
        "host": target.host,
        "port": target.port,
        "protocol": target.protocol,
        "description": target.description,
        "is_active": target.is_active,
        "created_at": target.created_at,
        "updated_at": target.updated_at
    }

@router.post("/")
def create_target(
    name: str,
    host: str,
    port: Optional[int] = None,
    protocol: str = "http",
    description: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Create new target"""
    target = Target(
        name=name,
        host=host,
        port=port,
        protocol=protocol,
        description=description
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    
    return {
        "id": target.id,
        "name": target.name,
        "host": target.host,
        "port": target.port,
        "protocol": target.protocol,
        "description": target.description,
        "message": "Target created successfully"
    }

@router.put("/{target_id}")
def update_target(
    target_id: int,
    name: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    description: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Update target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if name:
        target.name = name
    if host:
        target.host = host
    if port is not None:
        target.port = port
    if protocol:
        target.protocol = protocol
    if description is not None:
        target.description = description
    if is_active is not None:
        target.is_active = is_active
    
    db.commit()
    db.refresh(target)
    
    return {
        "id": target.id,
        "name": target.name,
        "host": target.host,
        "port": target.port,
        "protocol": target.protocol,
        "message": "Target updated successfully"
    }

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    """Delete target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    db.delete(target)
    db.commit()
    return {"message": "Target deleted successfully"}
