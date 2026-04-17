"""Device endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from database.models import Device

router = APIRouter()

@router.get("/")
def list_devices(db: Session = Depends(get_db)):
    """List all devices"""
    devices = db.query(Device).all()
    return {
        "data": [{
            "id": d.id,
            "name": d.name,
            "device_type": d.device_type,
            "ip_address": d.ip_address,
            "is_connected": d.is_connected,
            "last_seen": d.last_seen
        } for d in devices]
    }

@router.post("/")
def create_device(
    name: str,
    device_type: str,
    ip_address: str = None,
    port: int = None,
    username: str = None,
    db: Session = Depends(get_db)
):
    """Add new device"""
    device = Device(
        name=name,
        device_type=device_type,
        ip_address=ip_address,
        port=port,
        username=username
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"id": device.id, "message": "Device added successfully"}

@router.delete("/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_db)):
    """Delete device"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"message": "Device deleted successfully"}
