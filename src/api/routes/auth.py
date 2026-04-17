"""Authentication endpoints"""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from database import get_db
from database.models import User
from core.auth_utils import (
    get_password_hash, verify_password, create_access_token, 
    ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    username: str,
    email: str,
    password: str,
    db: Session = Depends(get_db)
):
    """Register new user"""
    # Validate inputs
    if len(username) < 3 or len(username) > 50:
        raise HTTPException(400, "Username must be 3-50 characters")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if "@" not in email:
        raise HTTPException(400, "Invalid email format")
    
    # Check existing
    existing_user = db.query(User).filter(
        (User.email == email) | (User.username == username)
    ).first()
    if existing_user:
        raise HTTPException(400, "Username or email already registered")
    
    # Create user
    hashed_password = get_password_hash(password)
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "message": "User registered successfully. Please login."
    }

@router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    """Login user and return JWT token"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(401, "Invalid email or password")
    
    if not verify_password(password, user.hashed_password):
        raise HTTPException(401, "Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id, "username": user.username, "is_admin": user.is_admin},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }

from api.dependencies import get_current_user

@router.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at
    }
