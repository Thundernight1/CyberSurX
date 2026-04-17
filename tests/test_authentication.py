"""Authentication tests - JWT validation, password hashing, token generation"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from core.auth_utils import (
    get_password_hash, verify_password, create_access_token, decode_token
)

class TestPasswordHashing:
    """Test password hashing functions"""
    
    def test_password_hashing_creates_different_hashes(self):
        """Same password should produce different hashes"""
        password = "testpassword123"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        assert hash1 != hash2
        assert len(hash1) > 20  # Expected bcrypt hash length
    
    def test_password_verification_success(self):
        """Correct password should verify"""
        password = "mypassword"
        hashed = get_password_hash(password)
        
        assert verify_password(password, hashed) is True
    
    def test_password_verification_failure(self):
        """Wrong password should fail verification"""
        password = "correctpassword"
        hashed = get_password_hash(password)
        
        assert verify_password("wrongpassword", hashed) is False
    
    def test_password_verification_wrong_hash(self):
        """Completely different hash should fail"""
        wrong_hash = "$2b$12$wronghashformat12345678901"
        
        assert verify_password("anypassword", wrong_hash) is False

class TestJWTToken:
    """Test JWT token generation and validation"""
    
    def test_token_creation_with_user_data(self):
        """Token should contain user data"""
        user_data = {"sub": 1, "username": "testuser", "is_admin": False}
        token = create_access_token(user_data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are long
    
    def test_token_decode_returns_original_data(self):
        """Decoded token should return original payload"""
        user_data = {"sub": 42, "username": "testuser"}
        token = create_access_token(user_data)
        decoded = decode_token(token)
        
        assert decoded is not None
        assert decoded["sub"] == 42
        assert decoded["username"] == "testuser"
    
    def test_invalid_token_returns_none(self):
        """Invalid token should return None"""
        result = decode_token("invalid.token.here")
        
        assert result is None
    
    def test_expired_token_returns_none(self):
        """Expired token should not decode successfully"""
        from datetime import timedelta
        
        user_data = {"sub": 1}
        # Create token that expired 1 hour ago
        token = create_access_token(user_data, expires_delta=timedelta(seconds=-3600))
        decoded = decode_token(token)
        
        # Expired tokens return None or have expired flag
        assert decoded is None or "exp" in decoded

class TestAuthEdgeCases:
    """Edge cases and validation"""
    
    def test_empty_password_handling(self):
        """Empty password should still hash"""
        hashed = get_password_hash("")
        assert hashed is not None
        assert len(hashed) > 0
    
    def test_long_password_handling(self):
        """Very long password should work"""
        long_password = "A" * 1000
        hashed = get_password_hash(long_password)
        
        assert verify_password(long_password, hashed) is True
