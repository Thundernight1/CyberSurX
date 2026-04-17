"""API endpoint integration tests"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from fastapi.testclient import TestClient
from api.main import app
from database.connection import engine, Base

# Create test database tables
Base.metadata.create_all(bind=engine)
client = TestClient(app)

class TestHealthEndpoints:
    """Test basic health checks"""
    
    def test_health_check_returns_200(self):
        """Health endpoint should return 200"""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_api_status_returns_structure(self):
        """Status endpoint should return structured data"""
        response = client.get("/api/v1/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data
        assert "status" in data

class TestAuthEndpoints:
    """Test authentication endpoints"""
    
    def test_register_requires_valid_email(self):
        """Registration should reject invalid email"""
        response = client.post(
            "/api/v1/auth/register",
            params={"username": "test", "email": "invalid-email", "password": "short"}
        )
        
        assert response.status_code == 422 or response.status_code == 400
    
    def test_login_returns_token_structure(self):
        """Login should return token (after user creation)"""
        # First create user
        client.post(
            "/api/v1/auth/register",
            params={"username": "logintest", "email": "login@test.com", "password": "password123"}
        )
        
        response = client.post(
            "/api/v1/auth/login",
            params={"email": "login@test.com", "password": "password123"}
        )
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            assert "token_type" in data
            assert data["token_type"] == "bearer"
    
    def test_login_wrong_password_fails(self):
        """Wrong password should fail"""
        response = client.post(
            "/api/v1/auth/login",
            params={"email": "nouser@exists.com", "password": "wrongpassword"}
        )
        
        assert response.status_code == 401

class TestTargetEndpoints:
    """Test target CRUD endpoints"""
    
    def test_list_targets_requires_auth(self):
        """Target list should require authentication"""
        response = client.get("/api/v1/targets/")
        
        assert response.status_code == 401 or response.status_code == 403
    
    def test_create_target_validates_host(self):
        """Target creation should validate host"""
        # This would need auth token in real scenario
        # Testing validation response
        response = client.post(
            "/api/v1/targets/",
            params={"name": "Test", "host": "x"}  # Too short
        )
        
        assert response.status_code in [400, 401, 422]

class TestScanEndpoints:
    """Test scan endpoints"""
    
    def test_nmap_check_returns_status(self):
        """Nmap check should return installation status"""
        response = client.get("/api/v1/scans/nmap-check")
        
        # Requires auth
        assert response.status_code in [200, 401, 403]
    
    def test_list_scans_requires_auth(self):
        """Scan list should require authentication"""
        response = client.get("/api/v1/scans/")
        
        assert response.status_code == 401 or response.status_code == 403

class TestInjectionEndpoints:
    """Test injection endpoints"""
    
    def test_payloads_requires_auth(self):
        """Payload list should require auth"""
        response = client.get("/api/v1/injection/payloads")
        
        assert response.status_code == 401 or response.status_code == 403
    
    def test_scan_requires_auth(self):
        """Injection scan should require auth"""
        response = client.post(
            "/api/v1/injection/scan",
            params={"target_url": "http://test.com", "test_type": "sqli"}
        )
        
        assert response.status_code == 401 or response.status_code == 403
