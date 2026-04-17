"""API endpoint tests"""
import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).parent.parent / "src"))

from api.main import app
from database.connection import engine, Base

client = TestClient(app)

# Create test database tables before tests
Base.metadata.create_all(bind=engine)

class TestHealthEndpoints:
    """Test basic health endpoints"""
    
    def test_health_check(self):
        """Test /health endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["app"] == "cybersurx"
    
    def test_api_status(self):
        """Test /api/v1/status endpoint"""
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["api_version"] == "1.0.0"
        assert data["status"] == "operational"

class TestTargetEndpoints:
    """Test target API endpoints"""
    
    def test_list_targets(self):
        """Test GET /api/v1/targets/"""
        response = client.get("/api/v1/targets/")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
    
    def test_create_target(self):
        """Test POST /api/v1/targets/"""
        response = client.post(
            "/api/v1/targets/",
            params={"name": "Test Target", "host": "192.168.1.100"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["host"] == "192.168.1.100"

class TestScanEndpoints:
    """Test scan API endpoints"""
    
    def test_list_scans(self):
        """Test GET /api/v1/scans/"""
        response = client.get("/api/v1/scans/")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
    
    def test_get_scan_not_found(self):
        """Test GET /api/v1/scans/99999 (not found)"""
        response = client.get("/api/v1/scans/99999")
        assert response.status_code == 404

class TestVulnerabilityEndpoints:
    """Test vulnerability API endpoints"""
    
    def test_list_vulnerabilities(self):
        """Test GET /api/v1/vulnerabilities/"""
        response = client.get("/api/v1/vulnerabilities/")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data

class TestDeviceEndpoints:
    """Test device API endpoints"""
    
    def test_list_devices(self):
        """Test GET /api/v1/devices/"""
        response = client.get("/api/v1/devices/")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data

class TestInjectionEndpoints:
    """Test injection API endpoints"""
    
    def test_list_injection_tests(self):
        """Test GET /api/v1/injection/tests"""
        response = client.get("/api/v1/injection/tests")
        assert response.status_code == 200
    
    def test_get_payloads(self):
        """Test GET /api/v1/injection/payloads"""
        response = client.get("/api/v1/injection/payloads")
        assert response.status_code == 200
        data = response.json()
        assert "sqli_payloads" in data
        assert "xss_payloads" in data
