"""Database model tests"""
import pytest
import sys
from pathlib import Path
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).parent.parent / "src"))

from database.models import Base, User, Target, ScanResult, Vulnerability, Report
from database.connection import SessionLocal, engine

# Test database
TEST_DATABASE_URL = "sqlite:///./test.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=test_engine)
    session = TestSession()
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)

class TestDatabaseModels:
    """Test all database models"""
    
    def test_create_user(self, db_session):
        """Test user creation"""
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password_here"
        )
        db_session.add(user)
        db_session.commit()
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
    
    def test_create_target(self, db_session):
        """Test target creation"""
        target = Target(
            name="Test Target",
            host="192.168.1.1",
            port=80,
            protocol="http",
            description="Test description"
        )
        db_session.add(target)
        db_session.commit()
        
        assert target.id is not None
        assert target.name == "Test Target"
        assert target.host == "192.168.1.1"
        assert target.port == 80
    
    def test_create_scan_result(self, db_session):
        """Test scan result creation"""
        target = Target(name="Test", host="127.0.0.1")
        db_session.add(target)
        db_session.commit()
        
        scan = ScanResult(
            target_id=target.id,
            scan_type="nmap",
            parameters={"ports": "80,443"},
            findings=[{"port": 80, "status": "open"}]
        )
        db_session.add(scan)
        db_session.commit()
        
        assert scan.id is not None
        assert scan.scan_type == "nmap"
        assert len(scan.findings) == 1
    
    def test_create_vulnerability(self, db_session):
        """Test vulnerability creation"""
        from database.models import RiskLevel
        
        vuln = Vulnerability(
            target_id=1,
            vuln_type="sqli",
            severity=RiskLevel.critical,
            title="SQL Injection in Login",
            description="The login form is vulnerable to SQL injection",
            cve_id="CVE-2021-1234",
            cvss_score="9.8"
        )
        # Note: target_id 1 should exist, add it first
        target = Target(name="Test Target", host="192.168.1.1")
        db_session.add(target)
        db_session.commit()
        vuln.target_id = target.id
        db_session.add(vuln)
        db_session.commit()
        
        assert vuln.id is not None
        assert vuln.severity == RiskLevel.critical
