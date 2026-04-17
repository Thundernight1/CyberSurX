"""Database integration tests"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, User, Target, ScanResult, Vulnerability
from database.models import ScanStatus, RiskLevel

# Test database
TEST_DB_URL = "sqlite:///./test_database.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

class TestUserModel:
    """Test User ORM model"""
    
    def test_create_user(self, db_session):
        """Should create user in database"""
        user = User(
            username="testuser",
            email="test@test.com",
            hashed_password="hashed123"
        )
        db_session.add(user)
        db_session.commit()
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.is_active is True
        assert user.is_admin is False
    
    def test_user_unique_constraint(self, db_session):
        """Should enforce unique username and email"""
        user1 = User(username="unique", email="unique@test.com", hashed_password="pass")
        db_session.add(user1)
        db_session.commit()
        
        user2 = User(username="unique", email="other@test.com", hashed_password="pass")
        db_session.add(user2)
        
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()

class TestTargetModel:
    """Test Target ORM model"""
    
    def test_create_target(self, db_session):
        """Should create target"""
        target = Target(
            name="Test Server",
            host="192.168.1.1",
            port=80,
            protocol="http"
        )
        db_session.add(target)
        db_session.commit()
        
        assert target.id is not None
        assert target.host == "192.168.1.1"
        assert target.is_active is True
    
    def test_target_default_protocol(self, db_session):
        """Should default to http protocol"""
        target = Target(name="Test", host="1.2.3.4")
        db_session.add(target)
        db_session.commit()
        
        assert target.protocol == "http"

class TestScanResultModel:
    """Test ScanResult ORM model"""
    
    def test_create_scan_result(self, db_session):
        """Should create scan result"""
        scan = ScanResult(
            target_id=1,
            scan_type="nmap",
            status=ScanStatus.pending,
            parameters={"ports": "80,443"},
            findings=[{"port": 80}]
        )
        db_session.add(scan)
        db_session.commit()
        
        assert scan.id is not None
        assert scan.scan_type == "nmap"
        assert scan.status == ScanStatus.pending
    
    def test_scan_status_enum_values(self):
        """ScanStatus enum should have expected values"""
        assert ScanStatus.pending.value == "pending"
        assert ScanStatus.running.value == "running"
        assert ScanStatus.completed.value == "completed"
        assert ScanStatus.failed.value == "failed"

class TestVulnerabilityModel:
    """Test Vulnerability ORM model"""
    
    def test_create_vulnerability(self, db_session):
        """Should create vulnerability"""
        vuln = Vulnerability(
            target_id=1,
            vuln_type="sqli",
            severity=RiskLevel.high,
            title="SQL Injection",
            description="Test vulnerability"
        )
        db_session.add(vuln)
        db_session.commit()
        
        assert vuln.id is not None
        assert vuln.severity == RiskLevel.high
        assert vuln.is_fixed is False
    
    def test_risk_level_enum_values(self):
        """RiskLevel enum should have expected values"""
        assert RiskLevel.critical.value == "critical"
        assert RiskLevel.high.value == "high"
        assert RiskLevel.medium.value == "medium"
        assert RiskLevel.low.value == "low"
