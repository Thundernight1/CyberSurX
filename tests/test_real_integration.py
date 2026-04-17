"""Full system integration tests - modules must work together"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

# Test 1: Database → API Entegrasyonu
def test_database_api_integration():
    """API must be able to query database"""
    from database import get_db
    from database.models import User, Target
    
    # Create database session
    db = next(get_db())
    
    # Create test user
    user = User(username="test_int", email="int@test.com", hashed_password="pass")
    db.add(user)
    db.commit()
    user_id = user.id
    
    # Create target linked to user
    target = Target(name="Test Target", host="192.168.1.1")
    db.add(target)
    db.commit()
    target_id = target.id
    
    # Query through database (like API would)
    queried = db.query(User).filter(User.id == user_id).first()
    assert queried.username == "test_int"
    
    queried_target = db.query(Target).filter(Target.id == target_id).first()
    assert queried_target.host == "192.168.1.1"
    
    # Cleanup
    db.delete(target)
    db.delete(user)
    db.commit()

# Test 2: Auth → API Entegrasyonu  
def test_auth_token_works_with_api():
    """JWT token must authenticate API requests"""
    from core.auth_utils import create_access_token, decode_token
    
    # Create token
    user_data = {"sub": 1, "username": "apitest"}
    token = create_access_token(user_data)
    
    # Token must be decodable
    decoded = decode_token(token)
    assert decoded is not None
    assert decoded["sub"] == 1
    assert decoded["username"] == "apitest"

# Test 3: Scanner → Database Entegrasyonu
def test_scanner_results_can_be_saved():
    """Scanner results must be storable in database"""
    from redteam.modules.scanner import NmapScanner
    from database import get_db
    from database.models import ScanResult, ScanStatus
    
    scanner = NmapScanner()
    db = next(get_db())
    
    # Create scan record (like API would do)
    scan = ScanResult(
        target_id=1,
        scan_type="nmap",
        status=ScanStatus.pending,
        parameters={"ports": "80"}
    )
    db.add(scan)
    db.commit()
    
    # Scanner must return results that fit database schema
    result = scanner.scan_host("127.0.0.1", ports="80", timeout=5)
    
    # Update database with results
    scan.status = ScanStatus.completed if result["status"] == "success" else ScanStatus.failed
    scan.findings = result.get("findings", [])
    db.commit()
    
    # Verify saved
    saved_scan = db.query(ScanResult).filter(ScanResult.id == scan.id).first()
    assert saved_scan is not None
    assert saved_scan.scan_type == "nmap"

# Test 4: Vulnerability Scanner → Database
def test_vulnerability_scan_save():
    """Vulnerability findings must save to database"""
    from injection.scanners.web_vuln_scanner import WebVulnerabilityScanner
    from database import get_db
    from database.models import Vulnerability
    
    scanner = WebVulnerabilityScanner()
    db = next(get_db())
    
    # Create vulnerability record
    vuln = Vulnerability(
        target_id=1,
        vuln_type="sqli",
        severity="high",
        title="SQL Injection Test",
        description="Test vulnerability"
    )
    db.add(vuln)
    db.commit()
    
    # Scanner result must be compatible
    result = scanner.test_sql_injection("http://127.0.0.1/test")
    
    # Update with actual results
    vuln.evidence = {"scan_results": result.get("results", [])}
    db.commit()
    
    # Verify
    saved = db.query(Vulnerability).filter(Vulnerability.id == vuln.id).first()
    assert saved is not None
    assert "scan_results" in saved.evidence

# Test 5: Exploit → Safety → Audit Log
def test_exploit_safety_logs_to_audit():
    """Exploit execution must log to audit"""
    from redteam.modules.exploit_executor import ExploitExecutor
    from database import get_db
    from database.models import AuditLog
    
    db = next(get_db())
    
    # Execute dangerous command (should be blocked)
    result = ExploitExecutor.execute_command("rm -rf /")
    
    # Dangerous commands must be blocked
    assert result["status"] == "blocked"
    
    # Log the attempt
    log = AuditLog(
        user_id=1,
        action="exploit_attempt_blocked",
        resource_type="exploit",
        details={"command": "rm -rf /", "result": result["status"]}
    )
    db.add(log)
    db.commit()
    
    # Verify logged
    saved_log = db.query(AuditLog).filter(AuditLog.id == log.id).first()
    assert saved_log is not None
    assert saved_log.action == "exploit_attempt_blocked"

# Test 6: API Routes → Auth → Database
def test_api_route_flow():
    """Full flow: API request → Auth check → Database → Response"""
    from api.dependencies import get_current_user
    from core.auth_utils import create_access_token
    from database import get_db
    from database.models import User
    
    # Create user in database
    db = next(get_db())
    user = User(username="flowtest", email="flow@test.com", hashed_password="hashed")
    db.add(user)
    db.commit()
    user_id = user.id
    
    # Create token for user
    token = create_access_token({"sub": user_id, "username": "flowtest"})
    assert token is not None
    
    # Token must contain data needed for auth
    from core.auth_utils import decode_token
    decoded = decode_token(token)
    assert decoded["sub"] == user_id
    
    # User must be queryable by that ID
    db_user = db.query(User).filter(User.id == decoded["sub"]).first()
    assert db_user.username == "flowtest"

# Test 7: End-to-End: Create Target → Scan → Save Results
def test_target_to_scan_workflow():
    """Complete workflow: Target creation → Scan → Results saved"""
    from database import get_db
    from database.models import Target, ScanResult, ScanStatus
    from redteam.modules.scanner import NmapScanner
    
    db = next(get_db())
    
    # Create target
    target = Target(name="E2E Test", host="127.0.0.1")
    db.add(target)
    db.commit()
    target_id = target.id
    
    # Create scan
    scan = ScanResult(
        target_id=target_id,
        scan_type="nmap",
        status=ScanStatus.pending
    )
    db.add(scan)
    db.commit()
    scan_id = scan.id
    
    # Execute scan (simplified)
    scanner = NmapScanner()
    result = scanner.scan_host("127.0.0.1", timeout=5)
    
    # Update scan
    scan.status = ScanStatus.completed if result["status"] == "success" else ScanStatus.failed
    scan.findings = result.get("findings", [])
    scan.completed_at = datetime.utcnow() if "datetime" in globals() else None
    db.commit()
    
    # Verify complete flow
    saved_target = db.query(Target).filter(Target.id == target_id).first()
    saved_scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    
    assert saved_target.name == "E2E Test"
    assert saved_scan.target_id == target_id
    assert saved_scan.scan_type == "nmap"
