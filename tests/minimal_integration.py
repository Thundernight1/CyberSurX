"""Minimal integration verification"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "src"))

def test_imports_work():
    """All modules must import without errors"""
    from api.main import app
    from database import get_db, engine
    from database.models import User, Target
    from core.auth_utils import create_access_token
    from redteam.modules.scanner import NmapScanner
    from injection.scanners.web_vuln_scanner import WebVulnerabilityScanner
    print("✅ All imports successful")

def test_database_connection():
    """Database must be connectable"""
    from database import engine
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert len(tables) >= 9, f"Expected 9+ tables, found {len(tables)}"
    print(f"✅ Database has {len(tables)} tables")

def test_jwt_flow():
    """JWT must encode and decode"""
    from core.auth_utils import create_access_token, decode_token
    token = create_access_token({"sub": 1, "user": "test"})
    decoded = decode_token(token)
    assert decoded["sub"] == 1
    print("✅ JWT encode/decode working")

if __name__ == "__main__":
    test_imports_work()
    test_database_connection()
    test_jwt_flow()
    print("\n=== ALL INTEGRATION CHECKS PASSED ===")
