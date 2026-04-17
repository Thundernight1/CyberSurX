"""Initialize database tables"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from database.connection import engine, Base
from database.models import (
    User, Target, ScanResult, Vulnerability, Report,
    AuditLog, AgentExecution, Device, InjectionTest
)

def init_database():
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully")
    
    # List created tables
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"\nTables created: {', '.join(tables)}")

if __name__ == "__main__":
    init_database()
