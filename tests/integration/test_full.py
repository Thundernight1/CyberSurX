"""End-to-end integration tests"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from database.models import Base, ScanStatus, RiskLevel
from database.connection import engine

class TestIntegration:
    """Full integration tests"""
    
    def test_database_enum_values(self):
        """Test database enum definitions"""
        assert ScanStatus.pending.value == "pending"
        assert ScanStatus.running.value == "running"
        assert ScanStatus.completed.value == "completed"
        
        assert RiskLevel.critical.value == "critical"
        assert RiskLevel.high.value == "high"
        assert RiskLevel.medium.value == "medium"
        assert RiskLevel.low.value == "low"
        assert RiskLevel.info.value == "info"
    
    def test_import_all_modules(self):
        """Test all modules can be imported"""
        try:
            from database import get_db, SessionLocal
            from database.models import User, Target, ScanResult
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import database modules: {e}")
        
        try:
            from api.main import app
            from api.routes import scans, targets, vulnerabilities
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import API modules: {e}")
        
        try:
            from core.base_agent import BaseAgent, AgentLayer
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import core modules: {e}")
    
    def test_cli_module_import(self):
        """Test CLI module imports"""
        try:
            import cli
            assert hasattr(cli, 'app')
        except ImportError as e:
            pytest.fail(f"Failed to import CLI: {e}")
