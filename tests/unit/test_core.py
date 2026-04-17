"""
Unit Tests for CyberSurX Core Modules
"""
import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

class TestCLI:
    """CLI module tests"""
    
    def test_import_cli(self):
        """Test CLI module imports"""
        try:
            from cli import app, show_banner
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import CLI: {e}")
    
    def test_version_defined(self):
        """Test version is defined"""
        import cli
        assert hasattr(cli, 'VERSION')
        assert isinstance(cli.VERSION, str)


class TestCoreModules:
    """Core module tests"""
    
    def test_base_agent_import(self):
        """Test base_agent imports successfully"""
        try:
            from core.base_agent import BaseAgent, AgentLayer
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import BaseAgent: {e}")
    
    def test_llm_client_import(self):
        """Test llm_client imports successfully"""
        try:
            from core.llm_client import LLMClient
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import LLMClient: {e}")


class TestRedteamModules:
    """Redteam module tests"""
    
    def test_redteam_import(self):
        """Test redteam module imports"""
        try:
            from redteam.redteam import RedTeamAutomation
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import RedTeam: {e}")


class TestInjectionModules:
    """Injection testing module tests"""
    
    def test_injection_imports(self):
        """Test injection modules are importable"""
        try:
            from injection import scanners
            assert True
        except ImportError:
            pytest.skip("Injection modules not fully implemented")


class TestConfiguration:
    """Configuration tests"""
    
    def test_config_exists(self):
        """Test config file exists"""
        config_path = Path(__file__).parent.parent / "config.yaml.example"
        assert config_path.exists(), "config.yaml.example should exist"
    
    def test_requirements_exists(self):
        """Test requirements file exists"""
        req_path = Path(__file__).parent.parent / "requirements.txt"
        assert req_path.exists(), "requirements.txt should exist"
