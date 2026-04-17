"""
Integration Tests for CyberSurX
Tests module interactions
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

class TestPipeline:
    """End-to-end pipeline tests"""
    
    def test_full_pipeline_imports(self):
        """Test all major components can be imported together"""
        try:
            from cli import app
            from core.base_agent import BaseAgent
            from redteam.redteam import RedTeamAutomation
        except ImportError as e:
            pytest.fail(f"Pipeline imports failed: {e}")
    
    def test_config_loading(self):
        """Test configuration can be loaded"""
        import yaml
        config_path = Path(__file__).parent.parent / "config.yaml.example"
        
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)
                assert isinstance(config, dict)
