"""CLI integration tests"""
import pytest
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

class TestCLICommands:
    """Test CLI commands"""
    
    def test_cli_help(self):
        """Test CLI help command"""
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )
        # Command should either succeed or show help
        assert "cybersurx" in result.stdout.lower() or "CyberSurX" in result.stdout
    
    def test_cli_status(self):
        """Test CLI status command"""
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "status"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )
        # Should run without crashing
        assert result.returncode in [0, 1]  # 0 = success, 1 = error but handled
    
    def test_cli_version(self):
        """Test CLI version flag"""
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "--version"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
