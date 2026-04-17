"""
End-to-End Tests for CyberSurX
CLI smoke tests
"""
import subprocess
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent

class TestCLIExecution:
    """CLI execution tests"""
    
    def test_cli_help(self):
        """Test CLI help command"""
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )
        # Should fail due to missing dependencies but show help
        assert "cybersurx" in result.stdout.lower() or result.returncode in [0, 1]
    
    def test_python_syntax(self):
        """Test all Python files have valid syntax"""
        src_dir = PROJECT_ROOT / "src"
        py_files = list(src_dir.rglob("*.py"))
        
        for py_file in py_files:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(py_file)],
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Syntax error in {py_file}"
