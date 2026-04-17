"""Web vulnerability scanner tests"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from injection.scanners.web_vuln_scanner import WebVulnerabilityScanner

class TestWebScannerBasics:
    """Test basic scanner functionality"""
    
    def test_scanner_initialization(self):
        """Scanner should initialize with timeout"""
        scanner = WebVulnerabilityScanner(timeout=5)
        
        assert scanner.timeout == 5
        assert scanner.session is not None
    
    def test_scanner_default_timeout(self):
        """Default timeout should be 10"""
        scanner = WebVulnerabilityScanner()
        
        assert scanner.timeout == 10
    
    def test_sqli_payloads_exist(self):
        """SQLi payloads should be defined"""
        scanner = WebVulnerabilityScanner()
        
        assert len(scanner.SQLI_PAYLOADS) > 0
        assert "' OR '1'='1" in scanner.SQLI_PAYLOADS
    
    def test_xss_payloads_exist(self):
        """XSS payloads should be defined"""
        scanner = WebVulnerabilityScanner()
        
        assert len(scanner.XSS_PAYLOADS) > 0
        assert "<script>alert(1)</script>" in scanner.XSS_PAYLOADS

class TestPortScanning:
    """Test port scanning functionality"""
    
    def test_port_scan_returns_structure(self):
        """Port scan should return structured data"""
        scanner = WebVulnerabilityScanner()
        result = scanner.test_open_ports("127.0.0.1")
        
        assert "host" in result
        assert "open_ports" in result
        assert "scanned_ports" in result
        assert result["host"] == "127.0.0.1"
        assert isinstance(result["open_ports"], list)
    
    def test_port_scan_with_custom_ports(self):
        """Custom port list should work"""
        scanner = WebVulnerabilityScanner()
        result = scanner.test_open_ports("127.0.0.1", ports=[80, 443])
        
        assert result["scanned_ports"] == 2

class TestSQLInjection:
    """Test SQL injection detection"""
    
    def test_sqli_test_returns_structure(self):
        """SQLi test should return proper structure"""
        scanner = WebVulnerabilityScanner()
        result = scanner.test_sql_injection("http://127.0.0.1:9000/test")
        
        assert "vulnerability" in result
        assert result["vulnerability"] == "SQL Injection"
        assert "results" in result
        assert "recommendation" in result
    
    def test_sqli_test_handles_connection_error(self):
        """Should handle connection errors gracefully"""
        scanner = WebVulnerabilityScanner()
        result = scanner.test_sql_injection("http://nonexistent-server-99999.local")
        
        assert "results" in result
        # Should have error entries but not crash

class TestXSSTesting:
    """Test XSS detection"""
    
    def test_xss_test_returns_structure(self):
        """XSS test should return proper structure"""
        scanner = WebVulnerabilityScanner()
        result = scanner.test_xss("http://127.0.0.1/test")
        
        assert "vulnerability" in result
        assert result["vulnerability"] == "Cross-Site Scripting (XSS)"
        assert "results" in result

class TestVulnerabilityPayloads:
    """Test payload effectiveness"""
    
    def test_sqli_payloads_coverage(self):
        """Should have various SQL injection vectors"""
        scanner = WebVulnerabilityScanner()
        
        # Union based
        assert any("UNION" in p for p in scanner.SQLI_PAYLOADS)
        # Boolean based
        assert any("OR" in p for p in scanner.SQLI_PAYLOADS)
        # Comment based
        assert any("--" in p for p in scanner.SQLI_PAYLOADS)
    
    def test_xss_payloads_coverage(self):
        """Should have various XSS vectors"""
        scanner = WebVulnerabilityScanner()
        
        # Script tag
        assert any("<script" in p for p in scanner.XSS_PAYLOADS)
        # Event handler
        assert any("onerror" in p.lower() for p in scanner.XSS_PAYLOADS)
        # SVG
        assert any("<svg" in p.lower() for p in scanner.XSS_PAYLOADS)
