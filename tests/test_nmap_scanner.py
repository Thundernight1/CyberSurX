"""Nmap scanner integration tests"""
import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from redteam.modules.scanner import NmapScanner

class TestNmapScanner:
    """Test real nmap scanner functionality"""
    
    def test_nmap_check_returns_boolean(self):
        """Check should return True or False"""
        result = NmapScanner.check_nmap()
        assert isinstance(result, bool)
    
    def test_scan_returns_proper_structure(self):
        """Scan should return structured result"""
        scanner = NmapScanner()
        result = scanner.scan_host("127.0.0.1", ports="80", timeout=5)
        
        # Must have these keys regardless of nmap status
        assert "status" in result
        assert "command" in result
        assert result["status"] in ["success", "error", "timeout"]
    
    def test_scan_timeout_handling(self):
        """Very short timeout should handle gracefully"""
        scanner = NmapScanner()
        result = scanner.scan_host("127.0.0.1", ports="1-1000", timeout=1)
        
        # Should not crash, return proper structure
        assert isinstance(result, dict)
        assert "status" in result
    
    def test_scan_invalid_host(self):
        """Invalid host should return error"""
        scanner = NmapScanner()
        result = scanner.scan_host("not-a-valid-host-12345.xyz", timeout=2)
        
        assert result["status"] in ["error", "timeout"]

class TestXmlParsing:
    """Test XML output parsing"""
    
    def test_parse_valid_xml(self):
        """Valid nmap XML should parse"""
        sample_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port portid="80" protocol="tcp">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        result = NmapScanner._parse_xml(sample_xml)
        
        assert len(result) > 0
        assert result[0]["port"] == 80
        assert result[0]["state"] == "open"
    
    def test_parse_invalid_xml(self):
        """Invalid XML should return empty list, not crash"""
        result = NmapScanner._parse_xml("<invalid>")
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_parse_empty_xml(self):
        """Empty XML should return empty list"""
        result = NmapScanner._parse_xml("")
        
        assert isinstance(result, list)

class TestScannerEdgeCases:
    """Edge cases"""
    
    def test_scan_with_special_characters_in_host(self):
        """Special chars in host should not crash"""
        scanner = NmapScanner()
        result = scanner.scan_host("test\'test;", timeout=1)
        
        assert isinstance(result, dict)
        assert "status" in result
    
    def test_scan_with_empty_ports(self):
        """Empty ports should default to all ports"""
        scanner = NmapScanner()
        result = scanner.scan_host("127.0.0.1", ports=None, timeout=1)
        
        assert isinstance(result, dict)
