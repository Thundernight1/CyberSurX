"""Web vulnerability scanner - SQLi, XSS detection"""
import requests
from typing import Dict, List

class WebVulnerabilityScanner:
    """Scan web applications for vulnerabilities"""
    
    SQLI_PAYLOADS = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "1; DELETE FROM users WHERE 'a'='a",
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=1 onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
    
    def test_sql_injection(self, url: str) -> Dict:
        """Test for SQL injection"""
        results = []
        for payload in self.SQLI_PAYLOADS[:2]:  # Limit for demo
            try:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for SQL errors
                if any(err in response.text.lower() for err in ['sql', 'mysql', 'sqlite', 'error']):
                    results.append({"payload": payload, "suspicious": True})
                else:
                    results.append({"payload": payload, "suspicious": False})
            except:
                results.append({"payload": payload, "error": "Connection failed"})
        
        return {
            "vulnerability": "SQL Injection",
            "target": url,
            "results": results,
            "recommendation": "Use parameterized queries and input validation"
        }
    
    def test_xss(self, url: str) -> Dict:
        """Test for XSS vulnerabilities"""
        results = []
        for payload in self.XSS_PAYLOADS:
            try:
                test_url = f"{url}?q={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                if payload in response.text:
                    results.append({"payload": payload, "reflected": True})
                else:
                    results.append({"payload": payload, "reflected": False})
            except:
                results.append({"payload": payload, "error": "Connection failed"})
        
        return {
            "vulnerability": "Cross-Site Scripting (XSS)",
            "target": url,
            "results": results,
            "recommendation": "Implement CSP headers and output encoding"
        }
    
    def test_open_ports(self, host: str, ports: List[int] = None) -> Dict:
        """Basic port scanning with socket"""
        import socket
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return {
            "host": host,
            "open_ports": open_ports,
            "scanned_ports": len(ports),
            "summary": f"Found {len(open_ports)} open ports out of {len(ports)} scanned"
        }
