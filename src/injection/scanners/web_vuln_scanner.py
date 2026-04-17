"""Real injection testing module"""
import requests
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

class WebVulnerabilityScanner:
    """Real web vulnerability scanner"""
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "1' AND 1=1--",
        "1' AND 1=2--"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'-><script>alert(1)</script>",
        "javascript:alert(1)"
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberSurX/1.0 Security Scanner"
        })
    
    def test_sql_injection(self, url: str, param: str = None) -> Dict:
        """Test for SQL injection"""
        results = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in self.SQLI_PAYLOADS[:3]:  # Test first 3 payloads
            try:
                # Try GET with payload
                test_url = f"{url}?test={payload}" if "?" not in url else f"{url}&test={payload}"
                
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for SQL errors
                error_indicators = [
                    "sql syntax",
                    "mysql_fetch",
                    "pg_query",
                    "sqlite_query",
                    "ORA-",
                    "syntax error"
                ]
                
                found_error = any(indicator.lower() in response.text.lower() 
                                 for indicator in error_indicators)
                
                results.append({
                    "payload": payload,
                    "url": test_url,
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "potential_vulnerable": found_error
                })
                
            except requests.RequestException as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })
        
        return {
            "vulnerability": "SQL Injection",
            "url": url,
            "tested_payloads": len(results),
            "results": results,
            "recommendation": "Use parameterized queries"
        }
    
    def test_xss(self, url: str) -> Dict:
        """Test for XSS"""
        results = []
        
        for payload in self.XSS_PAYLOADS[:3]:
            try:
                test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&q={payload}"
                
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check if payload reflected
                is_reflected = payload in response.text
                
                results.append({
                    "payload": payload,
                    "url": test_url,
                    "status_code": response.status_code,
                    "reflected": is_reflected,
                    "potential_vulnerable": is_reflected
                })
                
            except requests.RequestException as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })
        
        return {
            "vulnerability": "Cross-Site Scripting (XSS)",
            "url": url,
            "tested_payloads": len(results),
            "results": results,
            "recommendation": "Encode output and validate input"
        }
    
    def test_open_ports(self, host: str, ports: List[int] = None) -> Dict:
        """Test if common web ports are open"""
        import socket
        
        if ports is None:
            ports = [80, 443, 8080, 3000, 5000, 8000, 8443]
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return {
            "host": host,
            "scanned_ports": len(ports),
            "open_ports": open_ports,
            "services": {
                80: "HTTP",
                443: "HTTPS",
                8080: "HTTP Proxy",
                3000: "Node.js/Dev",
                5000: "Flask/Dev",
                8000: "Django/Dev"
            }
        }

if __name__ == "__main__":
    scanner = WebVulnerabilityScanner()
    print(json.dumps(scanner.test_open_ports("127.0.0.1"), indent=2))
