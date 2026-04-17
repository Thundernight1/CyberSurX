"""Real port scanner with nmap integration"""
import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
import re

class NmapScanner:
    """Nmap wrapper for network scanning"""
    
    @staticmethod
    def check_nmap() -> bool:
        """Check if nmap is installed"""
        try:
            subprocess.run(["nmap", "--version"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    @staticmethod
    def scan_host(
        host: str,
        ports: Optional[str] = None,
        scan_type: str = "tcp_syn",
        timeout: int = 300
    ) -> Dict:
        """
        Scan a single host with nmap
        
        Args:
            host: IP or hostname
            ports: Port range (e.g., "80,443" or "1-65535")
            scan_type: tcp_syn, tcp_connect, udp
            timeout: Scan timeout in seconds
        
        Returns:
            Dict with scan results
        """
        if not NmapScanner.check_nmap():
            return {
                "status": "error",
                "error": "nmap not installed",
                "command": None,
                "output": None
            }
        
        # Build nmap command
        cmd = ["nmap", "-oX", "-"]  # Output XML to stdout
        
        if ports:
            cmd.extend(["-p", ports])
        else:
            cmd.append("-p-")  # All ports
        
        # Scan type
        if scan_type == "tcp_syn":
            cmd.append("-sS")
        elif scan_type == "tcp_connect":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        
        # Service detection
        cmd.append("-sV")
        
        # OS detection (if root)
        cmd.append("-O")
        
        # Quiet mode
        cmd.append("-v")
        
        cmd.append(host)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                # Parse XML output
                findings = NmapScanner._parse_xml(result.stdout)
                return {
                    "status": "success",
                    "host": host,
                    "command": " ".join(cmd),
                    "raw_output": result.stdout,
                    "findings": findings
                }
            else:
                return {
                    "status": "error",
                    "error": result.stderr,
                    "command": " ".join(cmd),
                    "output": result.stdout
                }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "error": f"Scan exceeded {timeout} seconds",
                "command": " ".join(cmd),
                "output": None
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "command": " ".join(cmd),
                "output": None
            }
    
    @staticmethod
    def _parse_xml(xml_output: str) -> List[Dict]:
        """Parse nmap XML output"""
        findings = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall("host"):
                addr = host.find("address")
                if addr is not None:
                    ip = addr.get("addr")
                    
                    # Get ports
                    ports_elem = host.find("ports")
                    if ports_elem is not None:
                        for port in ports_elem.findall("port"):
                            port_id = port.get("portid")
                            protocol = port.get("protocol")
                            
                            state = port.find("state")
                            port_state = state.get("state") if state else "unknown"
                            
                            service = port.find("service")
                            service_name = service.get("name") if service else "unknown"
                            service_version = service.get("version") if service else None
                            
                            findings.append({
                                "ip": ip,
                                "port": int(port_id),
                                "protocol": protocol,
                                "state": port_state,
                                "service": service_name,
                                "version": service_version
                            })
                    
                    # Get OS
                    os_elem = host.find("os")
                    if os_elem is not None:
                        os_match = os_elem.find("osmatch")
                        if os_match is not None:
                            findings.append({
                                "ip": ip,
                                "type": "os_detection",
                                "os": os_match.get("name"),
                                "accuracy": os_match.get("accuracy")
                            })
        except ET.ParseError:
            pass
        
        return findings

if __name__ == "__main__":
    # Test
    scanner = NmapScanner()
    if scanner.check_nmap():
        print("Nmap found, testing scan...")
        result = scanner.scan_host("127.0.0.1", ports="80,443,8000")
        print(json.dumps(result, indent=2))
    else:
        print("Nmap not installed")
