"""
Reconnaissance module for network scanning and host discovery.
"""
import socket
import subprocess
from typing import List, Dict, Optional
from dataclasses import asdict
from datetime import datetime
import xml.etree.ElementTree as ET

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None

from redteam.core.models import Host, Port, ScanResult, Vulnerability
try:
    from redteam.utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(*args, **kwargs):
        return logging.getLogger(__name__)


class ReconnaissanceModule:
    """Handles network reconnaissance and scanning operations."""
    
    def __init__(self, nmap_path: str = "/usr/bin/nmap", timeout: int = 300):
        self.nmap_path = nmap_path
        self.timeout = timeout
        self.logger = setup_logger()
        
        if not NMAP_AVAILABLE:
            self.logger.warning("[yellow]python-nmap not installed. Reconnaissance module will not function.[/yellow]")
            self.scanner = None
        else:
            self.scanner = nmap.PortScanner(nmap_search_path=nmap_path)
    
    def discover_hosts(self, target: str, exclude: str = "") -> List[Host]:
        """
        Discover live hosts in the target network using ping scan.
        
        Args:
            target: Target network range (e.g., 192.168.1.0/24)
            exclude: Hosts to exclude from scan
            
        Returns:
            List of discovered Host objects
        """
        self.logger.info(f"[bold cyan]Starting host discovery on {target}...[/bold cyan]")
        
        hosts = []
        try:
            # Ping scan to discover live hosts
            args = "-sn -PE -PP -PM"
            if exclude:
                args += f" --exclude {exclude}"
            
            self.scanner.scan(hosts=target, arguments=args)
            
            for host_ip in self.scanner.all_hosts():
                if self.scanner[host_ip].state() == 'up':
                    host = Host(ip_address=host_ip)
                    
                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(host_ip)[0]
                        host.hostname = hostname
                    except socket.herror:
                        pass
                    
                    # Get MAC address if available
                    if 'mac' in self.scanner[host_ip]['addresses']:
                        host.mac_address = self.scanner[host_ip]['addresses']['mac']
                    
                    hosts.append(host)
                    self.logger.info(f"[green]Discovered host:[/green] {host_ip} ({host.hostname or 'unknown'})")
            
            self.logger.info(f"[bold green]Host discovery complete. Found {len(hosts)} live hosts.[/bold green]")
            
        except Exception as e:
            self.logger.error(f"[red]Host discovery failed:[/red] {str(e)}")
        
        return hosts
    
    def scan_ports(self, target: str, ports: str = "1-65535", 
                   intensity: int = 4) -> List[Port]:
        """
        Scan ports on a target host.
        
        Args:
            target: Target host IP
            ports: Port range to scan (e.g., "1-65535" or "80,443,8080")
            intensity: Scan intensity (1-5, higher = more thorough)
            
        Returns:
            List of discovered Port objects
        """
        self.logger.info(f"[cyan]Scanning ports on {target}...[/cyan]")
        
        discovered_ports = []
        
        try:
            # Build scan arguments based on intensity
            scan_args = self._build_scan_args(intensity)
            
            self.scanner.scan(hosts=target, ports=ports, arguments=scan_args)
            
            if target in self.scanner.all_hosts():
                for proto in self.scanner[target].all_protocols():
                    ports_list = sorted(self.scanner[target][proto].keys())
                    
                    for port in ports_list:
                        port_data = self.scanner[target][proto][port]
                        port_obj = Port(
                            port_number=port,
                            protocol=proto,
                            state=port_data.get('state', 'unknown'),
                            service=port_data.get('name', ''),
                            version=port_data.get('version', ''),
                            banner=port_data.get('product', '') + " " + port_data.get('version', '')
                        )
                        discovered_ports.append(port_obj)
                        
                        if port_obj.state == 'open':
                            self.logger.info(
                                f"[green]Port {port}/{proto}:[/green] {port_obj.service} "
                                f"({port_obj.version})"
                            )
            
        except Exception as e:
            self.logger.error(f"[red]Port scan failed for {target}:[/red] {str(e)}")
        
        return discovered_ports
    
    def detect_os(self, target: str) -> str:
        """
        Attempt to detect the operating system of the target.
        
        Args:
            target: Target host IP
            
        Returns:
            OS guess string
        """
        self.logger.info(f"[cyan]Attempting OS detection on {target}...[/cyan]")
        
        os_guess = "Unknown"
        
        try:
            # OS detection scan
            self.scanner.scan(hosts=target, arguments="-O --osscan-guess")
            
            if target in self.scanner.all_hosts() and 'osmatch' in self.scanner[target]:
                os_matches = self.scanner[target]['osmatch']
                if os_matches:
                    os_guess = os_matches[0].get('name', 'Unknown')
                    accuracy = os_matches[0].get('accuracy', '0')
                    self.logger.info(f"[green]OS Detection:[/green] {os_guess} (accuracy: {accuracy}%)")
        
        except Exception as e:
            self.logger.warning(f"[yellow]OS detection failed for {target}:[/yellow] {str(e)}")
        
        return os_guess
    
    def run_vuln_scan(self, target: str, ports: str = "") -> List[Dict]:
        """
        Run vulnerability scanning scripts against target.
        
        Args:
            target: Target host IP
            ports: Specific ports to scan (optional)
            
        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"[cyan]Running vulnerability scan on {target}...[/cyan]")
        
        vulnerabilities = []
        
        try:
            # Use NSE vulnerability scripts
            port_arg = f"-p {ports}" if ports else ""
            args = f"--script vuln {port_arg}"
            
            self.scanner.scan(hosts=target, arguments=args)
            
            if target in self.scanner.all_hosts():
                # Parse script output for vulnerabilities
                if 'hostscript' in self.scanner[target]:
                    for script in self.scanner[target]['hostscript']:
                        vuln = {
                            'id': script.get('id', ''),
                            'output': script.get('output', ''),
                            'type': 'host'
                        }
                        vulnerabilities.append(vuln)
                
                # Check port-specific scripts
                for proto in self.scanner[target].all_protocols():
                    for port in self.scanner[target][proto].keys():
                        if 'script' in self.scanner[target][proto][port]:
                            for script_name, output in self.scanner[target][proto][port]['script'].items():
                                vuln = {
                                    'id': script_name,
                                    'output': output,
                                    'port': port,
                                    'type': 'port'
                                }
                                vulnerabilities.append(vuln)
            
            self.logger.info(f"[green]Vulnerability scan complete. Found {len(vulnerabilities)} potential issues.[/green]")
            
        except Exception as e:
            self.logger.error(f"[red]Vulnerability scan failed:[/red] {str(e)}")
        
        return vulnerabilities
    
    def comprehensive_scan(self, target_hosts: str, ports: str = "1-65535",
                          intensity: int = 4, exclude: str = "") -> ScanResult:
        """
        Run a comprehensive scan including host discovery, port scanning,
        OS detection, and vulnerability scanning.
        
        Args:
            target_hosts: Target network range or hosts
            ports: Port range to scan
            intensity: Scan intensity (1-5)
            exclude: Hosts to exclude
            
        Returns:
            ScanResult object with all findings
        """
        self.logger.info("[bold cyan]=== Starting Comprehensive Network Scan ===[/bold cyan]")
        
        scan_result = ScanResult(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            target_hosts=target_hosts.split(','),
            start_time=datetime.now()
        )
        
        # Step 1: Host Discovery
        discovered_hosts = self.discover_hosts(target_hosts, exclude)
        
        # Step 2: Detailed scanning for each host
        for host in discovered_hosts:
            self.logger.info(f"[bold cyan]Scanning host {host.ip_address}...[/bold cyan]")
            
            # Port scan
            host.ports = self.scan_ports(host.ip_address, ports, intensity)
            
            # OS detection
            host.os_guess = self.detect_os(host.ip_address)
            
            # Vulnerability scan
            open_ports = ",".join([str(p.port_number) for p in host.ports if p.state == 'open'])
            if open_ports:
                vuln_results = self.run_vuln_scan(host.ip_address, open_ports)
                # Convert to Vulnerability objects
                for v in vuln_results:
                    vulnerability = Vulnerability(
                        id=v.get('id', ''),
                        name=v.get('id', ''),
                        description=v.get('output', ''),
                        affected_host=host.ip_address,
                        affected_port=v.get('port', 0)
                    )
                    host.vulnerabilities.append(vulnerability)
                    scan_result.vulnerabilities_found.append(vulnerability)
            
            scan_result.hosts_discovered.append(host)
        
        # Calculate scan statistics
        total_ports = sum(len(h.ports) for h in scan_result.hosts_discovered)
        open_ports = sum(len([p for p in h.ports if p.state == 'open']) for h in scan_result.hosts_discovered)
        
        scan_result.scan_stats = {
            'hosts_discovered': len(scan_result.hosts_discovered),
            'total_ports_scanned': total_ports,
            'open_ports_found': open_ports,
            'vulnerabilities_found': len(scan_result.vulnerabilities_found),
            'scan_duration': (datetime.now() - scan_result.start_time).total_seconds()
        }
        
        scan_result.end_time = datetime.now()
        
        self.logger.info("[bold green]=== Comprehensive Scan Complete ===[/bold green]")
        self.logger.info(f"[green]Hosts discovered:[/green] {scan_result.scan_stats['hosts_discovered']}")
        self.logger.info(f"[green]Open ports found:[/green] {scan_result.scan_stats['open_ports_found']}")
        self.logger.info(f"[green]Vulnerabilities found:[/green] {scan_result.scan_stats['vulnerabilities_found']}")
        
        return scan_result
    
    def _build_scan_args(self, intensity: int) -> str:
        """Build nmap scan arguments based on intensity level."""
        args_map = {
            1: "-sS -T2",           # Stealthy, slow
            2: "-sS -sV -T3",       # Standard scan
            3: "-sS -sV -A -T4",    # Aggressive
            4: "-sS -sV -A -O --script=default,discovery -T4",  # Comprehensive
            5: "-sS -sV -A -O --script=default,discovery,vuln -T5 -p-"  # Intensive
        }
        return args_map.get(min(max(intensity, 1), 5), args_map[4])
    
    def export_to_xml(self, scan_result: ScanResult, output_file: str):
        """Export scan results to XML format."""
        root = ET.Element("scan_result")
        root.set("scan_id", scan_result.scan_id)
        root.set("start_time", scan_result.start_time.isoformat())
        if scan_result.end_time:
            root.set("end_time", scan_result.end_time.isoformat())
        
        hosts_elem = ET.SubElement(root, "hosts")
        for host in scan_result.hosts_discovered:
            host_elem = ET.SubElement(hosts_elem, "host")
            host_elem.set("ip", host.ip_address)
            host_elem.set("hostname", host.hostname)
            host_elem.set("os", host.os_guess)
            
            ports_elem = ET.SubElement(host_elem, "ports")
            for port in host.ports:
                port_elem = ET.SubElement(ports_elem, "port")
                port_elem.set("number", str(port.port_number))
                port_elem.set("protocol", port.protocol)
                port_elem.set("state", port.state)
                port_elem.set("service", port.service)
                port_elem.set("version", port.version)
        
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        self.logger.info(f"[green]Scan results exported to:[/green] {output_file}")



