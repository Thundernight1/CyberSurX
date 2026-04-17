#!/usr/bin/env python3
"""
CyberSurX Suite - Ana Orkestratör

Pipeline:
1. Target Definition (hedef tanım)
2. Software Pentest (yazılım testi)
   - Injection tests
   - Reconnaissance
   - Vulnerability analysis
3. Physical Device Integration (opsiyonel)
   - WiFi Pineapple
   - Flipper Zero
   - SharkTap
4. AI Attack Planning (Claude API)
5. Exploitation (opsiyonel, HITL onaylı)
6. Reporting (HTML/JSON/PDF)

Usage:
    python -m src.redteam_master --target 192.168.1.0/24
    python -m src.redteam_master --target 10.0.0.1 --devices pineapple,flipper
    python -m src.redteam_master --config config.yaml --full-pipeline
"""

import asyncio
import argparse
import json
import logging
import signal
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Core modüller
from core.base_agent import BaseAgent, SharedState, TaskResult, AgentLayer
from core.llm_client import get_llm_client, OllamaClient
from core.config.settings import TEAM_ROSTER, AgentProfile, REPORT_DIR, LOG_DIR
from core.hitl import HITLApproval, ApprovalRequest, RiskLevel
from core.hitl_config import HITLConfig

# Injection modülleri (AIG-AgentTeam)
try:
    from injection.attacks.attack_engine import AttackEngine, ScanSession, AttackResult
    from injection.scanners.base_scanner import BaseScanner
    INJECTION_AVAILABLE = True
except ImportError:
    INJECTION_AVAILABLE = False

# RedTeam modülleri
try:
    from redteam.modules.reconnaissance import ReconnaissanceModule
    from redteam.modules.vulnerability_analyzer import VulnerabilityAnalyzer
    from redteam.modules.attack_planner import AttackPlanner
    from redteam.modules.exploit_engine import ExploitEngine
    from redteam.modules.post_exploitation import PostExploitationModule
    from redteam.modules.report_generator import ReportGenerator
    from redteam.core.config import Config as RedTeamConfig
    from redteam.core.models import ScanResult
    REDTEAM_AVAILABLE = True
except ImportError:
    REDTEAM_AVAILABLE = False

# Physical device modülleri
try:
    from devices.wifi_pineapple import WiFiPineapple
    from devices.flipper_zero import FlipperZero
    from devices.shark_tap import SharkTap
    DEVICES_AVAILABLE = True
except ImportError:
    DEVICES_AVAILABLE = False

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'redteam_master.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('redteam_master')


class RedTeamPhysicalSuite:
    """
    CyberSurX Suite - Ana Orkestratör
    
    Tüm CyberSurX operasyonlarını koordine eden ana sınıf.
    Yazılım pentest, injection testler ve fiziksel cihaz entegrasyonunu birleştirir.
    """

    def __init__(self, target: str, config_file: Optional[str] = None):
        """
        Initialize the RedTeam Physical Suite.
        
        Args:
            target: Target network or host (e.g., 192.168.1.0/24, 10.0.0.1)
            config_file: Optional configuration file path
        """
        self.target = target
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        
        # Shared state for agent coordination
        self.shared_state = SharedState(
            session_id=self.session_id,
            target=target
        )
        
        # Results storage
        self.results = {
            'injection_tests': [],
            'reconnaissance': None,
            'vulnerability_analysis': [],
            'attack_plan': None,
            'physical_devices': {},
            'exploitation': [],
            'hitl_decisions': [],
        }
        
        # Console for rich output
        self.console = Console()
        
        # Load configuration
        self.config = self._load_config(config_file)
        
        # Initialize HITL approval system
        self.hitl_config = self._load_hitl_config()
        self.hitl = HITLApproval(
            enabled=self.hitl_config.enabled,
            auto_approve_low_risk=self.hitl_config.auto_approve_low_risk,
            timeout=self.hitl_config.timeout,
            notification_email=self.hitl_config.notification_email,
            log_dir=Path(self.hitl_config.log_dir),
            console=self.console
        )
        
        # LLM Client
        self.llm_client = get_llm_client()
        
        # Agent instances
        self.agents: Dict[str, BaseAgent] = {}
        
        # Initialize agents from team roster
        self._init_agents()
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"RedTeam Physical Suite initialized - Session: {self.session_id}")
        logger.info(f"Target: {target}")

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults."""
        config = {
            'scan_intensity': 4,
            'ports': '1-65535',
            'enable_exploitation': False,
            'enable_physical_devices': False,
            'hitl_enabled': True,
            'output_dir': str(REPORT_DIR),
            'report_formats': ['html', 'json'],
            'anthropic_api_key': None,
        }
        
        if config_file and Path(config_file).exists():
            import yaml
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                config.update(file_config)
        
        return config

    def _load_hitl_config(self) -> HITLConfig:
        """Load HITL configuration from config file or use defaults."""
        hitl_config = HITLConfig()
        
        # Config dosyasından HITL ayarlarını oku
        if 'hitl' in self.config:
            hitl_dict = self.config.get('hitl', {})
            hitl_config = HITLConfig.from_dict(hitl_dict)
        
        return hitl_config

    def _init_agents(self):
        """Initialize all agents from team roster."""
        for agent_id, profile in TEAM_ROSTER.items():
            layer = AgentLayer(profile.layer.upper()) if hasattr(AgentLayer, profile.layer.upper()) else AgentLayer.SUPPORT
            
            self.agents[agent_id] = BaseAgent(
                agent_id=agent_id,
                name=profile.name,
                role=profile.role,
                layer=layer,
                model=profile.model,
                description=profile.description,
                tools=profile.tools,
            )
        
        logger.info(f"Initialized {len(self.agents)} agents")

    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        self.console.print("\n[yellow]Received interrupt signal. Shutting down gracefully...[/yellow]")
        self._generate_emergency_report()
        sys.exit(0)

    def _generate_emergency_report(self):
        """Generate emergency report on interrupt."""
        self.console.print("[cyan]Generating emergency report...[/cyan]")
        self.generate_report(format='json')

    def run_injection_tests(self) -> List[AttackResult]:
        """
        Run AI Injection tests using AIG-AgentTeam modules.
        
        Returns:
            List of attack results
        """
        if not INJECTION_AVAILABLE:
            self.console.print("[yellow]Injection modules not available, skipping...[/yellow]")
            return []
        
        self.console.print("\n[bold blue]▶ Running Injection Tests[/bold blue]")
        
        results = []
        
        try:
            # Initialize attack engine
            engine = AttackEngine(
                ollama_client=self.llm_client,
                target_url=self.target
            )
            
            # Run async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            session = loop.run_until_complete(engine.run_full_scan(self.target))
            loop.close()
            
            results = session.findings
            self.results['injection_tests'] = results
            
            # Update shared state
            vuln_count = len([r for r in results if r.is_vulnerable])
            self.shared_state.vulnerabilities.extend([
                {
                    'type': r.vulnerability_type,
                    'confidence': r.confidence,
                    'evidence': r.evidence,
                    'owasp': r.owasp_mapping
                }
                for r in results if r.is_vulnerable
            ])
            
            self.console.print(f"[green]Injection tests complete: {len(results)} probes, {vuln_count} vulnerabilities[/green]")
            
        except Exception as e:
            logger.error(f"Injection tests failed: {e}")
            self.console.print(f"[red]Injection tests failed: {e}[/red]")
        
        return results

    def run_reconnaissance(self) -> Optional[ScanResult]:
        """
        Run network reconnaissance using Nmap.
        
        Returns:
            ScanResult with discovered hosts and ports
        """
        if not REDTEAM_AVAILABLE:
            self.console.print("[yellow]RedTeam modules not available, skipping...[/yellow]")
            return None
        
        self.console.print("\n[bold blue]▶ Running Reconnaissance[/bold blue]")
        
        try:
            # Initialize recon module
            recon = ReconnaissanceModule(
                nmap_path=self.config.get('nmap_path', '/usr/bin/nmap'),
                timeout=self.config.get('scan_timeout', 300)
            )
            
            # Run comprehensive scan
            scan_result = recon.comprehensive_scan(
                target_hosts=self.target,
                ports=self.config.get('ports', '1-65535'),
                intensity=self.config.get('scan_intensity', 4)
            )
            
            self.results['reconnaissance'] = scan_result
            
            # Update shared state
            self.shared_state.hosts = [
                {'ip': h.ip_address, 'hostname': h.hostname, 'os': h.os_guess}
                for h in scan_result.hosts_discovered
            ]
            
            total_ports = sum(len(h.ports) for h in scan_result.hosts_discovered)
            open_ports = sum(len([p for p in h.ports if p.state == 'open']) for h in scan_result.hosts_discovered)
            
            self.console.print(f"[green]Reconnaissance complete: {len(scan_result.hosts_discovered)} hosts, {open_ports} open ports[/green]")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            self.console.print(f"[red]Reconnaissance failed: {e}[/red]")
            return None

    def run_vulnerability_analysis(self) -> List[Dict]:
        """
        Run CVE lookup and vulnerability analysis.
        
        Returns:
            List of vulnerabilities found
        """
        if not REDTEAM_AVAILABLE:
            self.console.print("[yellow]RedTeam modules not available, skipping...[/yellow]")
            return []
        
        if not self.results['reconnaissance']:
            self.console.print("[yellow]No reconnaissance data available, skipping vulnerability analysis...[/yellow]")
            return []
        
        self.console.print("\n[bold blue]▶ Running Vulnerability Analysis[/bold blue]")
        
        try:
            # Initialize analyzer
            analyzer = VulnerabilityAnalyzer()
            
            # Analyze scan results
            vulnerabilities = analyzer.analyze_scan_results(self.results['reconnaissance'])
            
            self.results['vulnerability_analysis'] = vulnerabilities
            
            # Update shared state
            self.shared_state.vulnerabilities.extend([
                {
                    'id': v.id,
                    'name': v.name,
                    'severity': v.severity.value,
                    'cvss': v.cvss_score,
                    'host': v.affected_host,
                    'port': v.affected_port
                }
                for v in vulnerabilities
            ])
            
            severities = {}
            for v in vulnerabilities:
                sev = v.severity.value
                severities[sev] = severities.get(sev, 0) + 1
            
            self.console.print(f"[green]Vulnerability analysis complete: {len(vulnerabilities)} vulnerabilities[/green]")
            for sev, count in severities.items():
                self.console.print(f"  {sev}: {count}")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            self.console.print(f"[red]Vulnerability analysis failed: {e}[/red]")
            return []

    def run_ai_attack_planning(self) -> Optional[Dict]:
        """
        Run AI-powered attack planning using Claude/Anthropic API.
        
        Returns:
            Attack plan dict or None
        """
        self.console.print("\n[bold blue]▶ Running AI Attack Planning[/bold blue]")
        
        api_key = self.config.get('anthropic_api_key')
        if not api_key:
            self.console.print("[yellow]No Anthropic API key configured, skipping AI attack planning...[/yellow]")
            return None
        
        try:
            # Use decision layer agent for attack planning
            attack_agent = self.agents.get('attack_path')
            if not attack_agent:
                self.console.print("[yellow]Attack path agent not available[/yellow]")
                return None
            
            # Prepare context
            context = {
                'target': self.target,
                'hosts': self.shared_state.hosts,
                'vulnerabilities': self.shared_state.vulnerabilities,
                'attack_opportunities': self.shared_state.attack_opportunities
            }
            
            # Run attack planning task
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                attack_agent.execute_task(
                    task="Generate attack paths based on discovered vulnerabilities and exposed services. Prioritize by likelihood of success and potential impact.",
                    shared_state=self.shared_state
                )
            )
            loop.close()
            
            self.results['attack_plan'] = result.output if result.status == 'completed' else None
            
            self.console.print("[green]AI attack planning complete[/green]")
            
            return self.results['attack_plan']
            
        except Exception as e:
            logger.error(f"AI attack planning failed: {e}")
            self.console.print(f"[red]AI attack planning failed: {e}[/red]")
            return None

    def run_physical_devices(self, devices: List[str] = None) -> Dict[str, Any]:
        """
        Run physical device integration tests with HITL approval.
        
        Args:
            devices: List of devices to use (e.g., ['pineapple', 'flipper', 'sharktap'])
        
        Returns:
            Dictionary of device results
        """
        if not devices:
            return {}
        
        if not DEVICES_AVAILABLE:
            self.console.print("[yellow]Physical device modules not available, skipping...[/yellow]")
            return {}
        
        # HITL Onay iste
        if self.hitl_config.enabled:
            self.console.print("\n[bold yellow]⚠ PHYSICAL DEVICE USAGE REQUIRES HITL APPROVAL[/bold yellow]")
            
            for device in devices:
                risk_level = RiskLevel.HIGH.value if device in ['pineapple', 'sharktap'] else RiskLevel.MEDIUM.value
                
                approval_request = self.hitl.request_approval(
                    operation_type="physical_device",
                    target=f"{device} on {self.target}",
                    risk_level=risk_level,
                    details={
                        "device_type": device,
                        "target_network": self.target,
                        "session_id": self.session_id,
                        "description": f"Physical {device} device integration and testing"
                    }
                )
                
                # Onay bekle
                result = self.hitl.wait_for_response(approval_request, timeout=self.hitl_config.timeout)
                
                # Sonucu kaydet
                self.results['hitl_decisions'].append(result.to_dict())
                
                if result.status != "approved":
                    self.console.print(f"[red]Physical device {device} approval {result.status}. Skipping...[/red]")
                    return {}
        
        self.console.print(f"\n[bold blue]▶ Running Physical Device Integration: {', '.join(devices)}[/bold blue]")
        
        device_results = {}
        
        try:
            # WiFi Pineapple
            if 'pineapple' in devices:
                self.console.print("[cyan]Connecting to WiFi Pineapple...[/cyan]")
                pineapple = WiFiPineapple()
                device_results['pineapple'] = pineapple.scan_networks(self.target)
            
            # Flipper Zero
            if 'flipper' in devices:
                self.console.print("[cyan]Connecting to Flipper Zero...[/cyan]")
                flipper = FlipperZero()
                device_results['flipper'] = flipper.enumerate_devices()
            
            # SharkTap
            if 'sharktap' in devices:
                self.console.print("[cyan]Connecting to SharkTap...[/cyan]")
                sharktap = SharkTap()
                device_results['sharktap'] = sharktap.capture_traffic(duration=60)
            
            self.results['physical_devices'] = device_results
            self.console.print("[green]Physical device integration complete[/green]")
            
        except Exception as e:
            logger.error(f"Physical device integration failed: {e}")
            self.console.print(f"[red]Physical device integration failed: {e}[/red]")
        
        return device_results

    def run_exploitation(self) -> List[Dict]:
        """
        Run exploitation phase (requires HITL approval).
        
        Returns:
            List of exploit results
        """
        if not self.config.get('enable_exploitation', False):
            self.console.print("[yellow]Exploitation disabled in configuration[/yellow]")
            return []
        
        if not REDTEAM_AVAILABLE:
            self.console.print("[yellow]RedTeam modules not available, skipping...[/yellow]")
            return []
        
        # HITL Approval - Enhanced
        if self.hitl_config.enabled:
            self.console.print("\n[bold yellow]⚠ EXPLOITATION REQUIRES HITL APPROVAL[/bold yellow]")
            
            # Risk seviyesini belirle
            critical_count = len([v for v in self.results.get('vulnerability_analysis', []) 
                               if v.severity.value == 'Critical'])
            high_count = len([v for v in self.results.get('vulnerability_analysis', []) 
                             if v.severity.value == 'High'])
            
            risk_level = RiskLevel.CRITICAL.value if critical_count > 0 else RiskLevel.HIGH.value
            
            # Onay isteği oluştur
            approval_request = self.hitl.request_approval(
                operation_type="exploit",
                target=self.target,
                risk_level=risk_level,
                details={
                    "session_id": self.session_id,
                    "critical_vulnerabilities": critical_count,
                    "high_vulnerabilities": high_count,
                    "total_vulnerabilities": len(self.results.get('vulnerability_analysis', [])),
                    "planned_exploits": [
                        f"{vuln.id} on {vuln.affected_host}:{vuln.affected_port}"
                        for vuln in self.results.get('vulnerability_analysis', [])[:5]
                        if vuln.exploit_available
                    ],
                    "description": "Exploit execution against discovered vulnerabilities"
                }
            )
            
            # Onay bekle
            result = self.hitl.wait_for_response(approval_request, timeout=self.hitl_config.timeout)
            
            # Sonucu kaydet
            self.results['hitl_decisions'].append(result.to_dict())
            
            if result.status != "approved":
                self.console.print(f"[yellow]Exploitation approval {result.status}. Cancelling exploitation phase.[/yellow]")
                if result.rejection_reason:
                    self.console.print(f"[dim]Reason: {result.rejection_reason}[/dim]")
                return []
        
        self.console.print("\n[bold blue]▶ Running Exploitation[/bold blue]")
        
        try:
            # Initialize exploit engine
            exploit_config = RedTeamConfig()
            exploit_config.enable_exploitation = True
            
            engine = ExploitEngine(exploit_config)
            
            # Execute exploits
            exploit_results = []
            
            for vuln in self.results.get('vulnerability_analysis', []):
                if vuln.exploit_available and len(exploit_results) < 3:  # Limit for safety
                    result = engine.try_exploit(vuln)
                    exploit_results.append(result)
            
            self.results['exploitation'] = exploit_results
            
            successful = len([r for r in exploit_results if r.get('success')])
            self.console.print(f"[green]Exploitation complete: {successful}/{len(exploit_results)} successful[/green]")
            
            return exploit_results
            
        except Exception as e:
            logger.error(f"Exploitation failed: {e}")
            self.console.print(f"[red]Exploitation failed: {e}[/red]")
            return []

    def generate_report(self, format: str = 'html') -> str:
        """
        Generate final report in specified format.
        
        Args:
            format: Report format ('html', 'json', 'pdf', 'all')
        
        Returns:
            Path to generated report
        """
        self.console.print(f"\n[bold blue]▶ Generating Report ({format})[/bold blue]")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_paths = {}
        
        # JSON Report (always generated)
        json_path = Path(self.config['output_dir']) / f"report_{self.session_id}_{timestamp}.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_data = {
            'session_id': self.session_id,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'injection_tests': [
                {
                    'type': r.vulnerability_type,
                    'vulnerable': r.is_vulnerable,
                    'confidence': r.confidence,
                    'owasp': r.owasp_mapping
                }
                for r in self.results.get('injection_tests', [])
            ],
            'reconnaissance': self._serialize_scan_result(self.results.get('reconnaissance')),
            'vulnerabilities': [
                {
                    'id': v.id,
                    'name': v.name,
                    'severity': v.severity.value,
                    'cvss': v.cvss_score,
                    'host': v.affected_host,
                    'port': v.affected_port
                }
                for v in self.results.get('vulnerability_analysis', [])
            ],
            'attack_plan': self.results.get('attack_plan'),
            'physical_devices': self.results.get('physical_devices', {}),
            'exploitation': self.results.get('exploitation', []),
            'hitl_decisions': self.results.get('hitl_decisions', []),
            'shared_state': self.shared_state.to_dict()
        }
        
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        report_paths['json'] = str(json_path)
        self.console.print(f"[green]JSON report: {json_path}[/green]")
        
        # HTML Report
        if format in ['html', 'all'] and REDTEAM_AVAILABLE:
            try:
                report_config = RedTeamConfig()
                report_config.report_output_dir = self.config['output_dir']
                report_config.report_format = 'html'
                
                generator = ReportGenerator(report_config)
                
                if self.results.get('reconnaissance'):
                    html_files = generator.generate_reports(self.results['reconnaissance'])
                    report_paths['html'] = html_files.get('html', '')
                    self.console.print(f"[green]HTML report: {html_files.get('html')}[/green]")
            except Exception as e:
                logger.error(f"HTML report generation failed: {e}")
        
        return report_paths.get(format, str(json_path))

    def _serialize_scan_result(self, scan_result: Optional[ScanResult]) -> Optional[Dict]:
        """Serialize ScanResult to dictionary."""
        if not scan_result:
            return None
        
        return {
            'scan_id': scan_result.scan_id,
            'hosts_discovered': len(scan_result.hosts_discovered),
            'vulnerabilities_found': len(scan_result.vulnerabilities_found),
            'stats': scan_result.scan_stats
        }

    def run_full_pipeline(self, devices: List[str] = None):
        """
        Run the complete CyberSurX pipeline.
        
        Args:
            devices: Optional list of physical devices to use
        """
        self._print_banner()
        
        self.console.print(f"\n[bold cyan]Target: {self.target}[/bold cyan]")
        self.console.print(f"[cyan]Session ID: {self.session_id}[/cyan]")
        self.console.print(f"[cyan]Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            # Phase 1: Injection Tests
            task = progress.add_task("[cyan]Running injection tests...", total=None)
            self.run_injection_tests()
            progress.remove_task(task)
            
            # Phase 2: Reconnaissance
            task = progress.add_task("[cyan]Running reconnaissance...", total=None)
            self.run_reconnaissance()
            progress.remove_task(task)
            
            # Phase 3: Vulnerability Analysis
            task = progress.add_task("[cyan]Running vulnerability analysis...", total=None)
            self.run_vulnerability_analysis()
            progress.remove_task(task)
            
            # Phase 4: Physical Device Integration
            if devices:
                task = progress.add_task("[cyan]Running physical device integration...", total=None)
                self.run_physical_devices(devices)
                progress.remove_task(task)
            
            # Phase 5: AI Attack Planning
            task = progress.add_task("[cyan]Running AI attack planning...", total=None)
            self.run_ai_attack_planning()
            progress.remove_task(task)
            
            # Phase 6: Exploitation (HITL approved)
            if self.config.get('enable_exploitation'):
                task = progress.add_task("[cyan]Running exploitation...", total=None)
                self.run_exploitation()
                progress.remove_task(task)
            
            # Phase 7: Report Generation
            task = progress.add_task("[cyan]Generating reports...", total=None)
            self.generate_report(format='all')
            progress.remove_task(task)
        
        # Summary
        self._print_summary()

    def _print_banner(self):
        """Print the application banner."""
        banner_text = Text("""
    ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
    ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
    ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
    ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
    ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
        """, style="bold red")
        
        subtitle = Text("\n    CyberSurX Suite\n", style="cyan")
        warning = Text("    ⚠ FOR AUTHORIZED TESTING ONLY ⚠\n", style="bold yellow")
        
        self.console.print(Panel(
            banner_text + subtitle + warning,
            border_style="red"
        ))

    def _print_summary(self):
        """Print final summary of the assessment."""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        self.console.print("\n" + "="*60)
        self.console.print("[bold green]RED TEAM ASSESSMENT COMPLETE[/bold green]")
        self.console.print("="*60)
        
        # Injection Tests Summary
        injection_count = len([r for r in self.results.get('injection_tests', []) if r.is_vulnerable])
        self.console.print(f"\n[bold]Injection Tests:[/bold]")
        self.console.print(f"  Vulnerabilities Found: {injection_count}")
        
        # Reconnaissance Summary
        recon = self.results.get('reconnaissance')
        if recon:
            self.console.print(f"\n[bold]Reconnaissance:[/bold]")
            self.console.print(f"  Hosts: {len(recon.hosts_discovered)}")
            open_ports = sum(len([p for p in h.ports if p.state == 'open']) for h in recon.hosts_discovered)
            self.console.print(f"  Open Ports: {open_ports}")
        
        # Vulnerability Analysis Summary
        vulns = self.results.get('vulnerability_analysis', [])
        if vulns:
            self.console.print(f"\n[bold]Vulnerability Analysis:[/bold]")
            self.console.print(f"  Total CVEs: {len(vulns)}")
            critical = len([v for v in vulns if v.severity.value == 'Critical'])
            high = len([v for v in vulns if v.severity.value == 'High'])
            self.console.print(f"  Critical: {critical}, High: {high}")
        
        # Physical Devices Summary
        devices = self.results.get('physical_devices', {})
        if devices:
            self.console.print(f"\n[bold]Physical Device Results:[/bold]")
            for device, result in devices.items():
                self.console.print(f"  {device}: {len(result) if isinstance(result, list) else 'Active'}")
        
        # Exploitation Summary
        exploits = self.results.get('exploitation', [])
        if exploits:
            successful = len([e for e in exploits if e.get('success')])
            self.console.print(f"\n[bold]Exploitation:[/bold]")
            self.console.print(f"  Successful: {successful}/{len(exploits)}")
        
        # HITL Decisions Summary
        hitl_decisions = self.results.get('hitl_decisions', [])
        if hitl_decisions:
            self.console.print(f"\n[bold]HITL Approval Decisions:[/bold]")
            approved = len([d for d in hitl_decisions if d.get('status') == 'approved'])
            rejected = len([d for d in hitl_decisions if d.get('status') == 'rejected'])
            timed_out = len([d for d in hitl_decisions if d.get('status') == 'timeout'])
            self.console.print(f"  Approved: {approved}, Rejected: {rejected}, Timed Out: {timed_out}")
        
        self.console.print(f"\n[bold]Duration:[/bold] {duration:.1f}s")
        self.console.print(f"[bold]Session ID:[/bold] {self.session_id}")
        self.console.print("="*60)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="CyberSurX Suite - Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline on a network
  python -m src.redteam_master --target 192.168.1.0/24 --full-pipeline
  
  # With physical devices
  python -m src.redteam_master --target 10.0.0.1 --devices pineapple,flipper
  
  # Specific phases only
  python -m src.redteam_master --target 192.168.1.1 --injection-only
  
  # With exploitation (requires HITL approval)
  python -m src.redteam_master --target 192.168.1.1 --enable-exploitation
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target host(s) to scan (e.g., 192.168.1.1, 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file (YAML)'
    )
    
    parser.add_argument(
        '--devices', '-d',
        help='Physical devices to use: pineapple,flipper,sharktap (comma-separated)'
    )
    
    parser.add_argument(
        '--full-pipeline', '-f',
        action='store_true',
        help='Run complete pipeline including all phases'
    )
    
    parser.add_argument(
        '--injection-only',
        action='store_true',
        help='Run only injection tests'
    )
    
    parser.add_argument(
        '--recon-only',
        action='store_true',
        help='Run only reconnaissance'
    )
    
    parser.add_argument(
        '--enable-exploitation', '-e',
        action='store_true',
        help='Enable exploitation phase (requires HITL approval)'
    )
    
    parser.add_argument(
        '--no-hitl',
        action='store_true',
        help='Skip HITL approval for exploitation (DANGEROUS)'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='./reports',
        help='Output directory for reports'
    )
    
    parser.add_argument(
        '--format',
        default='html',
        choices=['html', 'json', 'pdf', 'all'],
        help='Report format'
    )
    
    parser.add_argument(
        '--intensity', '-i',
        type=int,
        choices=range(1, 6),
        default=4,
        help='Scan intensity (1-5)'
    )
    
    parser.add_argument(
        '--ports', '-p',
        default='1-65535',
        help='Port range to scan'
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create orchestrator
    suite = RedTeamPhysicalSuite(
        target=args.target,
        config_file=args.config
    )
    
    # Update config from args
    suite.config['scan_intensity'] = args.intensity
    suite.config['ports'] = args.ports
    suite.config['output_dir'] = args.output
    suite.config['enable_exploitation'] = args.enable_exploitation
    
    # HITL override from CLI - disable HITL if --no-hitl is passed
    if args.no_hitl:
        suite.config['hitl_enabled'] = False
        suite.hitl_config.enabled = False
        suite.hitl.enabled = False
        logger.warning("[HITL] Disabled via --no-hitl flag (DANGEROUS)")
    
    try:
        # Parse devices
        devices = None
        if args.devices:
            devices = [d.strip() for d in args.devices.split(',')]
        
        # Run based on mode
        if args.injection_only:
            suite.run_injection_tests()
            suite.generate_report(args.format)
        elif args.recon_only:
            suite.run_reconnaissance()
            suite.generate_report(args.format)
        elif args.full_pipeline:
            suite.run_full_pipeline(devices=devices)
        else:
            # Default: run software pentest phases
            suite.run_injection_tests()
            suite.run_reconnaissance()
            suite.run_vulnerability_analysis()
            suite.generate_report(args.format)
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        suite._generate_emergency_report()
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
