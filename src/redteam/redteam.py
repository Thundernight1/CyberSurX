#!/usr/bin/env python3
"""
RedTeam Automation Tool - Main CLI Entry Point

An autonomous penetration testing framework that automates the entire ethical
hacking pipeline from reconnaissance to report generation.

Usage:
    python redteam.py --target 192.168.1.0/24
    python redteam.py --target 10.0.0.1 --ports 80,443,8080 --intensity 3
    python redteam.py --config /path/to/.env
"""

import sys
import argparse
import signal
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from redteam.core.config import Config
from redteam.core.models import ScanResult
from redteam.modules.reconnaissance import ReconnaissanceModule
from redteam.modules.vulnerability_analyzer import VulnerabilityAnalyzer
from redteam.modules.attack_planner import AttackPlanner
from redteam.modules.exploit_engine import ExploitEngine
from redteam.modules.post_exploitation import PostExploitationModule
from redteam.modules.report_generator import ReportGenerator
try:
    from redteam.utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(*args, **kwargs):
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger


class RedTeamTool:
    """Main orchestrator for the RedTeam Automation Tool."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger(config.log_level, config.log_file)
        self.console = Console()
        self.scan_result: Optional[ScanResult] = None
        
        # Initialize modules
        self.recon_module = ReconnaissanceModule(
            nmap_path=config.nmap_path,
            timeout=config.scan_timeout
        )
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.attack_planner: Optional[AttackPlanner] = None
        self.exploit_engine: Optional[ExploitEngine] = None
        self.post_exploit: Optional[PostExploitationModule] = None
        self.report_generator = ReportGenerator(config)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        self.logger.warning("\n[yellow]Received interrupt signal. Shutting down gracefully...[/yellow]")
        if self.scan_result:
            self._generate_reports()
        sys.exit(0)
    
    def run_full_assessment(self) -> ScanResult:
        """
        Run the complete penetration testing pipeline.
        
        Returns:
            Complete ScanResult with all findings
        """
        self._print_banner()
        
        # Validate configuration
        errors = self.config.validate()
        if errors:
            self.logger.error("[red]Configuration errors:[/red]")
            for error in errors:
                self.logger.error(f"  - {error}")
            sys.exit(1)
        
        self.logger.info("[bold cyan]=== Starting Full Penetration Test ===[/bold cyan]")
        self.logger.info(f"[cyan]Target:[/cyan] {self.config.target_hosts}")
        self.logger.info(f"[cyan]Ports:[/cyan] {self.config.target_ports}")
        self.logger.info(f"[cyan]Intensity:[/cyan] {self.config.scan_intensity}")
        self.logger.info(f"[cyan]Safe Mode:[/cyan] {self.config.safe_mode}")
        self.logger.info(f"[cyan]Dry Run:[/cyan] {self.config.dry_run}")
        
        # Phase 1: Reconnaissance
        self._run_phase("Reconnaissance", self._phase_reconnaissance)
        
        # Phase 2: Vulnerability Analysis
        self._run_phase("Vulnerability Analysis", self._phase_vulnerability_analysis)
        
        # Phase 3: AI Attack Planning (if API key available)
        if self.config.anthropic_api_key:
            self._run_phase("Attack Planning", self._phase_attack_planning)
        else:
            self.logger.warning("[yellow]Skipping attack planning - no Anthropic API key configured[/yellow]")
        
        # Phase 4: Exploitation (if enabled)
        if self.config.enable_exploitation and not self.config.dry_run:
            self._run_phase("Exploitation", self._phase_exploitation)
        else:
            if self.config.dry_run:
                self.logger.info("[yellow]Exploitation skipped - dry run mode[/yellow]")
            else:
                self.logger.info("[yellow]Exploitation disabled in configuration[/yellow]")
        
        # Phase 5: Post-Exploitation (if enabled)
        if self.config.enable_post_exploitation and not self.config.dry_run:
            self._run_phase("Post-Exploitation", self._phase_post_exploitation)
        
        # Phase 6: Report Generation
        self._run_phase("Report Generation", self._phase_report_generation)
        
        self.logger.info("[bold green]=== Penetration Test Complete ===[/bold green]")
        
        return self.scan_result
    
    def _run_phase(self, phase_name: str, phase_func):
        """Run a phase with progress indication."""
        self.console.print(f"\n[bold blue]▶ {phase_name}[/bold blue]")
        try:
            phase_func()
        except Exception as e:
            self.logger.error(f"[red]{phase_name} failed:[/red] {str(e)}")
            if self.scan_result:
                self.scan_result.errors.append(f"{phase_name}: {str(e)}")
    
    def _phase_reconnaissance(self):
        """Execute reconnaissance phase."""
        self.scan_result = self.recon_module.comprehensive_scan(
            target_hosts=self.config.target_hosts,
            ports=self.config.target_ports,
            intensity=self.config.scan_intensity,
            exclude=self.config.target_exclude
        )
    
    def _phase_vulnerability_analysis(self):
        """Execute vulnerability analysis phase."""
        if not self.scan_result:
            self.logger.error("[red]No scan results available for analysis[/red]")
            return
        
        self.vuln_analyzer.analyze_scan_results(self.scan_result)
    
    def _phase_attack_planning(self):
        """Execute AI-powered attack planning phase."""
        if not self.scan_result:
            self.logger.error("[red]No scan results available for attack planning[/red]")
            return
        
        self.attack_planner = AttackPlanner(self.config)
        attack_plan = self.attack_planner.create_attack_plan(self.scan_result)
        
        # Display attack plan summary
        self.console.print(f"[green]Generated attack plan with {len(attack_plan.steps)} steps[/green]")
        self.console.print(f"[green]Estimated duration: {attack_plan.estimated_time} minutes[/green]")
        self.console.print(f"[green]Risk level: {attack_plan.risk_level}[/green]")
    
    def _phase_exploitation(self):
        """Execute exploitation phase."""
        if not self.scan_result or not self.scan_result.attack_plan:
            self.logger.error("[red]No attack plan available for exploitation[/red]")
            return
        
        self.exploit_engine = ExploitEngine(self.config)
        exploit_results = self.exploit_engine.execute_attack_plan(
            self.scan_result.attack_plan,
            self.scan_result
        )
        
        self.scan_result.exploit_results = exploit_results
    
    def _phase_post_exploitation(self):
        """Execute post-exploitation phase."""
        if not self.scan_result or not self.exploit_engine:
            self.logger.error("[red]No exploit results available for post-exploitation[/red]")
            return
        
        successful_exploits = [
            r for r in self.scan_result.exploit_results 
            if r.status.value == "Success"
        ]
        
        if not successful_exploits:
            self.logger.info("[yellow]No successful exploits for post-exploitation[/yellow]")
            return
        
        self.post_exploit = PostExploitationModule(self.config)
        post_data = self.post_exploit.run_post_exploitation(successful_exploits)
        
        self.scan_result.post_exploit_data = post_data
    
    def _phase_report_generation(self):
        """Execute report generation phase."""
        if not self.scan_result:
            self.logger.error("[red]No scan results available for report generation[/red]")
            return
        
        report_files = self.report_generator.generate_reports(self.scan_result)
        
        self.console.print("\n[bold green]Reports generated:[/bold green]")
        for fmt, path in report_files.items():
            self.console.print(f"  [cyan]{fmt.upper()}:[/cyan] {path}")
    
    def _generate_reports(self):
        """Generate reports on interrupt."""
        if self.scan_result:
            self.logger.info("[cyan]Generating reports before exit...[/cyan]")
            self._phase_report_generation()
    
    def _print_banner(self):
        """Print the application banner."""
        banner_text = Text()
        banner_text.append("""
    ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
    ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
    ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
    ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
    ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
        """, style="bold red")
        
        subtitle = Text("\n    Autonomous Penetration Testing Framework\n", style="cyan")
        warning = Text("    ⚠ FOR AUTHORIZED TESTING ONLY ⚠\n", style="bold yellow")
        
        self.console.print(Panel(
            banner_text + subtitle + warning,
            border_style="red"
        ))


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="RedTeam Automation Tool - Autonomous Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan of a network
  python redteam.py --target 192.168.1.0/24
  
  # Scan specific ports with custom intensity
  python redteam.py --target 10.0.0.1 --ports 80,443,8080,3306 --intensity 3
  
  # Use custom configuration file
  python redteam.py --config /path/to/custom.env
  
  # Dry run (scan only, no exploitation)
  python redteam.py --target 192.168.1.1 --dry-run
  
  # Safe mode (no post-exploitation)
  python redteam.py --target 192.168.1.1 --safe-mode
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        help='Target host(s) to scan (e.g., 192.168.1.1, 192.168.1.0/24, 10.0.0.1-10.0.0.50)'
    )
    
    parser.add_argument(
        '--ports', '-p',
        default='1-65535',
        help='Port range to scan (default: 1-65535)'
    )
    
    parser.add_argument(
        '--exclude', '-e',
        help='Hosts to exclude from scan'
    )
    
    parser.add_argument(
        '--intensity', '-i',
        type=int,
        choices=range(1, 6),
        default=4,
        help='Scan intensity 1-5 (default: 4)'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file (.env)'
    )
    
    parser.add_argument(
        '--dry-run', '-d',
        action='store_true',
        help='Scan only, do not exploit'
    )
    
    parser.add_argument(
        '--safe-mode', '-s',
        action='store_true',
        help='Disable post-exploitation activities'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output directory for reports'
    )
    
    parser.add_argument(
        '--format', '-f',
        default='html,pdf',
        help='Report formats (default: html,pdf)'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Load configuration
    config = Config.from_env(args.config)
    
    # Override config with command line arguments
    if args.target:
        config.target_hosts = args.target
    if args.ports:
        config.target_ports = args.ports
    if args.exclude:
        config.target_exclude = args.exclude
    if args.intensity:
        config.scan_intensity = args.intensity
    if args.dry_run:
        config.dry_run = True
    if args.safe_mode:
        config.safe_mode = True
        config.enable_post_exploitation = False
    if args.output:
        config.report_output_dir = args.output
    if args.format:
        config.report_format = args.format
    
    # Validate required parameters
    if not config.target_hosts:
        parser.error("Target is required. Use --target or set TARGET_HOSTS in .env file")
    
    # Create and run the tool
    tool = RedTeamTool(config)
    
    try:
        tool.run_full_assessment()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
