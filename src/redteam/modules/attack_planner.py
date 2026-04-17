"""
AI-powered attack planning module using Claude API.
"""
import json
import uuid
from typing import List, Dict, Optional
from datetime import datetime
from anthropic import Anthropic

from redteam.core.models import (
    ScanResult, Vulnerability, AttackPlan, AttackStep, 
    Severity, AttackStatus
)
from redteam.core.config import Config
try:
    from redteam.utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(*args, **kwargs):
        return logging.getLogger(__name__)


class AttackPlanner:
    """Uses Claude AI to generate strategic attack plans based on vulnerabilities."""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = Anthropic(api_key=config.anthropic_api_key)
        self.model = config.anthropic_model
        self.logger = setup_logger()
    
    def create_attack_plan(self, scan_result: ScanResult) -> AttackPlan:
        """
        Generate an AI-powered attack plan based on scan results.
        
        Args:
            scan_result: The scan results containing discovered vulnerabilities
            
        Returns:
            AttackPlan object with strategic attack steps
        """
        self.logger.info("[bold cyan]=== Generating AI Attack Plan ===[/bold cyan]")
        
        # Prepare context for Claude
        context = self._prepare_context(scan_result)
        
        # Generate attack plan using Claude
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.2,
                system=self._get_system_prompt(),
                messages=[
                    {
                        "role": "user",
                        "content": self._build_planning_prompt(context)
                    }
                ]
            )
            
            # Parse the AI response
            plan_data = self._parse_attack_plan(response.content[0].text)
            
            # Create AttackPlan object
            attack_plan = AttackPlan(
                plan_id=str(uuid.uuid4())[:8],
                created_at=datetime.now(),
                target_scope=scan_result.target_hosts,
                objectives=[
                    "Gain initial access to the network",
                    "Escalate privileges on compromised systems",
                    "Identify and exfiltrate sensitive data",
                    "Establish persistence mechanisms",
                    "Document all findings for reporting"
                ],
                steps=plan_data.get('steps', []),
                estimated_time=plan_data.get('estimated_time', 60),
                risk_level=plan_data.get('risk_level', 'Medium'),
                prerequisites=plan_data.get('prerequisites', [])
            )
            
            self.logger.info("[bold green]=== Attack Plan Generated ===[/bold green]")
            self.logger.info(f"[green]Plan ID:[/green] {attack_plan.plan_id}")
            self.logger.info(f"[green]Total steps:[/green] {len(attack_plan.steps)}")
            self.logger.info(f"[green]Estimated time:[/green] {attack_plan.estimated_time} minutes")
            self.logger.info(f"[green]Risk level:[/green] {attack_plan.risk_level}")
            
            # Store plan in scan result
            scan_result.attack_plan = attack_plan
            
            return attack_plan
            
        except Exception as e:
            self.logger.error(f"[red]Failed to generate attack plan:[/red] {str(e)}")
            # Return a basic fallback plan
            return self._create_fallback_plan(scan_result)
    
    def _prepare_context(self, scan_result: ScanResult) -> Dict:
        """Prepare scan context for the AI."""
        context = {
            'hosts': [],
            'vulnerabilities': [],
            'scan_stats': scan_result.scan_stats
        }
        
        for host in scan_result.hosts_discovered:
            host_data = {
                'ip': host.ip_address,
                'hostname': host.hostname,
                'os': host.os_guess,
                'ports': []
            }
            
            for port in host.ports:
                if port.state == 'open':
                    host_data['ports'].append({
                        'port': port.port_number,
                        'service': port.service,
                        'version': port.version,
                        'protocol': port.protocol
                    })
            
            context['hosts'].append(host_data)
        
        for vuln in scan_result.vulnerabilities_found:
            vuln_data = {
                'id': vuln.id,
                'name': vuln.name,
                'severity': vuln.severity.value,
                'cve_id': vuln.cve_id,
                'cvss_score': vuln.cvss_score,
                'host': vuln.affected_host,
                'port': vuln.affected_port,
                'service': vuln.service,
                'exploit_available': vuln.exploit_available,
                'exploit_modules': vuln.exploit_modules,
                'description': vuln.description[:200] if vuln.description else ""
            }
            context['vulnerabilities'].append(vuln_data)
        
        return context
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for Claude."""
        return """You are an expert penetration tester and red team operator. Your task is to create a strategic, step-by-step attack plan based on discovered vulnerabilities.

Your attack plans should:
1. Prioritize high-impact vulnerabilities first
2. Follow the cyber kill chain: Reconnaissance -> Initial Access -> Execution -> Persistence -> Privilege Escalation -> Credential Access -> Lateral Movement -> Collection -> Exfiltration
3. Consider the attack surface and potential blast radius
4. Include specific exploit modules and techniques
5. Account for detection risks and suggest evasion techniques
6. Be practical and executable

Respond in JSON format only with the following structure:
{
    "steps": [
        {
            "step_number": 1,
            "name": "Step name",
            "description": "Detailed description",
            "target_host": "IP address",
            "target_port": 80,
            "vulnerability_id": "CVE-XXXX-XXXX",
            "exploit_module": "exploit/...",
            "parameters": {"key": "value"},
            "estimated_time": 10
        }
    ],
    "estimated_time": 120,
    "risk_level": "High|Medium|Low",
    "prerequisites": ["list of prerequisites"]
}"""
    
    def _build_planning_prompt(self, context: Dict) -> str:
        """Build the planning prompt with context."""
        prompt = f"""Based on the following network scan results, create a strategic attack plan:

## Network Discovery Summary
- Hosts Discovered: {context['scan_stats'].get('hosts_discovered', 0)}
- Open Ports Found: {context['scan_stats'].get('open_ports_found', 0)}
- Vulnerabilities Identified: {context['scan_stats'].get('vulnerabilities_found', 0)}

## Discovered Hosts
"""
        
        for host in context['hosts']:
            prompt += f"\n### Host: {host['ip']}"
            if host['hostname']:
                prompt += f" ({host['hostname']})"
            prompt += f"\n- OS: {host['os'] or 'Unknown'}"
            prompt += "\n- Open Services:\n"
            for port in host['ports']:
                prompt += f"  - Port {port['port']}/{port['protocol']}: {port['service']}"
                if port['version']:
                    prompt += f" {port['version']}"
                prompt += "\n"
        
        prompt += "\n## Identified Vulnerabilities\n"
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_vulns = sorted(
            context['vulnerabilities'],
            key=lambda x: severity_order.get(x['severity'], 5)
        )
        
        for vuln in sorted_vulns[:20]:  # Limit to top 20
            prompt += f"\n- [{vuln['severity']}] {vuln['id']}"
            if vuln['cve_id']:
                prompt += f" ({vuln['cve_id']})"
            prompt += f"\n  - Host: {vuln['host']}:{vuln['port']}"
            prompt += f"\n  - Service: {vuln['service']}"
            prompt += f"\n  - CVSS: {vuln['cvss_score']}"
            prompt += f"\n  - Exploit Available: {vuln['exploit_available']}"
            if vuln['exploit_modules']:
                prompt += f"\n  - Modules: {', '.join(vuln['exploit_modules'])}"
            prompt += f"\n  - Description: {vuln['description'][:150]}...\n"
        
        prompt += """

## Instructions
Create a strategic attack plan that:
1. Starts with the most promising entry points (high severity, exploit available)
2. Progresses through the cyber kill chain
3. Includes specific Metasploit modules where applicable
4. Provides realistic time estimates
5. Assigns a risk level based on detection probability

Return ONLY the JSON response with no additional text."""
        
        return prompt
    
    def _parse_attack_plan(self, response_text: str) -> Dict:
        """Parse the AI response into attack plan data."""
        try:
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                plan_data = json.loads(json_str)
                
                # Convert step dictionaries to AttackStep objects
                steps = []
                for step_data in plan_data.get('steps', []):
                    step = AttackStep(
                        step_number=step_data.get('step_number', 0),
                        name=step_data.get('name', ''),
                        description=step_data.get('description', ''),
                        target_host=step_data.get('target_host', ''),
                        target_port=step_data.get('target_port', 0),
                        vulnerability_id=step_data.get('vulnerability_id', ''),
                        exploit_module=step_data.get('exploit_module', ''),
                        parameters=step_data.get('parameters', {}),
                        status=AttackStatus.PENDING
                    )
                    steps.append(step)
                
                plan_data['steps'] = steps
                return plan_data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"[red]Failed to parse AI response as JSON:[/red] {str(e)}")
        
        return {'steps': [], 'estimated_time': 60, 'risk_level': 'Medium', 'prerequisites': []}
    
    def _create_fallback_plan(self, scan_result: ScanResult) -> AttackPlan:
        """Create a basic fallback plan if AI generation fails."""
        steps = []
        step_number = 1
        
        # Create steps for critical and high vulnerabilities
        for vuln in scan_result.vulnerabilities_found:
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH] and vuln.exploit_available:
                step = AttackStep(
                    step_number=step_number,
                    name=f"Exploit {vuln.cve_id or vuln.id}",
                    description=f"Attempt to exploit {vuln.name} on {vuln.affected_host}",
                    target_host=vuln.affected_host,
                    target_port=vuln.affected_port,
                    vulnerability_id=vuln.cve_id or vuln.id,
                    exploit_module=vuln.exploit_modules[0] if vuln.exploit_modules else "",
                    status=AttackStatus.PENDING
                )
                steps.append(step)
                step_number += 1
        
        return AttackPlan(
            plan_id=str(uuid.uuid4())[:8],
            created_at=datetime.now(),
            target_scope=scan_result.target_hosts,
            objectives=["Gain initial access", "Escalate privileges"],
            steps=steps,
            estimated_time=len(steps) * 15,
            risk_level="High" if steps else "Low",
            prerequisites=["Metasploit RPC connection", "Network access to targets"]
        )
    
    def refine_plan(self, attack_plan: AttackPlan, execution_results: List[Dict]) -> AttackPlan:
        """
        Refine the attack plan based on execution results.
        
        Args:
            attack_plan: The current attack plan
            execution_results: Results from executed steps
            
        Returns:
            Refined AttackPlan
        """
        self.logger.info("[cyan]Refining attack plan based on execution results...[/cyan]")
        
        # Prepare context for refinement
        context = {
            'original_plan': {
                'steps': [
                    {
                        'step_number': s.step_number,
                        'name': s.name,
                        'target': f"{s.target_host}:{s.target_port}",
                        'exploit': s.exploit_module
                    }
                    for s in attack_plan.steps
                ]
            },
            'execution_results': execution_results
        }
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.2,
                system="You are a penetration tester refining an attack plan based on execution results. Suggest adjustments to the remaining steps.",
                messages=[
                    {
                        "role": "user",
                        "content": f"""Based on these execution results, refine the remaining attack plan:

{json.dumps(context, indent=2)}

Suggest adjustments to the plan. Return JSON with 'adjustments' and 'new_steps' if needed."""
                    }
                ]
            )
            
            self.logger.info("[green]Attack plan refined based on execution results.[/green]")
            
        except Exception as e:
            self.logger.warning(f"[yellow]Failed to refine plan:[/yellow] {str(e)}")
        
        return attack_plan
    
    def analyze_attack_surface(self, scan_result: ScanResult) -> Dict:
        """
        Analyze the attack surface and provide insights.
        
        Args:
            scan_result: The scan results
            
        Returns:
            Dictionary with attack surface analysis
        """
        analysis = {
            'entry_points': [],
            'lateral_movement_paths': [],
            'high_value_targets': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        # Identify entry points
        for vuln in scan_result.vulnerabilities_found:
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                if vuln.exploit_available:
                    analysis['entry_points'].append({
                        'host': vuln.affected_host,
                        'port': vuln.affected_port,
                        'vulnerability': vuln.cve_id or vuln.id,
                        'exploit': vuln.exploit_modules[0] if vuln.exploit_modules else None
                    })
        
        # Identify high-value targets
        for host in scan_result.hosts_discovered:
            # Database servers
            db_ports = [3306, 5432, 1433, 27017, 6379]
            for port in host.ports:
                if port.port_number in db_ports:
                    analysis['high_value_targets'].append({
                        'host': host.ip_address,
                        'type': 'Database Server',
                        'service': port.service
                    })
        
        return analysis
