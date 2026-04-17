"""
Report generation module for HTML and PDF reports.
"""
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Template
from redteam.core.config import Config
from redteam.core.models import ScanResult, ReportData, Severity, Vulnerability
try:
    from redteam.utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(*args, **kwargs):
        return logging.getLogger(__name__)

# HTML report template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>RedTeaming Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #1a1a2e; color: white; padding: 20px; }
        .section { margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RedTeaming Assessment Report</h1>
        <p>Generated: {{ report.generated_at }}</p>
    </div>
    <div class="section">
        {{ content }}
    </div>
</body>
</html>
"""


class ReportGenerator:
    """Generates professional penetration test reports in HTML and PDF formats."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger()
        self.output_dir = Path(config.report_output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_reports(self, scan_result: ScanResult) -> Dict[str, str]:
        """
        Generate all configured report formats.
        
        Args:
            scan_result: The complete scan results
            
        Returns:
            Dictionary mapping format to file path
        """
        self.logger.info("[bold cyan]=== Generating Reports ===[/bold cyan]")
        
        # Prepare report data
        report_data = self._prepare_report_data(scan_result)
        
        generated_files = {}
        
        formats = self.config.report_format.split(',')
        
        for fmt in formats:
            fmt = fmt.strip().lower()
            
            if fmt == 'html':
                html_path = self._generate_html_report(report_data)
                generated_files['html'] = html_path
                self.logger.info(f"[green]HTML report generated:[/green] {html_path}")
            
            elif fmt == 'pdf':
                pdf_path = self._generate_pdf_report(report_data)
                generated_files['pdf'] = pdf_path
                self.logger.info(f"[green]PDF report generated:[/green] {pdf_path}")
            
            elif fmt == 'json':
                json_path = self._generate_json_report(scan_result)
                generated_files['json'] = json_path
                self.logger.info(f"[green]JSON report generated:[/green] {json_path}")
        
        self.logger.info("[bold green]=== Report Generation Complete ===[/bold green]")
        
        return generated_files
    
    def _prepare_report_data(self, scan_result: ScanResult) -> ReportData:
        """Prepare data for report generation."""
        
        # Calculate findings by severity
        findings_by_severity = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in scan_result.vulnerabilities_found:
            findings_by_severity[vuln.severity.value] += 1
        
        # Calculate risk score
        risk_score = (
            findings_by_severity['Critical'] * 10 +
            findings_by_severity['High'] * 7 +
            findings_by_severity['Medium'] * 4 +
            findings_by_severity['Low'] * 1
        )
        
        # Build attack timeline
        attack_timeline = []
        if scan_result.attack_plan:
            for step in scan_result.attack_plan.steps:
                attack_timeline.append({
                    'time': step.start_time.strftime('%H:%M:%S') if step.start_time else 'N/A',
                    'step': step.step_number,
                    'name': step.name,
                    'target': f"{step.target_host}:{step.target_port}",
                    'status': step.status.value,
                    'result': step.result[:100] + '...' if step.result and len(step.result) > 100 else step.result
                })
        
        # Generate recommendations
        recommendations = self._generate_recommendations(scan_result)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(scan_result, risk_score)
        
        return ReportData(
            scan_result=scan_result,
            executive_summary=executive_summary,
            risk_score=risk_score,
            findings_by_severity=findings_by_severity,
            attack_timeline=attack_timeline,
            recommendations=recommendations,
            generated_at=datetime.now()
        )
    
    def _generate_executive_summary(self, scan_result: ScanResult, risk_score: float) -> str:
        """Generate executive summary text."""
        summary = f"""This penetration test was conducted on {', '.join(scan_result.target_hosts)}. 
        
The assessment identified {len(scan_result.vulnerabilities_found)} vulnerabilities across {len(scan_result.hosts_discovered)} hosts. 

Key Findings:
- Critical vulnerabilities: {sum(1 for v in scan_result.vulnerabilities_found if v.severity == Severity.CRITICAL)}
- High severity vulnerabilities: {sum(1 for v in scan_result.vulnerabilities_found if v.severity == Severity.HIGH)}
- Medium severity vulnerabilities: {sum(1 for v in scan_result.vulnerabilities_found if v.severity == Severity.MEDIUM)}
- Low severity vulnerabilities: {sum(1 for v in scan_result.vulnerabilities_found if v.severity == Severity.LOW)}

Overall Risk Score: {risk_score}/100

{self._get_risk_rating(risk_score)}
"""
        return summary
    
    def _get_risk_rating(self, score: float) -> str:
        """Get risk rating based on score."""
        if score >= 50:
            return "The organization faces CRITICAL risk. Immediate remediation is required."
        elif score >= 30:
            return "The organization faces HIGH risk. Prompt remediation is recommended."
        elif score >= 15:
            return "The organization faces MEDIUM risk. Remediation should be prioritized."
        else:
            return "The organization faces LOW risk. Standard security practices should be maintained."
    
    def _generate_recommendations(self, scan_result: ScanResult) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Group vulnerabilities by service
        service_vulns = {}
        for vuln in scan_result.vulnerabilities_found:
            service = vuln.service or 'Unknown'
            if service not in service_vulns:
                service_vulns[service] = []
            service_vulns[service].append(vuln)
        
        for service, vulns in service_vulns.items():
            critical_high = [v for v in vulns if v.severity in [Severity.CRITICAL, Severity.HIGH]]
            if critical_high:
                recommendations.append(
                    f"Priority: Update {service} to the latest version to address "
                    f"{len(critical_high)} critical/high severity vulnerabilities."
                )
        
        # General recommendations
        recommendations.extend([
            "Implement network segmentation to limit lateral movement.",
            "Deploy intrusion detection/prevention systems (IDS/IPS).",
            "Establish regular vulnerability scanning and patch management processes.",
            "Implement principle of least privilege for all systems and services.",
            "Enable comprehensive logging and monitoring across all critical systems.",
            "Conduct regular security awareness training for all personnel.",
            "Implement multi-factor authentication (MFA) for all remote access.",
        ])
        
        return recommendations
    
    def _generate_html_report(self, report_data: ReportData) -> str:
        """Generate HTML report with dark theme."""
        
        html_template = self._get_html_template()
        template = Template(html_template)
        
        # Render template
        html_content = template.render(
            company_name=self.config.report_company_name,
            author=self.config.report_author,
            generated_at=report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
            executive_summary=report_data.executive_summary,
            risk_score=report_data.risk_score,
            findings_by_severity=report_data.findings_by_severity,
            scan_result=report_data.scan_result,
            attack_timeline=report_data.attack_timeline,
            recommendations=report_data.recommendations,
            severity_colors={
                'Critical': '#ff4444',
                'High': '#ff8800',
                'Medium': '#ffcc00',
                'Low': '#00ccff',
                'Info': '#888888'
            }
        )
        
        # Save HTML file
        output_path = self.output_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_pdf_report(self, report_data: ReportData) -> str:
        """Generate PDF report using the PDF skill."""
        
        # First generate HTML for PDF conversion
        pdf_html = self._get_pdf_html_template()
        
        from jinja2 import Template
        template = Template(pdf_html)
        
        html_content = template.render(
            company_name=self.config.report_company_name,
            author=self.config.report_author,
            generated_at=report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
            executive_summary=report_data.executive_summary,
            risk_score=report_data.risk_score,
            findings_by_severity=report_data.findings_by_severity,
            scan_result=report_data.scan_result,
            attack_timeline=report_data.attack_timeline,
            recommendations=report_data.recommendations,
        )
        
        # Save intermediate HTML
        html_path = self.output_dir / f"pentest_report_pdf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Convert to PDF using the skill script
        pdf_path = self.output_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        try:
            import subprocess
            result = subprocess.run(
                ['node', '/app/.kimi/skills/pdf/scripts/html_to_pdf.js', str(html_path), '--output', str(pdf_path)],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                self.logger.error(f"PDF conversion failed: {result.stderr}")
                # Return HTML path as fallback
                return str(html_path)
            
            # Clean up intermediate HTML
            html_path.unlink()
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {str(e)}")
            return str(html_path)
        
        return str(pdf_path)
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report."""
        
        # Convert to dictionary
        report_dict = {
            'scan_id': scan_result.scan_id,
            'start_time': scan_result.start_time.isoformat() if scan_result.start_time else None,
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'target_hosts': scan_result.target_hosts,
            'hosts_discovered': [
                {
                    'ip_address': h.ip_address,
                    'hostname': h.hostname,
                    'os_guess': h.os_guess,
                    'ports': [
                        {
                            'port_number': p.port_number,
                            'protocol': p.protocol,
                            'state': p.state,
                            'service': p.service,
                            'version': p.version
                        }
                        for p in h.ports
                    ],
                    'vulnerabilities': [
                        {
                            'id': v.id,
                            'name': v.name,
                            'severity': v.severity.value,
                            'cve_id': v.cve_id,
                            'cvss_score': v.cvss_score
                        }
                        for v in h.vulnerabilities
                    ]
                }
                for h in scan_result.hosts_discovered
            ],
            'vulnerabilities_found': [
                {
                    'id': v.id,
                    'name': v.name,
                    'description': v.description,
                    'severity': v.severity.value,
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'affected_host': v.affected_host,
                    'affected_port': v.affected_port,
                    'service': v.service,
                    'exploit_available': v.exploit_available,
                    'exploit_modules': v.exploit_modules
                }
                for v in scan_result.vulnerabilities_found
            ],
            'exploit_results': [
                {
                    'exploit_name': e.exploit_name,
                    'target_host': e.target_host,
                    'target_port': e.target_port,
                    'status': e.status.value,
                    'session_id': e.session_id,
                    'session_type': e.session_type,
                    'privileges': e.privileges,
                    'timestamp': e.timestamp.isoformat() if e.timestamp else None
                }
                for e in scan_result.exploit_results
            ],
            'scan_stats': scan_result.scan_stats
        }
        
        output_path = self.output_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2)
        
        return str(output_path)
    
    def _get_html_template(self) -> str:
        """Get the dark-themed HTML report template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {{ company_name }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --border: #30363d;
            --critical: #ff4444;
            --high: #ff8800;
            --medium: #ffcc00;
            --low: #00ccff;
            --info: #888888;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 3rem 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
        }
        
        header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--accent), #7ee787);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        header .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .section {
            background-color: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
        }
        
        .section h2 {
            color: var(--accent);
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border);
        }
        
        .risk-score {
            display: flex;
            align-items: center;
            gap: 2rem;
            margin: 1.5rem 0;
        }
        
        .risk-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            font-weight: bold;
            border: 4px solid;
        }
        
        .risk-critical { border-color: var(--critical); color: var(--critical); }
        .risk-high { border-color: var(--high); color: var(--high); }
        .risk-medium { border-color: var(--medium); color: var(--medium); }
        .risk-low { border-color: var(--low); color: var(--low); }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }
        
        .severity-card {
            background-color: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
        }
        
        .severity-card .count {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .severity-card.critical { color: var(--critical); }
        .severity-card.high { color: var(--high); }
        .severity-card.medium { color: var(--medium); }
        .severity-card.low { color: var(--low); }
        .severity-card.info { color: var(--info); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background-color: var(--bg-tertiary);
            color: var(--accent);
            font-weight: 600;
        }
        
        tr:hover {
            background-color: var(--bg-tertiary);
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .badge-critical { background-color: rgba(255, 68, 68, 0.2); color: var(--critical); }
        .badge-high { background-color: rgba(255, 136, 0, 0.2); color: var(--high); }
        .badge-medium { background-color: rgba(255, 204, 0, 0.2); color: var(--medium); }
        .badge-low { background-color: rgba(0, 204, 255, 0.2); color: var(--low); }
        .badge-info { background-color: rgba(136, 136, 136, 0.2); color: var(--info); }
        
        .badge-success { background-color: rgba(126, 231, 135, 0.2); color: #7ee787; }
        .badge-failed { background-color: rgba(255, 68, 68, 0.2); color: var(--critical); }
        .badge-pending { background-color: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }
        
        .timeline {
            position: relative;
            padding-left: 2rem;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 2px;
            background-color: var(--accent);
        }
        
        .timeline-item {
            position: relative;
            padding: 1rem;
            margin-bottom: 1rem;
            background-color: var(--bg-tertiary);
            border-radius: 8px;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -2.35rem;
            top: 1.5rem;
            width: 12px;
            height: 12px;
            background-color: var(--accent);
            border-radius: 50%;
        }
        
        .recommendations {
            list-style: none;
        }
        
        .recommendations li {
            padding: 1rem;
            margin-bottom: 0.5rem;
            background-color: var(--bg-tertiary);
            border-radius: 8px;
            border-left: 4px solid var(--accent);
        }
        
        .host-card {
            background-color: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border);
        }
        
        .host-card h4 {
            color: var(--accent);
            margin-bottom: 1rem;
        }
        
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        
        .port-tag {
            background-color: var(--bg-primary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-family: monospace;
        }
        
        pre {
            background-color: var(--bg-primary);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
        }
        
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Penetration Test Report</h1>
            <p class="meta">
                Generated by {{ company_name }} | Author: {{ author }} | Date: {{ generated_at }}
            </p>
        </header>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <pre>{{ executive_summary }}</pre>
            
            <div class="risk-score">
                <div class="risk-circle {% if risk_score >= 50 %}risk-critical{% elif risk_score >= 30 %}risk-high{% elif risk_score >= 15 %}risk-medium{% else %}risk-low{% endif %}">
                    {{ risk_score }}
                </div>
                <div>
                    <h3>Overall Risk Score</h3>
                    <p>Based on the number and severity of vulnerabilities discovered.</p>
                </div>
            </div>
            
            <h3>Findings by Severity</h3>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="count">{{ findings_by_severity.Critical }}</div>
                    <div>Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="count">{{ findings_by_severity.High }}</div>
                    <div>High</div>
                </div>
                <div class="severity-card medium">
                    <div class="count">{{ findings_by_severity.Medium }}</div>
                    <div>Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="count">{{ findings_by_severity.Low }}</div>
                    <div>Low</div>
                </div>
                <div class="severity-card info">
                    <div class="count">{{ findings_by_severity.Info }}</div>
                    <div>Info</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Discovered Hosts</h2>
            {% for host in scan_result.hosts_discovered %}
            <div class="host-card">
                <h4>{{ host.ip_address }} {% if host.hostname %}({{ host.hostname }}){% endif %}</h4>
                <p><strong>OS:</strong> {{ host.os_guess or 'Unknown' }}</p>
                <p><strong>Open Ports:</strong></p>
                <div class="port-list">
                    {% for port in host.ports %}
                    {% if port.state == 'open' %}
                    <span class="port-tag">{{ port.port_number }}/{{ port.protocol }}: {{ port.service }} {{ port.version }}</span>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>ID</th>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>CVSS</th>
                        <th>Exploit Available</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in scan_result.vulnerabilities_found %}
                    <tr>
                        <td><span class="badge badge-{{ vuln.severity.value.lower() }}">{{ vuln.severity.value }}</span></td>
                        <td>{{ vuln.cve_id or vuln.id }}</td>
                        <td>{{ vuln.affected_host }}</td>
                        <td>{{ vuln.affected_port }}</td>
                        <td>{{ vuln.service }}</td>
                        <td>{{ vuln.cvss_score }}</td>
                        <td>{% if vuln.exploit_available %}Yes{% else %}No{% endif %}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Attack Timeline</h2>
            <div class="timeline">
                {% for item in attack_timeline %}
                <div class="timeline-item">
                    <strong>{{ item.time }}</strong> - Step {{ item.step }}: {{ item.name }}<br>
                    <small>Target: {{ item.target }} | Status: 
                        <span class="badge badge-{% if item.status == 'Success' %}success{% elif item.status == 'Failed' %}failed{% else %}pending{% endif %}">
                            {{ item.status }}
                        </span>
                    </small>
                    {% if item.result %}
                    <pre>{{ item.result }}</pre>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="section">
            <h2>Exploit Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Exploit</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Session</th>
                        <th>Privileges</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in scan_result.exploit_results %}
                    <tr>
                        <td>{{ result.exploit_name }}</td>
                        <td>{{ result.target_host }}:{{ result.target_port }}</td>
                        <td><span class="badge badge-{% if result.status.value == 'Success' %}success{% elif result.status.value == 'Failed' %}failed{% else %}pending{% endif %}">{{ result.status.value }}</span></td>
                        <td>{{ result.session_id or 'N/A' }}</td>
                        <td>{{ result.privileges or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul class="recommendations">
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <footer>
            <p>Confidential - Penetration Test Report</p>
            <p>Generated by {{ company_name }}</p>
        </footer>
    </div>
</body>
</html>
"""
    
    def _get_pdf_html_template(self) -> str:
        """Get the HTML template optimized for PDF conversion."""
        # Similar to HTML template but with PDF-specific optimizations
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report</title>
    <style>
        @page {
            size: A4;
            margin: 2cm;
            @top-center { content: "Penetration Test Report"; }
            @bottom-center { content: counter(page); }
        }
        @page :first {
            @top-center { content: none; }
            @bottom-center { content: none; }
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Georgia, 'Times New Roman', serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }
        
        .cover {
            width: 210mm;
            height: 297mm;
            margin: 0;
            position: relative;
            overflow: hidden;
            page-break-after: always;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        }
        
        .cover-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            width: 80%;
            color: white;
        }
        
        .cover-title {
            font-size: 36pt;
            font-weight: bold;
            margin-bottom: 1cm;
            color: #e94560;
        }
        
        .cover-subtitle {
            font-size: 18pt;
            margin-bottom: 3cm;
            color: #eaeaea;
        }
        
        .cover-meta {
            font-size: 12pt;
            line-height: 2;
            color: #ccc;
        }
        
        h1 {
            font-size: 20pt;
            color: #1a1a2e;
            margin: 1.5em 0 0.5em 0;
            border-bottom: 2px solid #e94560;
            padding-bottom: 0.3em;
        }
        
        h2 {
            font-size: 16pt;
            color: #16213e;
            margin: 1.2em 0 0.5em 0;
        }
        
        h3 {
            font-size: 13pt;
            color: #0f3460;
            margin: 1em 0 0.5em 0;
        }
        
        p {
            margin-bottom: 0.8em;
            text-align: justify;
            text-align-last: left;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1em 0;
            font-size: 10pt;
        }
        
        th, td {
            padding: 0.5em;
            text-align: left;
            border: 1px solid #ddd;
        }
        
        th {
            background-color: #1a1a2e;
            color: white;
            font-weight: bold;
        }
        
        tr:nth-child(even) {
            background-color: #f5f5f5;
        }
        
        .risk-box {
            background-color: #f5f5f5;
            border-left: 4px solid #e94560;
            padding: 1em;
            margin: 1em 0;
        }
        
        .severity-count {
            display: inline-block;
            margin-right: 2em;
            text-align: center;
        }
        
        .severity-count .number {
            font-size: 24pt;
            font-weight: bold;
            display: block;
        }
        
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #17a2b8; }
        .info { color: #6c757d; }
        
        pre {
            background-color: #f5f5f5;
            padding: 1em;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .recommendation {
            background-color: #f8f9fa;
            border-left: 4px solid #0f3460;
            padding: 0.8em;
            margin: 0.5em 0;
        }
        
        .badge {
            display: inline-block;
            padding: 0.2em 0.5em;
            border-radius: 3px;
            font-size: 9pt;
            font-weight: bold;
        }
        
        .page-break {
            page-break-after: always;
        }
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="cover">
        <div class="cover-content">
            <h1 class="cover-title">Penetration Test Report</h1>
            <p class="cover-subtitle">Confidential Security Assessment</p>
            <div class="cover-meta">
                <p><strong>{{ company_name }}</strong></p>
                <p>Author: {{ author }}</p>
                <p>Date: {{ generated_at }}</p>
            </div>
        </div>
    </div>
    
    <!-- Executive Summary -->
    <h1>Executive Summary</h1>
    
    <div class="risk-box">
        <h2>Risk Assessment</h2>
        <p><strong>Overall Risk Score: {{ risk_score }}/100</strong></p>
        <p>{{ executive_summary }}</p>
    </div>
    
    <h2>Findings Overview</h2>
    <p>
        <span class="severity-count"><span class="number critical">{{ findings_by_severity.Critical }}</span>Critical</span>
        <span class="severity-count"><span class="number high">{{ findings_by_severity.High }}</span>High</span>
        <span class="severity-count"><span class="number medium">{{ findings_by_severity.Medium }}</span>Medium</span>
        <span class="severity-count"><span class="number low">{{ findings_by_severity.Low }}</span>Low</span>
        <span class="severity-count"><span class="number info">{{ findings_by_severity.Info }}</span>Info</span>
    </p>
    
    <div class="page-break"></div>
    
    <!-- Hosts Discovered -->
    <h1>Discovered Hosts</h1>
    
    {% for host in scan_result.hosts_discovered %}
    <h2>{{ host.ip_address }} {% if host.hostname %}({{ host.hostname }}){% endif %}</h2>
    <p><strong>Operating System:</strong> {{ host.os_guess or 'Unknown' }}</p>
    
    <h3>Open Services</h3>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
        </thead>
        <tbody>
            {% for port in host.ports %}
            {% if port.state == 'open' %}
            <tr>
                <td>{{ port.port_number }}</td>
                <td>{{ port.protocol }}</td>
                <td>{{ port.service }}</td>
                <td>{{ port.version }}</td>
            </tr>
            {% endif %}
            {% endfor %}
        </tbody>
    </table>
    {% endfor %}
    
    <div class="page-break"></div>
    
    <!-- Vulnerabilities -->
    <h1>Vulnerability Details</h1>
    
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Host:Port</th>
                <th>Service</th>
                <th>CVSS</th>
            </tr>
        </thead>
        <tbody>
            {% for vuln in scan_result.vulnerabilities_found %}
            <tr>
                <td><span class="badge" style="background-color: {% if vuln.severity.value == 'Critical' %}#dc3545{% elif vuln.severity.value == 'High' %}#fd7e14{% elif vuln.severity.value == 'Medium' %}#ffc107{% elif vuln.severity.value == 'Low' %}#17a2b8{% else %}#6c757d{% endif %}; color: white;">{{ vuln.severity.value }}</span></td>
                <td>{{ vuln.cve_id or vuln.id }}</td>
                <td>{{ vuln.affected_host }}:{{ vuln.affected_port }}</td>
                <td>{{ vuln.service }}</td>
                <td>{{ vuln.cvss_score }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <div class="page-break"></div>
    
    <!-- Exploit Results -->
    <h1>Exploitation Results</h1>
    
    <table>
        <thead>
            <tr>
                <th>Exploit</th>
                <th>Target</th>
                <th>Status</th>
                <th>Session</th>
            </tr>
        </thead>
        <tbody>
            {% for result in scan_result.exploit_results %}
            <tr>
                <td>{{ result.exploit_name }}</td>
                <td>{{ result.target_host }}:{{ result.target_port }}</td>
                <td>{{ result.status.value }}</td>
                <td>{{ result.session_id or 'N/A' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <div class="page-break"></div>
    
    <!-- Recommendations -->
    <h1>Recommendations</h1>
    
    {% for rec in recommendations %}
    <div class="recommendation">
        {{ rec }}
    </div>
    {% endfor %}
    
</body>
</html>
"""
