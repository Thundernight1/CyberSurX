"""
Data models for the RedTeam Automation Tool.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AttackStatus(Enum):
    PENDING = "Pending"
    IN_PROGRESS = "In Progress"
    SUCCESS = "Success"
    FAILED = "Failed"
    BLOCKED = "Blocked"
    SKIPPED = "Skipped"


@dataclass
class Port:
    """Represents a discovered port."""
    port_number: int
    protocol: str = "tcp"
    state: str = ""
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Host:
    """Represents a discovered host."""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    os_guess: str = ""
    ports: List[Port] = field(default_factory=list)
    vulnerabilities: List['Vulnerability'] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cve_id: str = ""
    cvss_score: float = 0.0
    affected_host: str = ""
    affected_port: int = 0
    service: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_modules: List[str] = field(default_factory=list)


@dataclass
class AttackStep:
    """Represents a step in the attack plan."""
    step_number: int
    name: str
    description: str
    target_host: str
    target_port: int
    vulnerability_id: str
    exploit_module: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: AttackStatus = AttackStatus.PENDING
    result: str = ""
    output: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: str = ""


@dataclass
class AttackPlan:
    """Represents the AI-generated attack plan."""
    plan_id: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    target_scope: List[str] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    steps: List[AttackStep] = field(default_factory=list)
    estimated_time: int = 0
    risk_level: str = ""
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class ExploitResult:
    """Represents the result of an exploit attempt."""
    exploit_name: str
    target_host: str
    target_port: int
    status: AttackStatus
    session_id: str = ""
    session_type: str = ""
    privileges: str = ""
    output: str = ""
    error: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    artifacts: List[str] = field(default_factory=list)


@dataclass
class PostExploitData:
    """Represents data gathered during post-exploitation."""
    host: str
    session_id: str
    user_context: str = ""
    hostname: str = ""
    os_info: str = ""
    network_interfaces: List[Dict] = field(default_factory=list)
    processes: List[Dict] = field(default_factory=list)
    installed_software: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    privilege_escalation_vectors: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Represents the complete scan results."""
    scan_id: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    target_hosts: List[str] = field(default_factory=list)
    hosts_discovered: List[Host] = field(default_factory=list)
    vulnerabilities_found: List[Vulnerability] = field(default_factory=list)
    attack_plan: Optional[AttackPlan] = None
    exploit_results: List[ExploitResult] = field(default_factory=list)
    post_exploit_data: List[PostExploitData] = field(default_factory=list)
    scan_stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class ReportData:
    """Represents data for report generation."""
    scan_result: ScanResult
    executive_summary: str = ""
    risk_score: float = 0.0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    attack_timeline: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    technical_details: str = ""
    generated_at: datetime = field(default_factory=datetime.now)
