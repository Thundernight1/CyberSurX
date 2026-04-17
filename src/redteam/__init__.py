"""
RedTeam Automation Tool Package
"""
__version__ = "1.0.0"

from .core.config import Config
from .core.models import (
    ScanResult, Host, Port, Vulnerability, AttackPlan,
    AttackStep, ExploitResult, PostExploitData, ReportData,
    Severity, AttackStatus
)

__all__ = [
    'Config',
    'ScanResult',
    'Host',
    'Port',
    'Vulnerability',
    'AttackPlan',
    'AttackStep',
    'ExploitResult',
    'PostExploitData',
    'ReportData',
    'Severity',
    'AttackStatus',
]