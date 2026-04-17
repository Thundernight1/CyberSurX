"""
Core module for RedTeam Automation Tool.
"""
from .config import Config
from .models import (
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
