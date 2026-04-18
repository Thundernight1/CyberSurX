"""SQLAlchemy ORM models"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .connection import Base
import enum

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class RiskLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    reports = relationship("Report", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="http")
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    scan_results = relationship("ScanResult", back_populates="target")
    vulnerabilities = relationship("Vulnerability", back_populates="target")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)  # nmap, injection, recon
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    parameters = Column(JSON, default=dict)
    findings = Column(JSON, default=list)
    raw_output = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    target = relationship("Target", back_populates="scan_results")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=True)
    vuln_type = Column(String(100), nullable=False)  # sqli, xss, rce, etc
    severity = Column(Enum(RiskLevel), default=RiskLevel.info)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)
    remediation = Column(Text, nullable=True)
    cve_id = Column(String(50), nullable=True)
    cvss_score = Column(String(10), nullable=True)
    is_fixed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    target = relationship("Target", back_populates="vulnerabilities")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    report_type = Column(String(50), default="executive")  # executive, technical, compliance
    title = Column(String(500), nullable=False)
    format = Column(String(20), default="pdf")  # pdf, html, json, markdown
    content = Column(JSON, default=dict)
    file_path = Column(String(1000), nullable=True)
    is_generated = Column(Boolean, default=False)
    generated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    user = relationship("User", back_populates="reports")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # scan_started, exploit_attempted, etc
    resource_type = Column(String(50), nullable=False)  # target, scan, device
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(100), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    user = relationship("User", back_populates="audit_logs")

class AgentExecution(Base):
    __tablename__ = "agent_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_type = Column(String(50), nullable=False)  # operator, analysis, decision
    agent_name = Column(String(100), nullable=False)
    task = Column(Text, nullable=False)
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    status = Column(String(50), default="pending")
    error = Column(Text, nullable=True)
    execution_time_ms = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    device_type = Column(String(50), nullable=False)  # pineapple, flipper, sharktap
    ip_address = Column(String(100), nullable=True)
    port = Column(Integer, nullable=True)
    username = Column(String(100), nullable=True)
    password_encrypted = Column(String(500), nullable=True)
    ssh_key_path = Column(String(500), nullable=True)
    is_connected = Column(Boolean, default=False)
    config = Column(JSON, default=dict)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class InjectionTest(Base):
    __tablename__ = "injection_tests"
    
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(500), nullable=False)
    test_type = Column(String(100), nullable=False)  # prompt-injection, data-exfiltration
    payload = Column(Text, nullable=False)
    payload_type = Column(String(100), default="single_turn")  # single_turn, multi_turn
    response = Column(Text, nullable=True)
    is_successful = Column(Boolean, default=False)
    vulnerability_detected = Column(JSON, default=dict)
    model_info = Column(JSON, default=dict)
    test_details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
