"""
Configuration management for the RedTeam Automation Tool.
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv


@dataclass
class Config:
    """Main configuration class for the RedTeam tool."""
    
    # Anthropic API
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-opus-20240229"
    
    # Target Configuration
    target_hosts: str = ""
    target_ports: str = "1-65535"
    target_exclude: str = ""
    
    # Scanning Configuration
    scan_timeout: int = 300
    scan_intensity: int = 4
    nmap_path: str = "/usr/bin/nmap"
    
    # Metasploit Configuration
    msf_rpc_host: str = "127.0.0.1"
    msf_rpc_port: int = 55553
    msf_rpc_user: str = "msf"
    msf_rpc_pass: str = ""
    msf_path: str = "/opt/metasploit-framework"
    
    # Attack Configuration
    exploit_timeout: int = 60
    max_threads: int = 10
    enable_exploitation: bool = True
    enable_post_exploitation: bool = True
    
    # Report Configuration
    report_output_dir: str = "./reports"
    report_format: str = "html,pdf"
    report_company_name: str = "RedTeam Security"
    report_author: str = "Automated Pentest System"
    
    # Safety Configuration
    dry_run: bool = False
    safe_mode: bool = True
    max_privilege_escalation: bool = True
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "./logs/redteam.log"
    output_dir: str = "./output"
    
    @classmethod
    def from_env(cls, env_file: Optional[str] = None) -> 'Config':
        """Load configuration from environment variables."""
        if env_file and os.path.exists(env_file):
            load_dotenv(env_file)
        else:
            load_dotenv()
        
        return cls(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229"),
            target_hosts=os.getenv("TARGET_HOSTS", ""),
            target_ports=os.getenv("TARGET_PORTS", "1-65535"),
            target_exclude=os.getenv("TARGET_EXCLUDE", ""),
            scan_timeout=int(os.getenv("SCAN_TIMEOUT", "300")),
            scan_intensity=int(os.getenv("SCAN_INTENSITY", "4")),
            nmap_path=os.getenv("NMAP_PATH", "/usr/bin/nmap"),
            msf_rpc_host=os.getenv("MSF_RPC_HOST", "127.0.0.1"),
            msf_rpc_port=int(os.getenv("MSF_RPC_PORT", "55553")),
            msf_rpc_user=os.getenv("MSF_RPC_USER", "msf"),
            msf_rpc_pass=os.getenv("MSF_RPC_PASS", ""),
            msf_path=os.getenv("MSF_PATH", "/opt/metasploit-framework"),
            exploit_timeout=int(os.getenv("EXPLOIT_TIMEOUT", "60")),
            max_threads=int(os.getenv("MAX_THREADS", "10")),
            enable_exploitation=os.getenv("ENABLE_EXPLOITATION", "true").lower() == "true",
            enable_post_exploitation=os.getenv("ENABLE_POST_EXPLOITATION", "true").lower() == "true",
            report_output_dir=os.getenv("REPORT_OUTPUT_DIR", "./reports"),
            report_format=os.getenv("REPORT_FORMAT", "html,pdf"),
            report_company_name=os.getenv("REPORT_COMPANY_NAME", "RedTeam Security"),
            report_author=os.getenv("REPORT_AUTHOR", "Automated Pentest System"),
            dry_run=os.getenv("DRY_RUN", "false").lower() == "true",
            safe_mode=os.getenv("SAFE_MODE", "true").lower() == "true",
            max_privilege_escalation=os.getenv("MAX_PRIVILEGE_ESCALATION", "true").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "./logs/redteam.log"),
            output_dir=os.getenv("OUTPUT_DIR", "./output"),
        )
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []
        
        if not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY is required")
        
        if not self.target_hosts:
            errors.append("TARGET_HOSTS is required")
        
        if self.scan_intensity < 1 or self.scan_intensity > 5:
            errors.append("SCAN_INTENSITY must be between 1 and 5")
        
        return errors
