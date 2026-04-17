"""
HITL Configuration Extension
RedTeam Physical Suite için HITL ayarları
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path


@dataclass
class HITLConfig:
    """HITL onay mekanizması ayarları."""
    
    # Ana ayarlar
    enabled: bool = True
    timeout: int = 300  # saniye
    auto_approve_low_risk: bool = False
    
    # Bildirim ayarları
    notification_email: Optional[str] = None
    enable_web_notifications: bool = False
    enable_email_notifications: bool = False
    
    # Risk seviyesi ayarları
    require_approval_for: list = field(default_factory=lambda: [
        "exploit",              # Exploit çalıştırma
        "physical_device",      # Fiziksel cihaz kullanımı
        "credential_dump",      # Credential toplama
        "persistence",          # Persistence mekanizmaları
        "lateral_movement",     # Yanal hareket
        "data_exfiltration",    # Veri sızdırma
        "destructive_action",   # Zararlı işlemler
    ])
    
    # Otomatik onaylanacak işlemler (risk-based)
    auto_approved_operations: list = field(default_factory=lambda: [
        "scan",                 # Tarama işlemleri
        "reconnaissance",       # Keşif işlemleri
        "information_gathering" # Bilgi toplama
    ])
    
    # Loglama ayarları
    log_dir: str = "./logs/hitl"
    log_retention_days: int = 30
    
    # Dashboard entegrasyonu
    webhook_url: Optional[str] = None
    api_key: Optional[str] = None
    
    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "HITLConfig":
        """Sözlükten HITLConfig oluştur."""
        return cls(
            enabled=config.get("enabled", True),
            timeout=config.get("timeout", 300),
            auto_approve_low_risk=config.get("auto_approve_low_risk", False),
            notification_email=config.get("notification_email"),
            enable_web_notifications=config.get("enable_web_notifications", False),
            enable_email_notifications=config.get("enable_email_notifications", False),
            require_approval_for=config.get("require_approval_for", []),
            auto_approved_operations=config.get("auto_approved_operations", []),
            log_dir=config.get("log_dir", "./logs/hitl"),
            log_retention_days=config.get("log_retention_days", 30),
            webhook_url=config.get("webhook_url"),
            api_key=config.get("api_key"),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Sözlük olarak döndür."""
        return {
            "enabled": self.enabled,
            "timeout": self.timeout,
            "auto_approve_low_risk": self.auto_approve_low_risk,
            "notification_email": self.notification_email,
            "enable_web_notifications": self.enable_web_notifications,
            "enable_email_notifications": self.enable_email_notifications,
            "require_approval_for": self.require_approval_for,
            "auto_approved_operations": self.auto_approved_operations,
            "log_dir": self.log_dir,
            "log_retention_days": self.log_retention_days,
            "webhook_url": self.webhook_url,
            "api_key": self.api_key
        }
    
    def requires_approval(self, operation_type: str, risk_level: str = "medium") -> bool:
        """
        İşlem için onay gerekip gerekmediğini kontrol et.
        
        Args:
            operation_type: İşlem tipi
            risk_level: Risk seviyesi (low, medium, high, critical)
            
        Returns:
            Onay gerekiyor mu?
        """
        if not self.enabled:
            return False
        
        # Düşük risk otomatik onay
        if self.auto_approve_low_risk and risk_level == "low":
            return False
        
        # Otomatik onaylanacak işlemler
        if operation_type in self.auto_approved_operations:
            return False
        
        # Onay gerektiren işlemler
        if operation_type in self.require_approval_for:
            return True
        
        # Kritik risk her zaman onay ister
        if risk_level in ["high", "critical"]:
            return True
        
        return False
