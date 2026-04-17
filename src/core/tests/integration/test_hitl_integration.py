"""
HITL Integration Tests

Ornek kullanim:
    python -m pytest tests/integration/test_hitl_integration.py -v

Not: Bu testler kullanici etkilesimi gerektirebilir.
"""
import pytest
import asyncio
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.hitl import HITLApproval, ApprovalStatus, RiskLevel
from core.hitl_config import HITLConfig


class TestHITLIntegrationWithRedTeam:
    """RedTeam Suite ile entegrasyon testleri."""
    
    def test_exploit_operation_requires_approval(self):
        """Exploit islemi onay gerektirir."""
        config = HITLConfig()
        
        # Exploit islemi her zaman onay ister
        assert config.requires_approval("exploit", "high") is True
        assert config.requires_approval("exploit", "medium") is True
        
    def test_physical_device_operation_requires_approval(self):
        """Fiziksel cihaz islemi onay gerektirir."""
        config = HITLConfig()
        
        # Pineapple/SharkTap yuksek risk
        assert config.requires_approval("physical_device", "high") is True
        # Flipper orta risk
        assert config.requires_approval("physical_device", "medium") is True
        
    def test_scan_operation_auto_approved(self):
        """Tarama islemleri otomatik onaylanir."""
        config = HITLConfig(auto_approve_low_risk=True)
        
        # Tarama islemleri dusuk risk
        assert config.requires_approval("scan", "low") is False
        assert config.requires_approval("reconnaissance", "low") is False
        
    def test_lateral_movement_requires_approval(self):
        """Yanal hareket onay gerektirir."""
        config = HITLConfig()
        
        assert config.requires_approval("lateral_movement", "high") is True
        assert config.requires_approval("lateral_movement", "critical") is True


class TestHITLAsync:
    """Asenkron HITL testleri."""
    
    @pytest.mark.asyncio
    async def test_wait_for_response_async_auto_approve(self):
        """Asenkron otomatik onay testi."""
        hitl = HITLApproval(
            enabled=True,
            auto_approve_low_risk=True,
            timeout=300
        )
        
        request = hitl.request_approval(
            operation_type="scan",
            target="192.168.1.0/24",
            risk_level=RiskLevel.LOW.value
        )
        
        # Asenkron cagi
        result = await hitl.wait_for_response_async(request)
        
        assert result.status == ApprovalStatus.APPROVED.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
