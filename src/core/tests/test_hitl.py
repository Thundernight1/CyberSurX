"""
HITL Module - Unit Tests

Kullanim:
    python -m pytest tests/test_hitl.py -v
    python -m pytest tests/test_hitl.py::test_request_approval -v
"""
import pytest
import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.hitl import HITLApproval, ApprovalRequest, ApprovalStatus, RiskLevel
from core.hitl_config import HITLConfig


class TestHITLApproval:
    """HITLApproval sinifi testleri."""
    
    def test_init_default_config(self):
        """Varsayilan ayarlarla baslatma testi."""
        hitl = HITLApproval(enabled=True, timeout=300)
        
        assert hitl.enabled is True
        assert hitl.timeout == 300
        assert hitl.auto_approve_low_risk is False
        
    def test_request_approval_creates_request(self):
        """Onay istegi olusturma testi."""
        hitl = HITLApproval(enabled=True, timeout=300)
        
        request = hitl.request_approval(
            operation_type="exploit",
            target="192.168.1.1:80",
            risk_level=RiskLevel.HIGH.value,
            details={"vulnerability": "CVE-2023-1234"}
        )
        
        assert isinstance(request, ApprovalRequest)
        assert request.operation_type == "exploit"
        assert request.target == "192.168.1.1:80"
        assert request.risk_level == RiskLevel.HIGH.value
        assert request.status == ApprovalStatus.PENDING.value
        assert request.details.get("vulnerability") == "CVE-2023-1234"
        assert request.timeout_at is not None
        
    def test_auto_approve_low_risk(self):
        """Dusuk risk otomatik onay testi."""
        hitl = HITLApproval(
            enabled=True,
            auto_approve_low_risk=True,
            timeout=300
        )
        
        request = hitl.request_approval(
            operation_type="scan",
            target="192.168.1.1",
            risk_level=RiskLevel.LOW.value
        )
        
        # wait_for_response cagrildiginda otomatik onaylanmali
        result = hitl.wait_for_response(request)
        
        assert result.status == ApprovalStatus.APPROVED.value
        assert result.approved_by == "SYSTEM_AUTO_LOW_RISK"
        
    def test_disabled_hitl_auto_approves(self):
        """Kapatilmis HITL otomatik onay testi."""
        hitl = HITLApproval(enabled=False, timeout=300)
        
        request = hitl.request_approval(
            operation_type="exploit",
            target="192.168.1.1",
            risk_level=RiskLevel.CRITICAL.value
        )
        
        result = hitl.wait_for_response(request)
        
        assert result.status == ApprovalStatus.APPROVED.value
        assert result.approved_by == "SYSTEM_AUTO"
        
    def test_log_decision_creates_log_file(self, tmp_path):
        """Log dosyasi olusturma testi."""
        log_dir = tmp_path / "hitl_logs"
        hitl = HITLApproval(enabled=True, timeout=300, log_dir=log_dir)
        
        request = ApprovalRequest(
            operation_type="exploit",
            target="192.168.1.1",
            risk_level=RiskLevel.HIGH.value
        )
        request.status = ApprovalStatus.APPROVED.value
        request.approved_by = "TEST_USER"
        request.approved_at = datetime.now().isoformat()
        
        hitl.log_decision(request)
        
        log_file = log_dir / f"hitl_{datetime.now().strftime('%Y%m%d')}.jsonl"
        assert log_file.exists()
        
    def test_approve_request_external(self):
        """Harici onay verme testi."""
        hitl = HITLApproval(enabled=True, timeout=300)
        
        request = hitl.request_approval(
            operation_type="physical_device",
            target="pineapple on 192.168.1.0/24",
            risk_level=RiskLevel.HIGH.value
        )
        
        # Harici onay
        success = hitl.approve_request(request.request_id, approver="ADMIN")
        
        assert success is True
        assert hitl._pending_requests[request.request_id].status == ApprovalStatus.APPROVED.value
        assert hitl._pending_requests[request.request_id].approved_by == "ADMIN"
        
    def test_reject_request_external(self):
        """Harici reddetme testi."""
        hitl = HITLApproval(enabled=True, timeout=300)
        
        request = hitl.request_approval(
            operation_type="destructive_action",
            target="192.168.1.1",
            risk_level=RiskLevel.CRITICAL.value
        )
        
        # Harici reddetme
        success = hitl.reject_request(
            request.request_id,
            reason="Too risky for current assessment",
            rejecter="ADMIN"
        )
        
        assert success is True
        assert hitl._pending_requests[request.request_id].status == ApprovalStatus.REJECTED.value
        assert hitl._pending_requests[request.request_id].rejected_by == "ADMIN"
        assert "Too risky" in hitl._pending_requests[request.request_id].rejection_reason


class TestHITLConfig:
    """HITLConfig sinifi testleri."""
    
    def test_default_config(self):
        """Varsayilan HITLConfig testi."""
        config = HITLConfig()
        
        assert config.enabled is True
        assert config.timeout == 300
        assert config.auto_approve_low_risk is False
        assert "exploit" in config.require_approval_for
        assert "physical_device" in config.require_approval_for
        
    def test_from_dict(self):
        """Sozlukten yukleme testi."""
        data = {
            "enabled": False,
            "timeout": 600,
            "auto_approve_low_risk": True,
            "notification_email": "test@example.com"
        }
        
        config = HITLConfig.from_dict(data)
        
        assert config.enabled is False
        assert config.timeout == 600
        assert config.auto_approve_low_risk is True
        assert config.notification_email == "test@example.com"
        
    def test_requires_approval_critical(self):
        """Kritik risk onay gereksinimi testi."""
        config = HITLConfig()
        
        assert config.requires_approval("exploit", "critical") is True
        assert config.requires_approval("exploit", "high") is True
        
    def test_requires_approval_low_risk_auto(self):
        """Dusuk risk otomatik onay testi."""
        config = HITLConfig(auto_approve_low_risk=True)
        
        # Otomatik onaylanacak islemler
        assert config.requires_approval("scan", "low") is False
        
    def test_to_dict_roundtrip(self):
        """Dict donusumu ve geri yukleme testi."""
        original = HITLConfig(
            enabled=False,
            timeout=600,
            notification_email="test@example.com"
        )
        
        data = original.to_dict()
        restored = HITLConfig.from_dict(data)
        
        assert restored.enabled == original.enabled
        assert restored.timeout == original.timeout
        assert restored.notification_email == original.notification_email


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
