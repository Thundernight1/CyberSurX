"""
HITL (Human-in-the-Loop) Approval Mechanism

Kritik operasyonlar için insan onayı mekanizması.
- Exploit çalıştırma
- Fiziksel cihaz kullanımı
- Riskli işlemler
"""
import asyncio
import json
import logging
import uuid
import threading
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass, field, asdict

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

logger = logging.getLogger("cyber-agent.hitl")


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApprovalRequest:
    """HITL onay isteği kaydı."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    operation_type: str = ""
    target: str = ""
    risk_level: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    timeout_at: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class HITLApproval:
    """
    Human-in-the-Loop Onay Mekanizması
    
    Kritik operasyonlar için kullanıcı onayı alır.
    - Timeout desteği (varsayılan: 300 saniye)
    - Asenkron ve senkron modlar
    - Loglama ve raporlama
    - Web/Dashboard entegrasyonu için callback desteği
    """
    
    def __init__(
        self,
        enabled: bool = True,
        auto_approve_low_risk: bool = False,
        timeout: int = 300,
        notification_email: Optional[str] = None,
        log_dir: Optional[Path] = None,
        console: Optional[Console] = None,
        approval_callback: Optional[Callable] = None
    ):
        """
        HITL Approval mekanizmasını başlat.
        
        Args:
            enabled: HITL mekanizması aktif mi?
            auto_approve_low_risk: Düşük riskli işlemleri otomatik onayla
            timeout: Onay bekleme süresi (saniye)
            notification_email: Bildirim e-postası (opsiyonel)
            log_dir: Karar loglama dizini
            console: Rich console instance
            approval_callback: Harici onay mekanizması için callback
        """
        self.enabled = enabled
        self.auto_approve_low_risk = auto_approve_low_risk
        self.timeout = timeout
        self.notification_email = notification_email
        self.log_dir = log_dir or Path("./logs/hitl")
        self.console = console or Console()
        self.approval_callback = approval_callback
        
        # Log dizini oluştur
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Aktif istekler
        self._pending_requests: Dict[str, ApprovalRequest] = {}
        self._request_lock = threading.Lock()
        
        logger.info(f"HITL Approval initialized (enabled={enabled}, timeout={timeout}s)")
    
    def request_approval(
        self,
        operation_type: str,
        target: str,
        risk_level: str,
        details: Optional[Dict[str, Any]] = None
    ) -> ApprovalRequest:
        """
        Yeni bir onay isteği oluştur.
        
        Args:
            operation_type: İşlem tipi (exploit, physical_device, vb.)
            target: Hedef host/cihaz
            risk_level: Risk seviyesi (low, medium, high, critical)
            details: Ek detaylar
            
        Returns:
            ApprovalRequest nesnesi
        """
        request = ApprovalRequest(
            operation_type=operation_type,
            target=target,
            risk_level=risk_level,
            details=details or {}
        )
        
        # Timeout hesapla
        timeout_seconds = details.get('timeout', self.timeout) if details else self.timeout
        timeout_at = datetime.fromtimestamp(time.time() + timeout_seconds)
        request.timeout_at = timeout_at.isoformat()
        
        with self._request_lock:
            self._pending_requests[request.request_id] = request
        
        logger.info(f"[HITL] New approval request: {request.request_id} ({operation_type} on {target}, risk={risk_level})")
        
        return request
    
    def wait_for_response(self, request: ApprovalRequest, timeout: int = None) -> ApprovalRequest:
        """
        Onay yanıtını bekle (senkron).
        
        Args:
            request: ApprovalRequest nesnesi
            timeout: Maksimum bekleme süresi (saniye)
            
        Returns:
            Güncellenmiş ApprovalRequest
        """
        if not self.enabled:
            request.status = ApprovalStatus.APPROVED.value
            request.approved_by = "SYSTEM_AUTO"
            request.approved_at = datetime.now().isoformat()
            self.log_decision(request)
            return request
        
        # Otomatik onay kontrolü
        if self.auto_approve_low_risk and request.risk_level == RiskLevel.LOW.value:
            request.status = ApprovalStatus.APPROVED.value
            request.approved_by = "SYSTEM_AUTO_LOW_RISK"
            request.approved_at = datetime.now().isoformat()
            logger.info(f"[HITL] Auto-approved low-risk request: {request.request_id}")
            self.log_decision(request)
            return request
        
        # Kullanıcıya sor
        return self._prompt_user(request, timeout or self.timeout)
    
    async def wait_for_response_async(
        self,
        request: ApprovalRequest,
        timeout: int = None
    ) -> ApprovalRequest:
        """
        Onay yanıtını bekle (asenkron).
        
        Args:
            request: ApprovalRequest nesnesi
            timeout: Maksimum bekleme süresi (saniye)
            
        Returns:
            Güncellenmiş ApprovalRequest
        """
        if not self.enabled:
            request.status = ApprovalStatus.APPROVED.value
            request.approved_by = "SYSTEM_AUTO"
            request.approved_at = datetime.now().isoformat()
            self.log_decision(request)
            return request
        
        # Otomatik onay kontrolü
        if self.auto_approve_low_risk and request.risk_level == RiskLevel.LOW.value:
            request.status = ApprovalStatus.APPROVED.value
            request.approved_by = "SYSTEM_AUTO_LOW_RISK"
            request.approved_at = datetime.now().isoformat()
            logger.info(f"[HITL] Auto-approved low-risk request: {request.request_id}")
            self.log_decision(request)
            return request
        
        # Callback varsa kullan (örn: web dashboard)
        if self.approval_callback:
            return await self._wait_callback(request, timeout or self.timeout)
        
        # Normal sync prompt'i asyncio thread'de çalıştır
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._prompt_user,
            request,
            timeout or self.timeout
        )
    
    def _prompt_user(self, request: ApprovalRequest, timeout: int) -> ApprovalRequest:
        """Kullanıcıdan onay iste."""
        start_time = time.time()
        
        self.console.print("\n")
        self.console.print(Panel.fit(
            f"[bold yellow]⚠️ CRITICAL OPERATION REQUIRES APPROVAL[/bold yellow]\n\n"
            f"[cyan]Request ID:[/cyan] {request.request_id}\n"
            f"[cyan]Operation:[/cyan] {request.operation_type}\n"
            f"[cyan]Target:[/cyan] {request.target}\n"
            f"[cyan]Risk Level:[/cyan] {request.risk_level.upper()}\n"
            f"[cyan]Timeout:[/cyan] {timeout} seconds\n\n"
            f"[bold]Details:[/bold]\n{self._format_details(request.details)}\n\n"
            f"[dim]Type 'approve' or 'reject' (with optional reason)[/dim]",
            title="HITL Approval Required",
            border_style="yellow"
        ))
        
        try:
            while time.time() - start_time < timeout:
                remaining = int(timeout - (time.time() - start_time))
                
                response = Prompt.ask(
                    f"\n[Approve/Reject] ({remaining}s remaining)",
                    default=""
                ).strip().lower()
                
                if not response:
                    continue
                
                if response.startswith('approve') or response == 'y' or response == 'yes':
                    request.status = ApprovalStatus.APPROVED.value
                    request.approved_by = "OPERATOR"
                    request.approved_at = datetime.now().isoformat()
                    self.log_decision(request)
                    return request
                
                elif response.startswith('reject') or response == 'n' or response == 'no':
                    reason = response[len('reject'):].strip() if response.startswith('reject') else "User rejected"
                    request.status = ApprovalStatus.REJECTED.value
                    request.rejected_by = "OPERATOR"
                    request.rejected_at = datetime.now().isoformat()
                    request.rejection_reason = reason if reason else "No reason provided"
                    self.log_decision(request)
                    return request
                
                else:
                    self.console.print("[yellow]Invalid response. Please type 'approve', 'reject', 'y', or 'n'[/yellow]")
        
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Approval cancelled by user[/yellow]")
            request.status = ApprovalStatus.CANCELLED.value
            request.rejection_reason = "Cancelled by user"
            self.log_decision(request)
            return request
        
        # Timeout
        request.status = ApprovalStatus.TIMEOUT.value
        request.rejection_reason = f"Timeout after {timeout} seconds"
        self.log_decision(request)
        self.console.print(f"\n[red]Approval request timed out after {timeout} seconds[/red]")
        return request
    
    async def _wait_callback(self, request: ApprovalRequest, timeout: int) -> ApprovalRequest:
        """Callback mekanizması ile bekle."""
        start_time = time.time()
        
        # Callback'i çağır (örn: web dashboard bildirimi)
        if self.approval_callback:
            self.approval_callback(request)
        
        while time.time() - start_time < timeout:
            with self._request_lock:
                current_request = self._pending_requests.get(request.request_id)
                if current_request and current_request.status != ApprovalStatus.PENDING.value:
                    return current_request
            
            await asyncio.sleep(0.5)
        
        # Timeout
        with self._request_lock:
            request = self._pending_requests.get(request.request_id)
            if request and request.status == ApprovalStatus.PENDING.value:
                request.status = ApprovalStatus.TIMEOUT.value
                request.rejection_reason = f"Timeout after {timeout} seconds"
                self.log_decision(request)
        
        return request
    
    def approve_request(self, request_id: str, approver: str = "OPERATOR") -> bool:
        """
        Harici olarak onay ver (web dashboard vb. için).
        
        Args:
            request_id: İstek ID'si
            approver: Onaylayan kullanıcı
            
        Returns:
            Başarılı mı?
        """
        with self._request_lock:
            request = self._pending_requests.get(request_id)
            if request and request.status == ApprovalStatus.PENDING.value:
                request.status = ApprovalStatus.APPROVED.value
                request.approved_by = approver
                request.approved_at = datetime.now().isoformat()
                self.log_decision(request)
                logger.info(f"[HITL] Request {request_id} approved by {approver}")
                return True
        return False
    
    def reject_request(self, request_id: str, reason: str, rejecter: str = "OPERATOR") -> bool:
        """
        Harici olarak reddet (web dashboard vb. için).
        
        Args:
            request_id: İstek ID'si
            reason: Reddetme nedeni
            rejecter: Reddeden kullanıcı
            
        Returns:
            Başarılı mı?
        """
        with self._request_lock:
            request = self._pending_requests.get(request_id)
            if request and request.status == ApprovalStatus.PENDING.value:
                request.status = ApprovalStatus.REJECTED.value
                request.rejected_by = rejecter
                request.rejected_at = datetime.now().isoformat()
                request.rejection_reason = reason
                self.log_decision(request)
                logger.info(f"[HITL] Request {request_id} rejected by {rejecter}: {reason}")
                return True
        return False
    
    def log_decision(self, request: ApprovalRequest) -> None:
        """
        Onay/reddetme kararını logla.
        
        Args:
            request: ApprovalRequest nesnesi
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": request.request_id,
            "operation_type": request.operation_type,
            "target": request.target,
            "risk_level": request.risk_level,
            "status": request.status,
            "approved_by": request.approved_by,
            "approved_at": request.approved_at,
            "rejected_by": request.rejected_by,
            "rejected_at": request.rejected_at,
            "rejection_reason": request.rejection_reason,
            "details": request.details
        }
        
        # Konsola yaz
        if request.status == ApprovalStatus.APPROVED.value:
            self.console.print(f"[green]✓ Approved: {request.operation_type} on {request.target}[/green]")
        elif request.status == ApprovalStatus.REJECTED.value:
            self.console.print(f"[red]✗ Rejected: {request.operation_type} on {request.target} - {request.rejection_reason}[/red]")
        elif request.status == ApprovalStatus.TIMEOUT.value:
            self.console.print(f"[yellow]⏱ Timeout: {request.operation_type} on {request.target}[/yellow]")
        
        # Dosyaya logla
        log_file = self.log_dir / f"hitl_{datetime.now().strftime('%Y%m%d')}.jsonl"
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write HITL log: {e}")
        
        # Central log
        logger.info(f"[HITL] Decision logged: {request.request_id} -> {request.status}")
    
    def _format_details(self, details: Dict) -> str:
        """Detayları formatla."""
        lines = []
        for key, value in details.items():
            if key != 'timeout':  # Timeout'u gösterme
                lines.append(f"  • {key}: {value}")
        return "\n".join(lines) if lines else "  No additional details"
    
    def get_pending_requests(self) -> list:
        """Bekleyen istekleri döndür."""
        with self._request_lock:
            return [
                r for r in self._pending_requests.values()
                if r.status == ApprovalStatus.PENDING.value
            ]
    
    def is_operation_allowed(self, operation_type: str, risk_level: str) -> bool:
        """
        İşlemin izinli olup olmadığını kontrol et.
        
        Args:
            operation_type: İşlem tipi
            risk_level: Risk seviyesi
            
        Returns:
            İzinli mi?
        """
        if not self.enabled:
            return True
        
        if self.auto_approve_low_risk and risk_level == RiskLevel.LOW.value:
            return True
        
        return False
