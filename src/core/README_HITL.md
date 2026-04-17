# HITL (Human-in-the-Loop) Module

Bu modul, RedTeam Physical Suite icin kritik operasyonlar icin insan onayi mekanizmasi saglar.

## Ozellikler

- **Kritik Operasyon Onayi**: Exploit calistirma, fiziksel cihaz kullanimi vb. icin onay
- **Risk Tabanli Onay**: Dusuk riskli islemler otomatik onaylanabilir
- **Timeout Destegi**: Varsayilan 300 saniye onay bekleme suresi
- **Loglama**: Tum onay/reddetme kararlari loglanir
- **Dashboard Entegrasyonu**: Web arayuzu ve callback destegi
- **Asenkron/Senkron Destegi**: Her iki mod da desteklenir

## Kurulum

Modul zorunlu bagimliliklar:
- rich (console ciktisi icin)
- standart kutuphaneler (asyncio, threading, json, datetime, vb.)

## Kullanim

```python
from core.hitl import HITLApproval, RiskLevel
from core.hitl_config import HITLConfig

# HITL ayarlari ile yapilandirma
hitl_config = HITLConfig(
    enabled=True,
    timeout=300,
    auto_approve_low_risk=False,
    notification_email="security@example.com"
)

# HITL mekanizmasi olustur
hitl = HITLApproval(
    enabled=hitl_config.enabled,
    auto_approve_low_risk=hitl_config.auto_approve_low_risk,
    timeout=hitl_config.timeout,
    notification_email=hitl_config.notification_email
)

# Onay istegi olustur
request = hitl.request_approval(
    operation_type="exploit",
    target="192.168.1.1:80",
    risk_level=RiskLevel.HIGH.value,
    details={
        "vulnerability": "CVE-2023-1234",
        "exploit_module": "exploit/linux/http/cve_2023_1234"
    }
)

# Onay bekle (senkron)
result = hitl.wait_for_response(request)

if result.status == "approved":
    print("Exploit calistirilabilir!")
else:
    print(f"Exploit reddedildi: {result.rejection_reason}")
```

## Yapilandirma (config.yaml)

```yaml
hitl:
  enabled: true
  timeout: 300
  auto_approve_low_risk: false
  notification_email: "security-team@example.com"
  enable_web_notifications: false
  enable_email_notifications: false
  
  require_approval_for:
    - exploit
    - physical_device
    - credential_dump
    - persistence
    - lateral_movement
    - data_exfiltration
    - destructive_action
  
  auto_approved_operations:
    - scan
    - reconnaissance
    - information_gathering
  
  log_dir: "./logs/hitl"
  log_retention_days: 30
```

## API Referansi

### HITLApproval

Ana sinif onay mekanizmasini saglar.

#### Metodlar

- `request_approval(operation_type, target, risk_level, details=None)` - Yeni onay istegi olusturur
- `wait_for_response(request, timeout=None)` - Senkron onay bekleme
- `wait_for_response_async(request, timeout=None)` - Asenkron onay bekleme
- `approve_request(request_id, approver="OPERATOR")` - Harici onay verme
- `reject_request(request_id, reason, rejecter="OPERATOR")` - Harici reddetme
- `log_decision(request)` - Karari loglama
- `is_operation_allowed(operation_type, risk_level)` - Islem izin kontrolu

### ApprovalRequest

Onay istegi veri sinifi.

| Alan | Tip | Aciklama |
|------|-----|----------|
| request_id | str | Benzersiz istek ID'si |
| operation_type | str | Islem tipi (exploit, physical_device, vb.) |
| target | str | Hedef host/cihaz |
| risk_level | str | Risk seviyesi (low, medium, high, critical) |
| status | str | Durum (pending, approved, rejected, timeout, cancelled) |
| approved_by | str | Onaylayan kullanici |
| rejected_by | str | Reddeden kullanici |
| rejection_reason | str | Reddetme nedeni |
| details | dict | Ek detaylar |

### RiskLevel Enum

- `LOW` - Dusuk risk
- `MEDIUM` - Orta risk
- `HIGH` - Yuksek risk
- `CRITICAL` - Kritik risk

### ApprovalStatus Enum

- `PENDING` - Beklemede
- `APPROVED` - Onaylandi
- `REJECTED` - Reddedildi
- `TIMEOUT` - Zaman asimi
- `CANCELLED` - Iptal edildi

## Testler

Testleri calistir:

```bash
# Unit testler
python -m pytest src/core/tests/test_hitl.py -v

# Entegrasyon testleri
python -m pytest src/core/tests/integration/test_hitl_integration.py -v
```

## Entegrasyon

### RedTeam Master ile Entegrasyon

`redteam_master.py` artik HITL modulunu entegre sekilde kullaniyor:

```python
# Ornek: Fiziksel cihaz kullanimi onayi
if self.hitl_config.enabled:
    for device in devices:
        approval_request = self.hitl.request_approval(
            operation_type="physical_device",
            target=f"{device} on {self.target}",
            risk_level=RiskLevel.HIGH.value,
            details={...}
        )
        
        result = self.hitl.wait_for_response(approval_request)
        self.results['hitl_decisions'].append(result.to_dict())
        
        if result.status != "approved":
            return {}  # Islem iptal

```

## Dashboard Entegrasyonu (Gelecek)

Web dashboard entegrasyonu icin callback kullanimi:

```python

def dashboard_notification_callback(request: ApprovalRequest):
    # Web soket veya HTTP API cagrisi
    notify_dashboard(request)

hitl = HITLApproval(
    approval_callback=dashboard_notification_callback
)
```

Dashboard'tan harici onay/reddetme:

```python
# Dashboard API endpoint
def approve_exploit(request_id: str, user: str):
    hitl.approve_request(request_id, approver=user)

def reject_exploit(request_id: str, reason: str, user: str):
    hitl.reject_request(request_id, reason=reason, rejecter=user)
```

## Guvenlik

- `--no-hitl` flag'i ile HITL devre disi birakilabilir (DANGEROUS)
- Tum kritik kararlar loglanir
- Timeout suresi konfigure edilebilir
- Risk tabanli otomatik onay yapilandirilabilir

## Lisans

Bu modul RedTeam Physical Suite projesinin bir parcasidir.
