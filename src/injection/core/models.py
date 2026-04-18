"""
AIG-AgentTeam Veri Modelleri
OWASP ASI 2026 sınıflandırma entegrasyonu ile bulgu ve rapor modelleri
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────
# Enumlar
# ──────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    """Bulgu şiddet seviyeleri"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ScanPhase(str, Enum):
    """Tarama aşamaları"""
    RECON = "recon"
    ASSESS = "assess"
    SCAN = "scan"
    REVIEW = "review"
    REPORT = "report"


class SkillName(str, Enum):
    """Beceri isimleri"""
    DATA_LEAKAGE = "data-leakage-detection"
    INDIRECT_INJECTION = "indirect-injection-detection"
    TOOL_ABUSE = "tool-abuse-detection"


class AttackMethod(str, Enum):
    """Deepteam saldırı yöntemleri"""
    RAW = "raw"
    ENCODING = "encoding"
    STEGO = "stego"
    STRATASWORD = "stratasword"
    MULTI_TURN = "multi_turn"


class OWASPASI(str, Enum):
    """OWASP Top 10 for Agentic Applications 2026"""
    ASI01 = "ASI01 — Agent Goal Hijack"
    ASI02 = "ASI02 — Tool Misuse & Exploitation"
    ASI03 = "ASI03 — Identity & Privilege Abuse"
    ASI04 = "ASI04 — Agentic Supply Chain"
    ASI05 = "ASI05 — Unexpected Code Execution"
    ASI06 = "ASI06 — Memory & Context Poisoning"
    ASI07 = "ASI07 — Insecure Inter-Agent Comm"
    ASI08 = "ASI08 — Cascading Failures"
    ASI09 = "ASI09 — Human-Agent Trust Exploit"
    ASI10 = "ASI10 — Rogue Agents"


# ──────────────────────────────────────────────────────────────
# Veri Modelleri
# ──────────────────────────────────────────────────────────────

class ConversationTurn(BaseModel):
    """Tek bir diyalog turu"""
    prompt: str = Field(..., description="Gönderilen test prompt'u")
    response: str = Field(..., description="AJ'ın yanıtı")
    timestamp: Optional[datetime] = None


class Vulnerability(BaseModel):
    """Tespit edilen güvenlik açığı"""
    title: str = Field(..., description="Kısa açıklayıcı başlık")
    desc: str = Field(..., description="Detaylı açıklama (Markdown)")
    risk_type: str = Field(..., description="OWASP ASI sınıflandırması (ör: ASI06: Context Data Leakage)")
    level: SeverityLevel = Field(..., description="Şiddet seviyesi")
    suggestion: str = Field(..., description="Onarım önerisi")
    conversation: list[ConversationTurn] = Field(
        default_factory=list, description="Kanıt diyalogları"
    )
    source_skill: SkillName = Field(..., description="Hangi skill tarafından tespit edildi")
    attack_method: Optional[AttackMethod] = Field(
        None, description="Kullanılan saldırı yöntemi"
    )
    detected_at: datetime = Field(default_factory=datetime.now)

    def to_xml(self) -> str:
        """OWASP ASI uyumlu XML çıktısı"""
        conv_xml = ""
        for turn in self.conversation:
            conv_xml += f"\n    <turn><prompt>{turn.prompt}</prompt><response>{turn.response}</response></turn>"
        return f"""<vuln>
  <title>{self.title}</title>
  <desc>{self.desc}</desc>
  <risk_type>{self.risk_type}</risk_type>
  <level>{self.level.value}</level>
  <suggestion>{self.suggestion}</suggestion>
  <conversation>{conv_xml}
  </conversation>
</vuln>"""


class ScanTarget(BaseModel):
    """Tarama hedefi"""
    url: str = Field(..., description="Hedef ajan URL'si")
    name: Optional[str] = None
    description: Optional[str] = None
    capabilities: list[str] = Field(
        default_factory=list,
        description="Hedefin yetenekleri (file_access, code_exec, rag, vb.)"
    )


class SkillResult(BaseModel):
    """Tek bir skill tarama sonucu"""
    skill_name: SkillName
    target: ScanTarget
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    phases_completed: list[ScanPhase] = Field(default_factory=list)
    total_probes: int = 0
    confirmed_findings: int = 0
    scan_duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0


class ScanReport(BaseModel):
    """Birleşik güvenlik tarama raporu"""
    target: ScanTarget
    results: list[SkillResult] = Field(default_factory=list)
    overall_severity: Optional[SeverityLevel] = None
    total_vulnerabilities: int = 0
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    owasp_classification: dict[str, list[str]] = Field(
        default_factory=dict, description="OWASP ASI → bulgu haritası"
    )

    def add_result(self, result: SkillResult):
        """Skill sonucu ekle"""
        self.results.append(result)
        self.total_vulnerabilities += len(result.vulnerabilities)
        self._update_severity()
        self._update_owasp_classification(result)

    def _update_severity(self):
        """Genel şiddet seviyesini güncelle"""
        if any(v.level == SeverityLevel.CRITICAL for r in self.results for v in r.vulnerabilities):
            self.overall_severity = SeverityLevel.CRITICAL
        elif any(v.level == SeverityLevel.HIGH for r in self.results for v in r.vulnerabilities):
            self.overall_severity = SeverityLevel.HIGH
        elif any(v.level == SeverityLevel.MEDIUM for r in self.results for v in r.vulnerabilities):
            self.overall_severity = SeverityLevel.MEDIUM
        elif any(v.level == SeverityLevel.LOW for r in self.results for v in r.vulnerabilities):
            self.overall_severity = SeverityLevel.LOW
        else:
            self.overall_severity = SeverityLevel.INFO

    def _update_owasp_classification(self, result: SkillResult):
        """OWASP ASI sınıflandırmasını güncelle"""
        for vuln in result.vulnerabilities:
            asi_id = vuln.risk_type.split(":")[0].strip() if ":" in vuln.risk_type else vuln.risk_type
            if asi_id not in self.owasp_classification:
                self.owasp_classification[asi_id] = []
            self.owasp_classification[asi_id].append(vuln.title)

    def to_xml(self) -> str:
        """Tam XML rapor"""
        vulns_xml = "\n".join(v.to_xml() for r in self.results for v in r.vulnerabilities)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<scan-report>
  <target>{self.target.url}</target>
  <overall-severity>{self.overall_severity.value if self.overall_severity else 'None'}</overall-severity>
  <total-vulnerabilities>{self.total_vulnerabilities}</total-vulnerabilities>
  <scan-started>{self.scan_started_at}</scan-started>
  <scan-completed>{self.scan_completed_at}</scan-completed>
  <owasp-classification>
{json.dumps(self.owasp_classification, indent=4, ensure_ascii=False)}
  </owasp-classification>
  <vulnerabilities>
{vulns_xml}
  </vulnerabilities>
</scan-report>"""

    def to_markdown(self) -> str:
        """Markdown formatında rapor"""
        lines = [
            f"# 🔒 AIG-AgentTeam Güvenlik Tarama Raporu",
            f"",
            f"**Hedef**: {self.target.url}",
            f"**Genel Şiddet**: {self.overall_severity.value if self.overall_severity else 'Yok'}",
            f"**Toplam Bulgular**: {self.total_vulnerabilities}",
            f"",
            f"## OWASP ASI 2026 Sınıflandırması",
            f"",
        ]
        for asi_id, vulns in self.owasp_classification.items():
            lines.append(f"### {asi_id}")
            for v in vulns:
                lines.append(f"- {v}")
            lines.append("")

        lines.append("## Bulgular")
        lines.append("")
        for result in self.results:
            for v in result.vulnerabilities:
                lines.append(f"### {v.title}")
                lines.append(f"- **Şiddet**: {v.level.value}")
                lines.append(f"- **ASI**: {v.risk_type}")
                lines.append(f"- **Kaynak Skill**: {v.source_skill.value}")
                lines.append(f"- **Onarım**: {v.suggestion}")
                lines.append("")
                for turn in v.conversation:
                    lines.append(f"> **Prompt**: {turn.prompt}")
                    lines.append(f"> **Yanıt**: {turn.response[:200]}...")
                    lines.append("")

        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# OWASP ASI → Skill Haritası
# ──────────────────────────────────────────────────────────────

SKILL_ASI_MAP: dict[SkillName, list[OWASPASI]] = {
    SkillName.DATA_LEAKAGE: [
        OWASPASI.ASI06,
        OWASPASI.ASI07,
        OWASPASI.ASI01,
        OWASPASI.ASI03,
    ],
    SkillName.INDIRECT_INJECTION: [
        OWASPASI.ASI01,
        OWASPASI.ASI06,
    ],
    SkillName.TOOL_ABUSE: [
        OWASPASI.ASI02,
        OWASPASI.ASI05,
        OWASPASI.ASI07,
        OWASPASI.ASI03,
    ],
}

# Yetenek → Skill haritası
CAPABILITY_SKILL_MAP: dict[str, list[SkillName]] = {
    "file_access": [SkillName.TOOL_ABUSE],
    "code_exec": [SkillName.TOOL_ABUSE],
    "network": [SkillName.TOOL_ABUSE],
    "database": [SkillName.TOOL_ABUSE],
    "rag": [SkillName.INDIRECT_INJECTION],
    "file_upload": [SkillName.INDIRECT_INJECTION],
    "web_fetch": [SkillName.INDIRECT_INJECTION],
    "roles": [SkillName.DATA_LEAKAGE],
    "user_data": [SkillName.DATA_LEAKAGE],
    "admin_functions": [SkillName.DATA_LEAKAGE],
}

# Her hedef için varsayılan: en azından data-leakage uygulanabilir
DEFAULT_SKILLS = [SkillName.DATA_LEAKAGE]