"""
AIG-AgentTeam OWASP ASI Sınıflandırıcı
Bulguları OWASP Top 10 for Agentic Applications 2026'ya göre sınıflandırır

Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from injection.core.models import OWASPASI, SeverityLevel, Vulnerability, ScanReport


# ──────────────────────────────────────────────────────────────
# OWASP ASI 2026 Sınıflandırma Verisi
# ──────────────────────────────────────────────────────────────

OWASP_ASI_CATEGORIES = {
    "ASI01": {
        "name": "Agent Goal Hijack",
        "description": "Prompt injection, instruction override, goal manipulation",
        "severity_base": "High",
        "key_indicators": [
            "prompt injection", "instruction override", "goal manipulation",
            "indirect injection", "goal hijack",
        ],
    },
    "ASI02": {
        "name": "Tool Misuse & Exploitation",
        "description": "Unauthorized tool calls, parameter tampering, unvalidated inputs",
        "severity_base": "High",
        "key_indicators": [
            "unauthorized tool call", "parameter tampering",
            "unvalidated input", "tool misuse", "ssrf",
        ],
    },
    "ASI03": {
        "name": "Identity & Privilege Abuse",
        "description": "Auth bypass, permission escalation, missing authorization",
        "severity_base": "High",
        "key_indicators": [
            "auth bypass", "permission escalation", "missing authorization",
            "privilege escalation",
        ],
    },
    "ASI04": {
        "name": "Agentic Supply Chain",
        "description": "Malicious dependencies, compromised tools, package poisoning",
        "severity_base": "Critical",
        "key_indicators": [
            "malicious dependency", "compromised tool", "package poisoning",
        ],
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "description": "RCE, command injection, code evaluation",
        "severity_base": "Critical",
        "key_indicators": [
            "RCE", "command injection", "code evaluation",
            "shell injection", "code exec",
        ],
    },
    "ASI06": {
        "name": "Memory & Context Poisoning",
        "description": "Data leakage, context manipulation, memory corruption",
        "severity_base": "High",
        "key_indicators": [
            "data leakage", "context manipulation", "memory corruption",
            "prompt leakage", "credential exposure",
        ],
    },
    "ASI07": {
        "name": "Insecure Inter-Agent Comm",
        "description": "Unencrypted channels, data exposure between agents",
        "severity_base": "Medium",
        "key_indicators": [
            "unencrypted", "data exposure", "inter-agent",
            "PII exposure",
        ],
    },
    "ASI08": {
        "name": "Cascading Failures",
        "description": "Error propagation, chain reaction vulnerabilities",
        "severity_base": "Medium",
        "key_indicators": [
            "error propagation", "chain reaction", "cascading failure",
        ],
    },
    "ASI09": {
        "name": "Human-Agent Trust Exploit",
        "description": "Social engineering, deceptive responses",
        "severity_base": "Medium",
        "key_indicators": [
            "social engineering", "deceptive", "trust exploit",
        ],
    },
    "ASI10": {
        "name": "Rogue Agents",
        "description": "Malicious agent behavior, unauthorized actions",
        "severity_base": "Critical",
        "key_indicators": [
            "malicious behavior", "unauthorized action", "rogue",
        ],
    },
}

# Bulgı türü → OWASP ASI haritası
FINDING_TYPE_ASI_MAP = {
    "System Prompt Disclosure": ("ASI06", "ASI01"),
    "Credential Leakage": ("ASI06", "ASI07"),
    "API Key Exposure": ("ASI06", "ASI03"),
    "PII Exposure": ("ASI07", "ASI06"),
    "Environment Variable Exposure": ("ASI06",),
    "Internal Configuration Exposure": ("ASI06", "ASI04"),
    "Indirect Prompt Injection": ("ASI01", "ASI06"),
    "Goal Hijack": ("ASI01",),
    "Command Injection": ("ASI05", "ASI02"),
    "Path Traversal": ("ASI02", "ASI05"),
    "SSRF": ("ASI02", "ASI05"),
    "SQL Injection": ("ASI02", "ASI05"),
    "Tool Misuse": ("ASI02", "ASI03"),
    "Unauthorized Access": ("ASI03", "ASI09"),
    "Privilege Escalation": ("ASI03",),
}

# Skill → OWASP ASI haritası
SKILL_ASI_MAP = {
    "data-leakage-detection": ["ASI06", "ASI07", "ASI01", "ASI03"],
    "indirect-injection-detection": ["ASI01", "ASI06"],
    "tool-abuse-detection": ["ASI02", "ASI05", "ASI07", "ASI03"],
}

# Severity calibration matrix
SEVERITY_MATRIX = {
    "Critical": {
        "description": "Tam özel anahtar ifşası, üretim kimlik bilgileri, uzaktan kod yürütme onayı",
        "action": "24 saat içinde acil onarım",
    },
    "High": {
        "description": "Sınırlı kapsamlı API anahtarları, kimlik doğrulama token'ları, sistem prompt ifşası",
        "action": "1 hafta içinde acil onarım",
    },
    "Medium": {
        "description": "Yapılandırma detayları, dahili uç noktalar, şartlı istismar yolları",
        "action": "2-4 hafta içinde onarım",
    },
    "Low": {
        "description": "Genel sistem bilgileri, hassas olmayan yapılandırmalar",
        "action": "Zaman olduğunda gözden geçir",
    },
}


class OWASPClassifier:
    """
    OWASP ASI 2026 sınıflandırıcı.
    Bulguları OWASP ASI kategorilerine ve şiddet seviyelerine göre sınıflandırır.
    """

    def __init__(self, data_path: Optional[str] = None):
        self.categories = OWASP_ASI_CATEGORIES
        self.finding_map = FINDING_TYPE_ASI_MAP
        self.severity_matrix = SEVERITY_MATRIX

        if data_path:
            self._load_custom_data(data_path)

    def classify(self, vuln: Vulnerability) -> dict:
        """
        Bir bulguyu OWASP ASI sınıflandırmasına göre sınıflandırır.

        Returns:
            Sınıflandırma sonucu sözlüğü
        """
        # risk_type'dan ASI kodunu çıkar
        asi_ids = self._extract_asi_ids(vuln.risk_type)

        # Bulgu türü haritasından ek ASI kodlarını al
        finding_asi = self.finding_map.get(vuln.title, ())

        # Birleştir
        all_asi_ids = list(dict.fromkeys(list(asi_ids) + list(finding_asi)))

        # Her ASI kodu için kategori bilgisini al
        categories = []
        for asi_id in all_asi_ids:
            clean_id = asi_id.strip()
            if clean_id in self.categories:
                cat = self.categories[clean_id]
                categories.append({
                    "id": clean_id,
                    "name": cat["name"],
                    "description": cat["description"],
                    "severity_base": cat["severity_base"],
                })

        # Şiddet seviyesi detaylarını al
        severity_info = self.severity_matrix.get(vuln.level.value, {})

        return {
            "vuln_title": vuln.title,
            "risk_type": vuln.risk_type,
            "level": vuln.level.value,
            "asi_classifications": categories,
            "severity_detail": severity_info,
            "source_skill": vuln.source_skill.value,
        }

    def classify_report(self, report: ScanReport) -> list[dict]:
        """Bir rapordaki tüm bulguları sınıflandırır"""
        results = []
        for result in report.results:
            for vuln in result.vulnerabilities:
                results.append(self.classify(vuln))
        return results

    def generate_asi_summary(self, report: ScanReport) -> dict:
        """
        OWASP ASI sınıflandırma özetini oluşturur.
        Her ASI kodu için bulgu sayısını ve şiddet dağılımını gösterir.
        """
        summary = {}
        for result in report.results:
            for vuln in result.vulnerabilities:
                classification = self.classify(vuln)
                for asi_cat in classification["asi_classifications"]:
                    asi_id = asi_cat["id"]
                    if asi_id not in summary:
                        summary[asi_id] = {
                            "name": asi_cat["name"],
                            "description": asi_cat["description"],
                            "findings": [],
                            "severity_distribution": {
                                "Critical": 0, "High": 0, "Medium": 0, "Low": 0
                            },
                        }
                    summary[asi_id]["findings"].append({
                        "title": vuln.title,
                        "level": vuln.level.value,
                        "skill": vuln.source_skill.value,
                    })
                    summary[asi_id]["severity_distribution"][vuln.level.value] += 1

        return dict(sorted(summary.items()))

    def _extract_asi_ids(self, risk_type: str) -> tuple:
        """Risk türünden ASI kodlarını çıkarır"""
        asi_ids = []
        parts = risk_type.split(",")
        for part in parts:
            part = part.strip()
            if part.startswith("ASI"):
                asi_id = part.split(":")[0].strip() if ":" in part else part
                asi_ids.append(asi_id)
            elif part in self.categories:
                asi_ids.append(part)
        return tuple(asi_ids)

    def _load_custom_data(self, path: str):
        """Özel OWASP ASI verisi yükle"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "categories" in data:
                    self.categories.update(data["categories"])
                if "finding_map" in data:
                    self.finding_map.update(data["finding_map"])
        except Exception as e:
            import logging
            logging.getLogger("aig-agentteam.owasp").warning(f"Özel veri yükleme hatası: {e}")