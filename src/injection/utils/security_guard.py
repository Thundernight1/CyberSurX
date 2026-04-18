"""
AIG-AgentTeam Security Guard — Gerçek Zamanlı Güvenlik Uyarı Kancası
security-guidance modülünden dönüştürülmüş bağımsız implementasyon

Dosya düzenleme sırasında güvenlik açığı kalıplarını tespit eder.
Model gerektirmez — tamamen kural tabanlı.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aig-agentteam.security_guard")


# ──────────────────────────────────────────────────────────────
# Güvenlik Kural Tanımları
# ──────────────────────────────────────────────────────────────

@dataclass
class SecurityRule:
    """Güvenlik kuralı"""
    name: str
    description: str
    severity: str  # critical, high, medium, low
    patterns: list[str]
    path_patterns: list[str] | None = None
    advice: str = ""


SECURITY_RULES = [
    SecurityRule(
        name="eval_injection",
        description="eval() ve new Function() kod enjeksiyonu riski",
        severity="critical",
        patterns=["eval(", "new Function", "exec(", "execSync("],
        advice="""
⚠️ KRİTİK: eval() ve new Function() rasgele kod çalıştırabilir.
- Veri ayrıştırma için JSON.parse() kullanın
- Dinamik kod çalıştırma için güvenli alternatifler arayın
- Kullanıcı girdisini asla eval()'e göndermeyin""",
    ),
    SecurityRule(
        name="command_injection",
        description="Sistem komutu enjeksiyonu riski",
        severity="critical",
        patterns=[
            "child_process.exec", "child_process.execSync",
            "os.system", "os.popen",
            "subprocess.call", "subprocess.Popen",
            "subprocess.run(shell=True",
        ],
        advice="""
⚠️ KRİTİK: Sistem komutları enjeksiyon açığı oluşturabilir.
- exec() yerine execFile() kullanın
- shell=True kullanmayın
- Kullanıcı girdisini asla komut parametresi olarak göndermeyin
- Tüm girdileri sanitize edin""",
    ),
    SecurityRule(
        name="xss",
        description="XSS (Cross-Site Scripting) riski",
        severity="high",
        patterns=[
            "dangerouslySetInnerHTML", ".innerHTML =", ".innerHTML=",
            "document.write", "v-html=", "[innerHTML]",
        ],
        advice="""
⚠️ YÜKSEK: XSS açığı tespit edildi.
- innerHTML yerine textContent kullanın
- HTML gerekirse DOMPurify gibi sanitizer kullanın
- React'te dangerouslySetInnerHTML'den kaçının""",
    ),
    SecurityRule(
        name="sql_injection",
        description="SQL enjeksiyonu riski",
        severity="high",
        patterns=[
            "raw_query(", "execute_sql(", "cursor.execute(f",
            ".raw(", "string concatenation in SQL",
        ],
        advice="""
⚠️ YÜKSEK: SQL enjeksiyonu riski tespit edildi.
- Her zaman parametrik sorgular kullanın
- String birleştirme ile SQL oluşturmayın
- ORM kullanıyorsanız raw query'den kaçının""",
    ),
    SecurityRule(
        name="deserialization",
        description="Güvensiz deserialization riski",
        severity="critical",
        patterns=[
            "pickle.loads", "pickle.load(",
            "yaml.load(unsafe", "yaml.unsafe_load",
            "marshal.loads",
        ],
        advice="""
⚠️ KRİTİK: Deserialization açığı tespit edildi.
- pickle yerine JSON kullanın
- yaml.load() yerine yaml.safe_load() kullanın
- Güvenilmeyen veriyi asla deserialize etmeyin""",
    ),
    SecurityRule(
        name="github_actions",
        description="GitHub Actions workflow enjeksiyonu",
        severity="high",
        patterns=[],  # path_patterns ile eşleşir
        path_patterns=[".github/workflows/"],
        advice="""
⚠️ YÜKSEK: GitHub Actions workflow dosyası düzenleniyor.
- ${{ github.event.issue.title }} gibi ifadeleri run:'da kullanmayın
- Environment variable olarak aktarın
- Detaylı rehber: https://github.blog/security/vulnerability-research/""",
    ),
    SecurityRule(
        name="path_traversal",
        description="Dosya yol geçişi riski",
        severity="high",
        patterns=[
            "../../../", "..\\..\\..\\",
            "open(user_input", "read_file(user_input",
            "send_file(user_input",
        ],
        advice="""
⚠️ YÜKSEK: Path traversal riski tespit edildi.
- Dosya yollarını normalize edin
- Allowlist ile sınırlayın
- ../ ve ..\\ dizilerini filtreleyin""",
    ),
    SecurityRule(
        name="hardcoded_secrets",
        description="Sabit kodlanmış gizli anahtarlar",
        severity="high",
        patterns=[
            "api_key=", "api_key =",
            "password=", "password =",
            "secret_key=", "secret_key =",
            "AKIA", "ghp_",
            "AKIA",  # AWS access key prefix
        ],
        advice="""
⚠️ YÜKSEK: Sabit kodlanmış gizli anahtar tespit edildi.
- API anahtarlarını environment variable olarak tutun
- .env dosyalarını .gitignore'a ekleyin
- Asla koda doğrudan yazmayın""",
    ),
]


class SecurityGuard:
    """
    Gerçek zamanlı güvenlik gözeticisi.
    Dosya değişikliklerini izler ve güvenlik açığı kalıplarını tespit eder.
    Model gerektirmez — tamamen kural tabanlı.
    """

    def __init__(self, rules: list[SecurityRule] | None = None):
        self.rules = rules or SECURITY_RULES
        self._warnings_shown: set[str] = set()  # Tekrar uyarılarını önle

    def check_file(self, file_path: str, content: str) -> list[dict]:
        """
        Bir dosyayı güvenlik kurallarıyla kontrol et.

        Args:
            file_path: Dosya yolu
            content: Dosya içeriği

        Returns:
            Uyarı listesi (boş ise güvenli)
        """
        warnings = []

        for rule in self.rules:
            # Yol kalıbı kontrolü
            if rule.path_patterns:
                path_match = any(
                    pattern in file_path for pattern in rule.path_patterns
                )
                if path_match and not rule.patterns:
                    warning_key = f"{file_path}:{rule.name}"
                    if warning_key not in self._warnings_shown:
                        self._warnings_shown.add(warning_key)
                        warnings.append({
                            "rule": rule.name,
                            "severity": rule.severity,
                            "description": rule.description,
                            "file": file_path,
                            "advice": rule.advice,
                        })

            # İçerik kalıbı kontrolü
            if rule.patterns:
                for pattern in rule.patterns:
                    if pattern in content:
                        warning_key = f"{file_path}:{rule.name}:{pattern}"
                        if warning_key not in self._warnings_shown:
                            self._warnings_shown.add(warning_key)
                            warnings.append({
                                "rule": rule.name,
                                "severity": rule.severity,
                                "description": rule.description,
                                "file": file_path,
                                "pattern": pattern,
                                "line": self._find_line(content, pattern),
                                "advice": rule.advice,
                            })
                            break  # Aynı kural için bir uyarı yeterli

        return warnings

    def check_diff(self, diff_content: str) -> list[dict]:
        """
        Bir git diff çıktısını kontrol et.
        Sadece eklenen satırları (+' ile başlayan) kontrol eder.
        """
        warnings = []
        added_lines = []

        for line in diff_content.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        added_content = "\n".join(added_lines)

        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern in added_content:
                    warnings.append({
                        "rule": rule.name,
                        "severity": rule.severity,
                        "description": rule.description,
                        "pattern": pattern,
                        "advice": rule.advice,
                    })
                    break

        return warnings

    def _find_line(self, content: str, pattern: str) -> int:
        """Kalıbın bulunduğu satır numarasını döndür"""
        for i, line in enumerate(content.split("\n"), 1):
            if pattern in line:
                return i
        return -1

    def format_warning(self, warning: dict) -> str:
        """Uyarıyı okunabilir formata dönüştür"""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }
        emoji = severity_emoji.get(warning.get("severity", ""), "⚪")
        lines = [
            f"\n{emoji} GÜVENLİK UYARISI [{warning['severity'].upper()}]",
            f"   Kural: {warning['rule']}",
            f"   Açıklama: {warning['description']}",
        ]
        if "file" in warning:
            lines.append(f"   Dosya: {warning['file']}")
        if "line" in warning and warning["line"] > 0:
            lines.append(f"   Satır: {warning['line']}")
        if "pattern" in warning:
            lines.append(f"   Kalıp: {warning['pattern']}")
        if warning.get("advice"):
            lines.append(f"   {warning['advice']}")
        return "\n".join(lines)

    def reset_session(self):
        """Oturum uyarılarını sıfırla"""
        self._warnings_shown.clear()