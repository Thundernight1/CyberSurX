"""
AIG-AgentTeam Rapor Oluşturucu
Markdown, XML ve JSON formatlarında güvenlik raporu oluşturur

Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from injection.core.models import ScanReport, SeverityLevel, Vulnerability
from injection.reports.owasp_classifier import OWASPClassifier


class Reporter:
    """
    Güvenlik tarama raporu oluşturucu.
    Markdown, XML ve JSON formatlarında rapor üretir.
    """

    def __init__(self, classifier: Optional[OWASPClassifier] = None):
        self.classifier = classifier or OWASPClassifier()

    def generate_markdown(self, report: ScanReport) -> str:
        """Markdown formatında detaylı rapor"""
        lines = [
            "# 🔒 AIG-AgentTeam Güvenlik Tarama Raporu",
            "",
            f"**Hedef**: {report.target.url}",
            f"**Tarama Tarihi**: {report.scan_started_at}",
            f"**Genel Şiddet**: {report.overall_severity.value if report.overall_severity else 'Yok'}",
            f"**Toplam Bulgular**: {report.total_vulnerabilities}",
            "",
        ]

        # OWASP ASI Sınıflandırma Özeti
        asi_summary = self.classifier.generate_asi_summary(report)
        if asi_summary:
            lines.append("## 📊 OWASP ASI 2026 Sınıflandırma Özeti")
            lines.append("")
            lines.append("| ASI Kodu | Risk Adı | Bulgular | Critical | High | Medium | Low |")
            lines.append("|----------|----------|----------|----------|------|--------|-----|")
            for asi_id, data in asi_summary.items():
                sd = data["severity_distribution"]
                lines.append(
                    f"| {asi_id} | {data['name']} | {len(data['findings'])} | "
                    f"{sd['Critical']} | {sd['High']} | {sd['Medium']} | {sd['Low']} |"
                )
            lines.append("")

        # Her skill için bulgular
        for result in report.results:
            if not result.vulnerabilities:
                continue

            lines.append(f"## 🔍 {result.skill_name.value}")
            lines.append(f"**Probes**: {result.total_probes} | **Bulgular**: {result.confirmed_findings}")
            lines.append("")

            for vuln in result.vulnerabilities:
                lines.append(f"### {vuln.title}")
                lines.append(f"- **Şiddet**: {vuln.level.value}")
                lines.append(f"- **ASI**: {vuln.risk_type}")
                lines.append(f"- **Saldırı Yöntemi**: {vuln.attack_method.value if vuln.attack_method else 'N/A'}")
                lines.append(f"- **Onarım**: {vuln.suggestion}")
                lines.append("")
                lines.append(vuln.desc)
                lines.append("")

                # Kanıt zinciri
                if vuln.conversation:
                    lines.append("**Kanıt Zinciri**:")
                    lines.append("")
                    for turn in vuln.conversation:
                        lines.append(f"> **Prompt**: `{turn.prompt[:200]}{'...' if len(turn.prompt) > 200 else ''}`")
                        lines.append(f"> **Yanıt**: `{turn.response[:200]}{'...' if len(turn.response) > 200 else ''}`")
                        lines.append("")
                lines.append("---")
                lines.append("")

        # Öneriler ve yol haritası
        lines.append("## 🗺️ Onarım Yol Haritası")
        lines.append("")
        lines.append("Öncelik sırasına göre öneriler:")
        lines.append("")

        all_vulns = []
        for result in report.results:
            all_vulns.extend(result.vulnerabilities)

        severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]
        for severity in severity_order:
            matching = [v for v in all_vulns if v.level == severity]
            if matching:
                lines.append(f"### {severity.value}")
                for v in matching:
                    lines.append(f"- [{v.risk_type}] {v.title}: {v.suggestion}")
                lines.append("")

        lines.append("---")
        lines.append(f"*Rapor oluşturulma tarihi: {datetime.now().isoformat()}*")
        lines.append(f"*AIG-AgentTeam v2.0.0 — Tencent Zhuque Lab*")

        return "\n".join(lines)

    def generate_xml(self, report: ScanReport) -> str:
        """XML formatında rapor (OWASP ASI uyumlu)"""
        return report.to_xml()

    def generate_json(self, report: ScanReport) -> str:
        """JSON formatında rapor"""
        data = {
            "scan_report": {
                "target": report.target.url,
                "overall_severity": report.overall_severity.value if report.overall_severity else None,
                "total_vulnerabilities": report.total_vulnerabilities,
                "scan_started_at": report.scan_started_at.isoformat() if report.scan_started_at else None,
                "scan_completed_at": report.scan_completed_at.isoformat() if report.scan_completed_at else None,
                "owasp_classification": report.owasp_classification,
                "results": [],
            }
        }

        for result in report.results:
            result_data = {
                "skill": result.skill_name.value,
                "total_probes": result.total_probes,
                "confirmed_findings": result.confirmed_findings,
                "scan_duration_seconds": result.scan_duration_seconds,
                "errors": result.errors,
                "vulnerabilities": [],
            }
            for vuln in result.vulnerabilities:
                result_data["vulnerabilities"].append({
                    "title": vuln.title,
                    "desc": vuln.desc,
                    "risk_type": vuln.risk_type,
                    "level": vuln.level.value,
                    "suggestion": vuln.suggestion,
                    "source_skill": vuln.source_skill.value,
                    "attack_method": vuln.attack_method.value if vuln.attack_method else None,
                    "conversation": [
                        {"prompt": t.prompt, "response": t.response}
                        for t in vuln.conversation
                    ],
                })
            data["scan_report"]["results"].append(result_data)

        return json.dumps(data, indent=2, ensure_ascii=False)

    def generate_summary(self, report: ScanReport) -> str:
        """Kısa özet rapor"""
        severity_counts = {s.value: 0 for s in SeverityLevel}
        for result in report.results:
            for vuln in result.vulnerabilities:
                severity_counts[vuln.level.value] += 1

        asi_summary = self.classifier.generate_asi_summary(report)

        lines = [
            f"🔒 AIG-AgentTeam Tarama Özeti",
            f"{'='*40}",
            f"Hedef: {report.target.url}",
            f"Genel Şiddet: {report.overall_severity.value if report.overall_severity else 'Yok'}",
            f"Toplam Bulgular: {report.total_vulnerabilities}",
            f"  Critical: {severity_counts['Critical']}",
            f"  High: {severity_counts['High']}",
            f"  Medium: {severity_counts['Medium']}",
            f"  Low: {severity_counts['Low']}",
            f"",
            f"OWASP ASI Kapsamı:",
        ]

        for asi_id, data in asi_summary.items():
            lines.append(f"  {asi_id}: {data['name']} — {len(data['findings'])} bulgu")

        return "\n".join(lines)