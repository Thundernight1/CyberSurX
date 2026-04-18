"""
AIG-AgentTeam Skill Runner — Skill Yürütücü
Her bir skill'i bağımsız olarak çalıştırır ve bulguları toplar.

Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Optional

from injection.core.models import (
    AttackMethod,
    ConversationTurn,
    ScanPhase,
    SkillName,
    SkillResult,
    Vulnerability,
)
from injection.core.models import SeverityLevel

logger = logging.getLogger("aig-agentteam.skill_runner")


class SkillRunner:
    """
    Tekil bir güvenlik test becerisini (skill) yürütür.
    Her skill için 3 aşamalı tarama yapar:
      Phase 1: Doğrudan sorgular
      Phase 2: Kaçınma/Evasion teknikleri
      Phase 3: Jailbreak/Gelişmiş teknikler
    """

    def __init__(self, skill_name: SkillName, llm_client, attack_engine=None):
        self.skill_name = skill_name
        self.llm = llm_client
        self.attack_engine = attack_engine
        self._result: Optional[SkillResult] = None
        self._phase = ScanPhase.RECON
        self._probes_sent = 0
        self._confirmed_types: set[str] = set()

    @property
    def result(self) -> Optional[SkillResult]:
        return self._result

    async def run(self, target, recon_report: dict) -> SkillResult:
        """
        Skill'i çalıştır ve bulguları topla.
        """
        start_time = time.time()
        self._result = SkillResult(
            skill_name=self.skill_name,
            target=target,
        )

        # Phase 1: Doğrudan sorgular
        logger.info(f"[{self.skill_name.value}] Phase 1: Doğrudan sorgular başlatılıyor...")
        self._phase = ScanPhase.SCAN
        await self._run_phase1(target, recon_report)
        self._result.phases_completed.append(ScanPhase.SCAN)

        # Phase 2: Kaçınma teknikleri (sadece Phase 1'de engellenen kategoriler için)
        if self._should_continue():
            logger.info(f"[{self.skill_name.value}] Phase 2: Kaçınma teknikleri başlatılıyor...")
            await self._run_phase2(target, recon_report)
            self._result.phases_completed.append(ScanPhase.REVIEW)

        # Phase 3: Gelişmiş teknikler (sadece Phase 2'de engellenen kategoriler için)
        if self._should_continue():
            logger.info(f"[{self.skill_name.value}] Phase 3: Gelişmiş teknikler başlatılıyor...")
            await self._run_phase3(target, recon_report)
            self._result.phases_completed.append(ScanPhase.REPORT)

        self._result.total_probes = self._probes_sent
        self._result.confirmed_findings = len(self._result.vulnerabilities)
        self._result.scan_duration_seconds = time.time() - start_time

        logger.info(
            f"[{self.skill_name.value}] Tarama tamamlandı: "
            f"{self._result.total_probes} probe, "
            f"{self._result.confirmed_findings} bulgu"
        )
        return self._result

    def _should_continue(self) -> bool:
        """Henüz onaylanmamış kategoriler var mı kontrol et"""
        # Her zaman Phase 2 ve 3'e geçmeyi dene
        # Gerçek implementasyonda confirmed_types ile karşılaştırılır
        return True

    async def _send_dialogue(self, target_url: str, prompt: str) -> str:
        """Hedefe bir diyalog probe'u gönder"""
        self._probes_sent += 1
        try:
            response = await self.llm.chat(target_url, prompt)
            return response
        except Exception as e:
            logger.error(f"[{self.skill_name.value}] Diyalog hatası: {e}")
            return ""

    def _add_vuln(
        self,
        title: str,
        desc: str,
        risk_type: str,
        level: SeverityLevel,
        suggestion: str,
        prompt: str,
        response: str,
        attack_method: AttackMethod = AttackMethod.RAW,
    ):
        """Bulgu ekle"""
        vuln = Vulnerability(
            title=title,
            desc=desc,
            risk_type=risk_type,
            level=level,
            suggestion=suggestion,
            conversation=[
                ConversationTurn(prompt=prompt, response=response)
            ],
            source_skill=self.skill_name,
            attack_method=attack_method,
        )
        self._result.vulnerabilities.append(vuln)
        self._confirmed_types.add(risk_type)
        logger.info(f"[{self.skill_name.value}] Bulgu eklendi: {title} ({level.value})")

    # ──────────────────────────────────────────
    # Phase yöntemleri alt sınıflar tarafından override edilir
    # ──────────────────────────────────────────

    async def _run_phase1(self, target, recon_report: dict):
        raise NotImplementedError("Subclass must implement _run_phase1")

    async def _run_phase2(self, target, recon_report: dict):
        raise NotImplementedError("Subclass must implement _run_phase2")

    async def _run_phase3(self, target, recon_report: dict):
        raise NotImplementedError("Subclass must implement _run_phase3")

    async def _generate_attack_prompt(self, base_prompt: str, method: AttackMethod) -> str:
        """Deepteam attack engine ile gelişmiş prompt üret"""
        if self.attack_engine is None:
            return base_prompt

        try:
            enhanced = await self.attack_engine.enhance(base_prompt, method)
            return enhanced
        except Exception as e:
            logger.warning(f"[{self.skill_name.value}] Attack engine hatası ({method}): {e}")
            return base_prompt