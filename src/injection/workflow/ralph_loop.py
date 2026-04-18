"""
AIG-AgentTeam Ralph Loop — Yinelemeli Geliştirme Döngüsü
ralph-loop modülünden dönüştürülmüş, Ollama Pro bağımsız implementasyon

Konsept: Aynı prompt'u tekrar tekrar gönder, her iterasyonda
önceki çalışmayı gör ve iyileştir. Ta ki tamamlanana kadar.

Güvenlik: Sadece localhost:11434, dış bağlantı yok.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from injection.utils.ollama_client import OllamaClient

logger = logging.getLogger("aig-agentteam.ralph_loop")


@dataclass
class LoopState:
    """Döngü durumu"""
    task: str
    iteration: int = 0
    max_iterations: int = 50
    completion_promise: str = "COMPLETE"
    status: str = "running"  # running, completed, failed, cancelled
    started_at: Optional[datetime] = None
    last_output: str = ""
    iterations_log: list = field(default_factory=list)

    def is_complete(self) -> bool:
        return self.completion_promise in self.last_output

    def is_max_reached(self) -> bool:
        return self.max_iterations > 0 and self.iteration >= self.max_iterations

    def to_dict(self) -> dict:
        return {
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completion_promise": self.completion_promise,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }


class RalphLoop:
    """
    Yinelemeli geliştirme döngüsü (Ralph Loop).
    
    Nasıl çalışır:
    1. Görev tanımla
    2. Modeli çalıştır → çıktıyı kaydet
    3. Çıktıda tamamlama sinyali var mı kontrol et
    4. Yoksa → çıktıyı bağlamla birlikte tekrar gönder
    5. Tekrarla → ta ki tamamlanana veya max iterasyona ulaşana kadar
    
    Her iterasyonda model önceki çalışmasını dosyalarda görür
    ve otomatik olarak iyileştirir.
    """

    def __init__(
        self,
        ollama: OllamaClient,
        config: dict | None = None,
        max_iterations: int = 50,
        completion_promise: str = "COMPLETE",
        executor_model: str = "gemini-flash",
        planner_model: str = "cogito",
        evaluator_model: str = "deepseek",
    ):
        self.ollama = ollama
        self.config = config or {}
        self.executor_model = executor_model
        self.planner_model = planner_model
        self.evaluator_model = evaluator_model
        self.state: Optional[LoopState] = None
        self._work_dir = Path(".")

    async def run(self, task: str):
        """Döngüyü başlat"""
        self.state = LoopState(
            task=task,
            max_iterations=self.config.get("ralph_loop", {}).get("default_max_iterations", 50),
            completion_promise=self.config.get("ralph_loop", {}).get("completion_promise", "COMPLETE"),
            started_at=datetime.now(),
        )
        self.state.max_iterations = self.state.max_iterations or 50

        logger.info(f"🔄 Ralph Loop başlatılıyor: {task}")
        print(f"\n🔄 Ralph Loop: {task}")
        print(f"   Model: {self.executor_model}")
        print(f"   Maks iterasyon: {self.state.max_iterations}")
        print(f"   Tamamlama sinyali: {self.state.completion_promise}")
        print()

        # Aşama 1: Plan oluştur
        await self._create_plan()

        # Aşama 2: Döngüyü çalıştır
        while self.state.status == "running":
            self.state.iteration += 1

            logger.info(f"İterasyon {self.state.iteration}/{self.state.max_iterations}")
            print(f"\n─── İterasyon {self.state.iteration}/{self.state.max_iterations} ───")

            # Yürüt
            output = await self._execute_iteration()

            # Kaydet
            self.state.last_output = output
            self.state.iterations_log.append({
                "iteration": self.state.iteration,
                "output_length": len(output),
                "timestamp": datetime.now().isoformat(),
            })

            # Tamamlama kontrolü
            if self.state.is_complete():
                self.state.status = "completed"
                print(f"\n✅ Tamamlandı! (İterasyon {self.state.iteration})")
                break

            # Maksimum kontrolü
            if self.state.is_max_reached():
                self.state.status = "completed"
                print(f"\n🛑 Maks iterasyona ulaşıldı ({self.state.max_iterations})")
                break

            # Değerlendir
            await self._evaluate_iteration()

        # Sonuç
        print(f"\n{'='*60}")
        print(f"🔄 Ralph Loop Sonucu")
        print(f"   Durum: {self.state.status}")
        print(f"   İterasyon: {self.state.iteration}")
        print(f"   Görev: {self.state.task}")
        print(f"{'='*60}")

    async def _create_plan(self):
        """Plan oluştur"""
        prompt = f"""Sen bir proje planlayıcısın. Aşağıdaki görev için detaylı bir plan oluştur:

GÖREV: {self.state.task}

Plan:
1. Alt görevlere böl
2. Her alt görev için adımlar tanımla
3. Tamamlama kriterlerini belirt
4. Olası zorlukları ve çözümleri listele
5. Öncelik sırasını belirt

Tamamlandığında şu sinyali ver: {self.state.completion_promise}

Türkçe yanıt ver."""

        plan = await self.ollama.chat(self.planner_model, prompt, temperature=0.1)
        self.state.iterations_log.append({
            "phase": "planning",
            "output": plan[:500],
        })
        print(f"📋 Plan oluşturuldu")

    async def _execute_iteration(self) -> str:
        """Tek bir iterasyon çalıştır"""
        # Önceki iterasyonların özeti
        previous_summary = ""
        if self.state.iterations_log:
            last = self.state.iterations_log[-1]
            previous_summary = f"\nÖNCEKİ İTERASYONUN SONUCU (özet): {last.get('output', '')[:500]}"

        prompt = f"""Sen bir yazılım geliştiricisisin. Aşağıdaki görev üzerinde çalış:

GÖREV: {self.state.task}
İTERASYON: {self.state.iteration}/{self.state.max_iterations}
{previous_summary}

Bu iterasyonda:
1. Önceki çalışmayı kontrol et (dosyalarda görülebilir)
2. Eksikleri tamamla
3. Hataları düzelt
4. İyileştirmeler yap
5. İlerleme kaydet

Tamamlandığında şu sinyali yaz: {self.state.completion_promise}

Türkçe açıklama, kod ise İngilizce yaz."""

        output = await self.ollama.chat(
            self.executor_model,
            prompt,
            temperature=0.3,
            max_tokens=8192,
        )

        # Çıktıyı göster
        print(f"  📝 Çıktı: {output[:200]}...")

        return output

    async def _evaluate_iteration(self):
        """İterasyon sonucunu değerlendir"""
        prompt = f"""Sen bir değerlendiricisin. Aşağıdaki görevin ilerlemesini değerlendir:

GÖREV: {self.state.task}
İTERASYON: {self.state.iteration}/{self.state.max_iterations}
SON ÇIKTI: {self.state.last_output[:1000]}

Değerlendir:
1. İlerleme yüzde kaç? (0-100%)
2. Hangi alt görevler tamamlandı?
3. Hangi engeller var?
4. Sonraki iterasyonda odaklanılması gereken nedir?
5. Tamamlama yaklaştı mı?

%100 tamamlandığında, çıktıda {self.state.completion_promise} sinyali olmalı.

Türkçe yanıt ver."""

        evaluation = await self.ollama.chat(
            self.evaluator_model,
            prompt,
            temperature=0.2,
        )

        # Değerlendirmede tamamlama sinyali varsa
        if self.state.completion_promise in evaluation:
            self.state.status = "completed"

        print(f"  📊 Değerlendirme: {evaluation[:150]}...")