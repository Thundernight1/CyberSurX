"""
AIG-AgentTeam Geliştirme İş Akışı — 7-Aşamalı Özellik Geliştirme
feature-dev modülünden dönüştürülmüş, Ollama Pro bağımsız implementasyon

Orijinal: feature-dev plugin (bağımsız dönüştürme)
Dönüşüm: Ollama Pro bulut modelleriyle bağımsız çalışır
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from injection.utils.ollama_client import OllamaClient

logger = logging.getLogger("aig-agentteam.dev_workflow")


@dataclass
class DevPhase:
    """Geliştirme aşaması"""
    name: str
    description: str
    model: str
    status: str = "pending"  # pending, running, completed, failed
    output: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# 7-Aşama Geliştirme İş Akışı
DEV_PHASES = [
    DevPhase(name="discovery",    description="Gereksinim analizi ve belirsizlik giderme", model="cogito"),
    DevPhase(name="exploration",  description="Kod tabanı keşfi",                          model="qwen3.5"),
    DevPhase(name="questions",    description="Açık noktaları sorma",                      model="cogito"),
    DevPhase(name="architecture", description="Mimari tasarım",                            model="gemma4"),
    DevPhase(name="implementation", description="Uygulama",                              model="qwen3-coder"),
    DevPhase(name="review",       description="Kalite incelemesi",                         model="deepseek"),
    DevPhase(name="summary",      description="Özet ve belgeleme",                         model="cogito"),
]


class DevWorkflow:
    """
    7-aşamalı özellik geliştirme iş akışı.
    Her aşama için farklı Ollama Pro bulut modeli kullanır.
    """

    def __init__(self, ollama: OllamaClient, config: dict | None = None):
        self.ollama = ollama
        self.config = config or {}
        self.phases = [DevPhase(**{k: v for k, v in p.__dict__.items()}) for p in DEV_PHASES]
        self._context: dict = {}

    async def run(self, feature_description: str):
        """Tüm iş akışını çalıştır"""
        logger.info(f"🚀 Özellik geliştirme başlatılıyor: {feature_description}")
        print(f"\n🚀 Özellik Geliştirme: {feature_description}\n")

        self._context["feature"] = feature_description

        for i, phase in enumerate(self.phases):
            logger.info(f"📋 Aşama {i+1}/7: {phase.name}")
            print(f"\n{'─'*60}")
            print(f"📋 Aşama {i+1}/7: {phase.description}")
            print(f"   Model: {phase.model}")
            print(f"{'─'*60}")

            phase.status = "running"
            phase.started_at = datetime.now()

            try:
                result = await self._execute_phase(phase)
                phase.output = result
                phase.status = "completed"
                phase.completed_at = datetime.now()

                # Sonraki aşama için bağlamı güncelle
                self._context[f"phase_{phase.name}_result"] = result

                # Kullanıcıya göster
                print(f"\n{result[:500]}{'...' if len(result) > 500 else ''}")

            except Exception as e:
                logger.error(f"Aşama hatası ({phase.name}): {e}")
                phase.status = "failed"
                phase.output = f"Hata: {str(e)}"

        # Özet
        print(f"\n{'='*60}")
        print("✅ Özellik geliştirme tamamlandı!")
        print(f"{'='*60}")

    async def _execute_phase(self, phase: DevPhase) -> str:
        """Tek bir aşamayı çalıştır"""

        if phase.name == "discovery":
            return await self._phase_discovery(phase)
        elif phase.name == "exploration":
            return await self._phase_exploration(phase)
        elif phase.name == "questions":
            return await self._phase_questions(phase)
        elif phase.name == "architecture":
            return await self._phase_architecture(phase)
        elif phase.name == "implementation":
            return await self._phase_implementation(phase)
        elif phase.name == "review":
            return await self._phase_review(phase)
        elif phase.name == "summary":
            return await self._phase_summary(phase)
        else:
            return "Bilinmeyen aşama"

    async def _phase_discovery(self, phase: DevPhase) -> str:
        """Aşama 1: Keşif — Ne yapılacak?"""
        prompt = f"""Sen bir yazılım mimarısın. Aşağıdaki özellik talebini analiz et:

ÖZELLİK: {self._context['feature']}

Şunları yap:
1. Özelliğin ne yapacağını net bir şekilde açıkla
2. Hangi problemi çözdüğünü belirt
3. Kısıtlamaları ve gereksinimleri tanımla
4. Başarı kriterlerini listele
5. Belirsiz noktaları işaretle

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.2)

    async def _phase_exploration(self, phase: DevPhase) -> str:
        """Aşama 2: Kod tabanı keşfi"""
        prompt = f"""Sen bir kod analistiksin. Aşağıdaki özellik için mevcut kod tabanında hangi alanların önemli olduğunu analiz et:

ÖZELLİK: {self._context['feature']}

Keşif sonucu:
1. Benzer özelliklerin nasıl uygulandığını tahmin et
2. Olası mimari katmanları tanımla
3. Veri modellerini ve akışını tahmin et
4. Entegrasyon noktalarını belirle
5. Okunması gereken 5-10 dosya türü öner

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.3)

    async def _phase_questions(self, phase: DevPhase) -> str:
        """Aşama 3: Açık noktaları sorma"""
        discovery = self._context.get("phase_discovery_result", "")
        exploration = self._context.get("phase_exploration_result", "")

        prompt = f"""Sen bir proje yöneticisisin. Aşağıdaki özellik analizi ve kod keşfinden yola çıkarak:
  
ÖZELLİK: {self._context['feature']}

KEŞİF: {discovery[:1000]}

KOD ANALİZİ: {exploration[:1000]}

Şunları yap:
1. Hala belirsiz olan noktaları listele (en az 5 soru)
2. Her sorunun neden önemli olduğunu açıkla
3. Olası cevap seçeneklerini sun
4. Hangi soruların kritik olduğunu belirt
5. Bu sorular nasıl çözülmezse ne riskler var

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.2)

    async def _phase_architecture(self, phase: DevPhase) -> str:
        """Aşama 4: Mimari tasarım"""
        questions = self._context.get("phase_questions_result", "")

        prompt = f"""Sen bir üst düzey yazılım mimarısın. Aşağıdaki özellik için 3 farklı mimari yaklaşım tasarla:

ÖZELLİK: {self._context['feature']}

BELİRSİZLİKLER: {questions[:1000]}

3 yaklaşım tasarla:
1. **Minimal Yaklaşım**: En küçük değişiklik, maksimum yeniden kullanım
2. **Temiz Mimari**: Sürdürülebilirlik, zarif soyutlamalar  
3. **Pragmatik Denge**: Hız + kalite dengesi

Her yaklaşım için:
- Avantajlar ve dezavantajlar
- Dosya yapısı önerisi
- Veri akışı
- Önerilen yaklaşımı belirt ve gerekçele

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.2, max_tokens=8192)

    async def _phase_implementation(self, phase: DevPhase) -> str:
        """Aşama 5: Uygulama"""
        architecture = self._context.get("phase_architecture_result", "")

        prompt = f"""Sen bir uzman yazılım geliştiricisisin. Aşağıdaki özellik ve mimariye göre uygulama planı oluştur:

ÖZELLİK: {self._context['feature']}

MİMARİ: {architecture[:2000]}

Şunları oluştur:
1. Her dosya için kod iskeleti (sözde kod veya gerçek kod)
2. Ana sınıflar ve fonksiyonlar
3. Hata yönetimi stratejisi
4. Test yaklaşımı
5. Uygulama sırası (hangi dosya önce)

Tam çalışan kod yazmaya çalış, sadece sözde kod değil.
Türkçe açıklama, İngilizce kod."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.1, max_tokens=8192)

    async def _phase_review(self, phase: DevPhase) -> str:
        """Aşama 6: Kalite incelemesi"""
        implementation = self._context.get("phase_implementation_result", "")

        prompt = f"""Sen bir üst düzey güvenlik ve kod incelemecisisin. Aşağıdaki uygulamayı incele:

ÖZELLİK: {self._context['feature']}

UYGULAMA: {implementation[:3000]}

Şunları kontrol et:
1. **Güvenlik**: OWASP ASI 2026'ya göre güvenlik açıkları
2. **Hatalar**: Mantık hataları, null handling, yarış koşulları
3. **Kod Kalitesi**: DRY, basitlik, okunabilirlik
4. **Performans**: Darboğazlar, gereksiz işlemler
5. **Test Edilebilirlik**: Test edilebilir mi?

Her bulgu için şiddet skoru (0-100) ve onarım önerisi ver.
Sadece 80+ puanlı bulguları raporla.

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.2, max_tokens=8192)

    async def _phase_summary(self, phase: DevPhase) -> str:
        """Aşama 7: Özet"""
        review = self._context.get("phase_review_result", "")
        implementation = self._context.get("phase_implementation_result", "")
        architecture = self._context.get("phase_architecture_result", "")

        prompt = f"""Sen bir proje dokümantasyoncusun. Aşağıdaki özellik geliştirme sürecinin özetini oluştur:

ÖZELLİK: {self._context['feature']}

MİMARİ KARARLAR: {architecture[:500]}
İNCELEME SONUÇLARI: {review[:500]}

Şunları oluştur:
1. Ne yapıldığının özeti
2. Alınan mimari kararlar
3. Değiştirilmesi gereken dosyalar
4. Güvenlik bulguları (varsa)
5. Sonraki adımlar önerisi
6. Zaman çizelgesi tahmini

Türkçe yanıt ver."""

        return await self.ollama.chat(phase.model, prompt, temperature=0.2)