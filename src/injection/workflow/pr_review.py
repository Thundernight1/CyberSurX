"""
AIG-AgentTeam PR İnceleme — 6 Uzman Ajanla İnceleme
pr-review-toolkit modülünden dönüştürülmüş, Ollama Pro bağımsız implementasyon

6 Ajan:
1. Comment Analyzer — Yorum doğruluğu
2. Test Analyzer — Test kapsamı
3. Silent Failure Hunter — Sessiz hatalar
4. Type Design Analyzer — Tip tasarımı
5. Code Reviewer — Genel kalite
6. Code Simplifier — Sadeleştirme
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from injection.utils.ollama_client import OllamaClient

logger = logging.getLogger("aig-agentteam.pr_review")


# ──────────────────────────────────────────────────────────────
# Ajan Tanımları
# ──────────────────────────────────────────────────────────────

@dataclass
class ReviewAgent:
    """İnceleme ajanı tanımı"""
    name: str
    model: str
    focus: str
    system_prompt: str


REVIEW_AGENTS = [
    ReviewAgent(
        name="comment_analyzer",
        model="qwen3.5",
        focus="Yorum doğruluğu ve sürdürülebilirliği",
        system_prompt="""Sen bir kod yorum analizcisisin. Kod yorumlarını analiz et:
1. Yorumlar koda göre doğru mu?
2. Eksik dokümantasyon var mı?
3. Güncelliğini yitirmiş yorumlar var mı?
4. Misleading yorumlar var mı?
Her bulgu için dosya:satır referansı ve düzeltme önerisi ver. Türkçe yanıt ver.""",
    ),
    ReviewAgent(
        name="test_analyzer",
        model="qwen3-coder",
        focus="Test kapsamı ve kalitesi",
        system_prompt="""Sen bir test kapsamı analistiksin. Test kalitesini değerlendir:
1. Kritik yollar test ediliyor mu?
2. Edge case'ler kapsanıyor mu?
3. Hata senaryoları test ediliyor mu?
4. Testler dayanıklı mı (refactoring'e karşı)?
Her boşluk için kritiklik skoru (1-10) ver. Sadece 7+ olanları raporla. Türkçe yanıt ver.""",
    ),
    ReviewAgent(
        name="silent_failure_hunter",
        model="nemotron-3",
        focus="Sessiz hatalar ve yetersiz hata yönetimi",
        system_prompt="""Sen bir hata yönetimi denetçisisin. Sessiz hataları avla:
1. catch blokları hatayı yutuyor mu?
2. Hata mesajları eyleme dönük mü?
3. Fallback davranışları kullanıcıyı yanıltıyor mu?
4. Hatalar yeterince loglanıyor mu?
Sıfır tolerans — her sessiz hata kritik. Türkçe yanıt ver.""",
    ),
    ReviewAgent(
        name="type_design_analyzer",
        model="minimax-m2.7",
        focus="Tip tasarımı ve değişmezler",
        system_prompt="""Sen bir tip tasarımı uzmanısın. Tip tasarımını analiz et:
1. Kapsülleme (1-10)
2. Değişmez ifadesi (1-10)
3. Kullanışlılık (1-10)
4. Değişmez zorlama (1-10)
Her boyut için gerekçe ve geliştirme önerisi ver. Türkçe yanıt ver.""",
    ),
    ReviewAgent(
        name="code_reviewer",
        model="deepseek",
        focus="Genel kod kalitesi ve güvenlik",
        system_prompt="""Sen bir üst düzey kod incelemecisisin. Kodu güvenlik ve kalite açısından incele:
1. OWASP ASI 2026 güvenlik açıkları
2. Mantık hataları ve bug'lar
3. Kod kalitesi (DRY, basitlik, okunabilirlik)
4. Proje standartlarına uyum
Her bulgu için güven skoru (0-100) ver. Sadece 80+ olanları raporla. Türkçe yanıt ver.""",
    ),
    ReviewAgent(
        name="code_simplifier",
        model="qwen3-coder",
        focus="Kod sadeleştirme ve refactoring",
        system_prompt="""Sen bir kod sadeleştirme uzmanısın. Kodu daha okunabilir hale getir:
1. Gereksiz karmaşıklık var mı?
2. Daha net ifade edilebilir yerler var mı?
3. Tekrar eden kod blokları var mı?
4. Over-engineering var mı?
İşlevselliği koruyarak sadeleştirme öner. Türkçe yanıt ver.""",
    ),
]


class PRReviewer:
    """
    PR inceleme sistemi. 6 uzman ajanla kapsamlı inceleme yapar.
    Her ajan farklı bir Ollama Pro bulut modeli kullanır.
    """

    def __init__(self, ollama: OllamaClient, config: dict | None = None):
        self.ollama = ollama
        self.config = config or {}

    async def run(self, path: str):
        """Tüm inceleme ajanlarını çalıştır"""
        logger.info(f"📋 PR incelemesi başlatılıyor: {path}")
        print(f"\n📋 PR İncelemesi: {path}\n")

        # Kodu topla
        code_content = await self._collect_code(path)

        if not code_content:
            logger.warning("İncelenecek kod bulunamadı")
            print("⚠️ İncelenecek kod bulunamadı")
            return

        # Tüm ajanları paralel çalıştır
        tasks = []
        for agent in REVIEW_AGENTS:
            tasks.append(self._run_agent(agent, code_content))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Sonuçları birleştir
        print(f"\n{'='*60}")
        print("📊 PR İnceleme Sonuçları")
        print(f"{'='*60}")

        for agent, result in zip(REVIEW_AGENTS, results):
            if isinstance(result, Exception):
                print(f"\n❌ {agent.name}: Hata — {result}")
            else:
                print(f"\n✅ {agent.name} ({agent.model}):")
                print(f"   {result[:300]}{'...' if len(result) > 300 else ''}")

    async def _run_agent(self, agent: ReviewAgent, code: str) -> str:
        """Tek bir inceleme ajanını çalıştır"""
        prompt = f"""{agent.focus}

Aşağıdaki kodu incele:

```
{code[:8000]}
```

{agent.system_prompt}"""

        return await self.ollama.chat(
            agent.model,
            prompt,
            system=agent.system_prompt,
            temperature=0.2,
            max_tokens=4096,
        )

    async def _collect_code(self, path: str) -> str:
        """Verilen yoldaki kod dosyalarını topla"""
        from pathlib import Path

        code_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb"}
        code_content = []
        root = Path(path)

        if not root.exists():
            return ""

        for ext in code_extensions:
            for file in root.rglob(f"*{ext}"):
                # Test ve node_modules dışla
                if "node_modules" in str(file) or "__pycache__" in str(file):
                    continue
                try:
                    content = file.read_text(encoding="utf-8", errors="ignore")
                    code_content.append(f"# --- {file} ---\n{content}")
                    # Maksimum 100KB
                    if sum(len(c) for c in code_content) > 100000:
                        break
                except Exception:
                    continue

        return "\n\n".join(code_content)