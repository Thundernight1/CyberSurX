"""
AIG-AgentTeam — Kırmızı/Mavi/Mor Takım AI Güvenlik Test Platformu
Ollama Pro bulut modelleriyle bağımsız çalışır

Kullanım:
    # Tam kırmızı takım taraması
    python -m src.main --target http://localhost:3000

    # Sadece veri sızıntısı taraması
    python -m src.main --target http://localhost:3000 --skill data_leakage

    # Sadece enjeksiyon taraması
    python -m src.main --target http://localhost:3000 --skill injection

    # Model listesi
    python -m src.main --list-models

    # Bağlantı testi
    python -m src.main --health-check
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import yaml

from injection.attacks.attack_engine import AttackEngine, ScanSession
from injection.utils.ollama_client import OllamaClient, OllamaConfig, OllamaTargetClient, OLLAMA_MODELS

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("aig-agentteam")
logger.setLevel(logging.INFO)
# httpx loglarını sustur
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def parse_args():
    parser = argparse.ArgumentParser(
        description="AIG-AgentTeam — AI Güvenlik Test Platformu (Kırmızı/Mavi/Mor Takım)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  python -m src.main --target http://localhost:3000\n"
            "  python -m src.main --target http://localhost:3000 --skill data_leakage\n"
            "  python -m src.main --target http://localhost:3000 --mode full\n"
            "  python -m src.main --list-models\n"
        ),
    )

    # Gerekli
    parser.add_argument("--target", "-t", help="Hedef AJ URL (ör: http://localhost:3000)")

    # Tarama modu
    parser.add_argument("--mode", "-m", choices=["full", "quick", "stealth"],
                        default="full",
                        help="Tarama modu: full (3 faz), quick (sadece faz 1), stealth (yavaş)")

    # Zafiyet türü
    parser.add_argument("--skill", "-s",
                        choices=["data_leakage", "injection", "tool_abuse"],
                        help="Sadece bu zafiyet türünü tara (varsayılan: hepsi)")

    # Çıktı
    parser.add_argument("--output", "-o", help="Rapor dosyası (JSON)")
    parser.add_argument("--output-md", help="Rapor dosyası (Markdown)")

    # Model ayarları
    parser.add_argument("--attack-model", default="kimi-k2.5",
                        help="Saldırı üretim modeli (varsayılan: kimi-k2.5)")
    parser.add_argument("--judge-model", default="deepseek",
                        help="Zafiyet değerlendirme modeli (varsayılan: deepseek)")
    parser.add_argument("--target-model", default="",
                        help="Hedef model adı (boş=bilinmiyor)")

    # Ollama bağlantı
    parser.add_argument("--ollama-url", default="https://ollama.com",
                        help="Ollama API URL")
    parser.add_argument("--api-key", help="Ollama Pro API key")

    # Utility
    parser.add_argument("--local", action="store_true", help="🏠 LOKAL MOD: Sadece yerel modeller, veri dışarı çıkmaz (şirketler için güvenli)")
    parser.add_argument("--cloud", action="store_true", help="☁️ CLOUD MOD: Bulut modeller kullanır (daha güçlü ama veri gönderir)")
    parser.add_argument("--list-models", action="store_true", help="Modelleri listele")
    parser.add_argument("--health-check", action="store_true", help="Bağlantı testi")
    parser.add_argument("--verbose", "-v", action="store_true", help="Detaylı log")
    parser.add_argument("--max-probes", type=int, default=5, help="Faz başına maksimum sorgu")

    return parser.parse_args()


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔴 AIG-AgentTeam — Kırmızı/Mavi/Mor Takım Platformu     ║
║   Ollama Pro Bulut · Bağımsız · OWASP ASI 2026             ║
║                                                              ║
║   3 Zafiyet Türü × 3 Faz × 19 Saldırı Tekniği             ║
║   Kırmızı takım saldırısından mavi takım savunmasına        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def print_session_report(session: ScanSession):
    """Tarama oturumu raporunu yazdır"""
    vulns = [f for f in session.findings if f.is_vulnerable and not f.is_false_positive]
    fps = [f for f in session.findings if f.is_vulnerable and f.is_false_positive]
    safe = [f for f in session.findings if not f.is_vulnerable]

    print("\n" + "=" * 70)
    print("📊 TARAMA RAPORU")
    print("=" * 70)
    print(f"\n🎯 Hedef: {session.target_url}")
    print(f"📡 Toplam sorgu: {session.total_probes}")
    print(f"🔴 Zafiyet bulgu: {len(vulns)}")
    print(f"🟡 Hatalı pozitif: {len(fps)}")
    print(f"🟢 Güvenli yanıt: {len(safe)}")

    if vulns:
        print(f"\n{'─'*70}")
        print("🔴 ZAFİYET BULGULARI:")
        print(f"{'─'*70}")
        for i, v in enumerate(vulns, 1):
            conf = "🔴" if v.confidence >= 0.8 else "🟡"
            print(f"\n  {conf} BULGU #{i}: {v.vulnerability_type.upper()}")
            print(f"     Teknik:     {v.attack_type}")
            print(f"     OWASP:     {v.owasp_mapping}")
            print(f"     Güven:     {v.confidence:.0%}")
            print(f"     Kanıt:     {v.evidence[:200]}")
            if v.target_response:
                resp = v.target_response[:200].replace('\n', ' ')
                print(f"     Yanıt:     {resp}...")

    # Zafiyet türüne göre özet
    by_type = {}
    for v in session.findings:
        t = v.vulnerability_type
        if t not in by_type:
            by_type[t] = {"total": 0, "vuln": 0, "max_conf": 0}
        by_type[t]["total"] += 1
        if v.is_vulnerable:
            by_type[t]["vuln"] += 1
            by_type[t]["max_conf"] = max(by_type[t]["max_conf"], v.confidence)

    print(f"\n{'─'*70}")
    print("📋 ZAFİYET ÖZETİ:")
    print(f"{'─'*70}")
    for vtype, stats in by_type.items():
        icon = "🔴" if stats["vuln"] > 0 else "🟢"
        print(f"  {icon} {vtype:20s} | Sorgu: {stats['total']} | Bulgu: {stats['vuln']} | Max güven: {stats['max_conf']:.0%}")

    print(f"\n{'='*70}\n")


async def run_scan(args, ollama: OllamaClient):
    """Ana tarama fonksiyonu"""
    target_url = args.target

    print(f"\n🔴 Hedef: {target_url}")
    print(f"📡 Saldırı modeli: {args.attack_model}")
    print(f"🔍 Değerlendirme modeli: {args.judge_model}")
    print(f"⚡ Mod: {args.mode}")
    if args.skill:
        print(f"🎯 Yetenek: {args.skill}")
    print()

    # Target client — hedef AJ'a sorular gönderir
    target_client = OllamaTargetClient(config=ollama.config)
    
    # Attack engine
    engine = AttackEngine(
        ollama_client=ollama,
        target_client=target_client,
        target_url=target_url,
    )
    engine.judge_model = args.judge_model
    engine.attack_model = args.attack_model

    # Tam tarama
    session = await engine.run_full_scan(target_url)

    # Rapor
    print_session_report(session)

    # JSON raporu
    if args.output:
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "target": session.target_url,
            "total_probes": session.total_probes,
            "total_vulnerabilities": session.total_vulnerabilities,
            "findings": [
                {
                    "attack_type": f.attack_type,
                    "vulnerability_type": f.vulnerability_type,
                    "is_vulnerable": f.is_vulnerable,
                    "confidence": f.confidence,
                    "owasp": f.owasp_mapping,
                    "evidence": f.evidence,
                    "response_snippet": f.target_response[:300],
                }
                for f in session.findings
            ],
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as fp:
            json.dump(report_data, fp, indent=2, ensure_ascii=False)
        print(f"📁 JSON raporu kaydedildi: {args.output}")

    # Markdown raporu
    if args.output_md:
        md = generate_markdown_report(session)
        Path(args.output_md).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_md, "w") as fp:
            fp.write(md)
        print(f"📁 Markdown raporu kaydedildi: {args.output_md}")

    await target_client.close()


def generate_markdown_report(session: ScanSession) -> str:
    lines = [
        "# AIG-AgentTeam Güvenlik Tarama Raporu",
        f"\n**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Hedef:** {session.target_url}",
        f"**Toplam Sorgu:** {session.total_probes}",
        f"**Zafiyet Bulgu:** {session.total_vulnerabilities}\n",
    ]

    vulns = [f for f in session.findings if f.is_vulnerable]
    if vulns:
        lines.append("## 🔴 Zafiyet Bulguları\n")
        for i, v in enumerate(vulns, 1):
            lines.append(f"### {i}. {v.vulnerability_type.upper()} ({v.owasp_mapping})\n")
            lines.append(f"- **Teknik:** {v.attack_type}")
            lines.append(f"- **Güven:** {v.confidence:.0%}")
            lines.append(f"- **Kanıt:** {v.evidence[:300]}")
            lines.append(f"- **Yanıt:** {v.target_response[:300]}\n")

    safe = [f for f in session.findings if not f.is_vulnerable]
    lines.append(f"\n## 🟢 Güvenli Yanıtlar: {len(safe)}\n")

    return "\n".join(lines)


async def main():
    args = parse_args()
    print_banner()

    # Ollama bağlantısı
    from dotenv import load_dotenv
    load_dotenv()
    
    config = OllamaConfig.from_env()
    if args.api_key:
        config.api_key = args.api_key
    if args.ollama_url:
        config.base_url = args.ollama_url

    ollama = OllamaClient(config=config)

    # Health check
    if args.health_check:
        healthy = await ollama.health_check()
        if healthy:
            print("✅ Ollama çalışıyor ve erişilebilir")
        else:
            print("❌ Ollama erişilemiyor — API key ve URL'yi kontrol et")
        await ollama.close()
        return

    # Model listesi
    if args.list_models:
        print("\n🧠 Kullanılabilir Modeller:\n")
        print("  🏠 LOKAL (veri dışarı çıkmaz — şirketler için güvenli):\n")
        for key, info in OLLAMA_MODELS.items():
            if info.get("local"):
                print(f"    {key:20s}  {info['id']:45s}  {info['desc']}")
        print("\n  ☁️ CLOUD (daha güçlü ama veri gönderir — dikkatli olun):\n")
        for key, info in OLLAMA_MODELS.items():
            if not info.get("local"):
                print(f"    {key:20s}  {info['id']:45s}  {info['desc']}")
        print()
        await ollama.close()
        return

    # Tarama gerekli
    if not args.target:
        print("❌ Hedef URL gerekli! Kullanım:")
        print("   python -m src.main --target http://localhost:3000")
        print("   python -m src.main --target http://localhost:3000 --mode quick")
        await ollama.close()
        sys.exit(1)

    # Taramayı çalıştır
    await run_scan(args, ollama)
    await ollama.close()


if __name__ == "__main__":
    asyncio.run(main())