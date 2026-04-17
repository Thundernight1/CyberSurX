# AIG-AgentTeam Injection Test Modules

Bu modüller AIG-AgentTeam projesinden entegre edilmiş prompt injection test araçlarıdır.

## Modül Yapısı

```
src/injection/
├── scanners/                   # Ana tarama motorları
│   ├── base_scanner.py        # Temel tarayıcı sınıfı (3 aşamalı tarama)
│   ├── indirect_injection_scanner.py  # Dolaylı prompt enjeksiyonu tespiti
│   ├── tool_abuse_scanner.py  # Araç kötüye kullanımı tespiti
│   └── data_leakage_scanner.py # Hassas bilgi sızıntısı tespiti
│
├── attacks/                    # Saldırı motorları
│   ├── attack_engine.py       # Ana saldırı motoru (3 aşama)
│   ├── judge.py               # Zafiyet değerlendirme motoru
│   ├── encoding/              # Encoding tabanlı teknikler (10+ yöntem)
│   │   ├── base64_enc.py
│   │   ├── caesar.py
│   │   ├── leetspeak.py
│   │   ├── ascii_smuggling.py
│   │   └── ...
│   └── single_turn/           # StrataSword teknikleri
│       ├── acrostic_poem.py
│       ├── character_split.py
│       ├── stego.py
│       └── ...
│
├── skills/                     # Skill tanımlamaları
│   ├── indirect-injection-detection/SKILL.md
│   ├── tool-abuse-detection/SKILL.md
│   └── data-leakage-detection/SKILL.md
│
├── config/
│   └── ollama_models.yaml     # Model yapılandırması
│
├── data/
│   └── owasp_asi.json         # OWASP ASI sınıflandırması
│
└── injection-rapor.json       # Örnek rapor yapısı
```

## Özellikler

### 1. Tarayıcılar (Scanners)

#### IndirectInjectionScanner
- **OWASP ASI**: ASI01 (Agent Goal Hijack), ASI06 (Memory & Context Poisoning)
- **3 Aşama Tarama**:
  - Phase 1: Temel enjeksiyon (Document, RAG, Web)
  - Phase 2: Encoding/Steganografik enjeksiyon
  - Phase 3: Multi-turn güven oluşturma

#### ToolAbuseScanner
- **OWASP ASI**: ASI02, ASI05, ASI03, ASI07
- **Test Türleri**: Command Injection, Path Traversal, SSRF, Code Execution

#### DataLeakageScanner
- **OWASP ASI**: ASI06, ASI07, ASI01, ASI03
- **Test Türleri**: System Prompt Disclosure, Credential Leakage, PII Exposure

### 2. Saldırı Teknikleri

#### Encoding Methods (10+)
- `base64`: Base64 encoding
- `caesar`: Caesar cipher
- `leetspeak`: Leetspeak substitution
- `ascii_smuggling`: Unicode tag characters
- `a1z26`: A=1, B=2 encoding
- `mirror`: Reversed text
- `affine`: Affine cipher
- `vaporwave`: Vaporwave style
- `ogham`: Ogham script
- `zalgo`: Zalgo text

#### StrataSword Techniques
- `acrostic_poem`: Akrostiş şiir
- `character_split`: Karakter bölme
- `contradictory`: Çelişkili talimatlar
- `opposing`: Zıt yönlü
- `shuffle`: Karıştırma
- `long_text`: Uzun metin
- `code_attack`: Kod üzerinden saldırı
- `drattack`: Çift saldırı
- `script_template`: Senaryo şablonu

### 3. OWASP ASI Uyumluluk Matrisi

| Test Modülü | ASI01 | ASI02 | ASI03 | ASI05 | ASI06 | ASI07 |
|-------------|-------|-------|-------|-------|-------|-------|
| IndirectInjection | ✅ | - | - | - | ✅ | - |
| ToolAbuse | - | ✅ | ✅ | ✅ | - | ✅ |
| DataLeakage | ✅ | - | ✅ | - | ✅ | ✅ |

## Kullanım Örneği

```python
from src.injection.scanners.indirect_injection_scanner import IndirectInjectionScanner
from src.injection.scanners.tool_abuse_scanner import ToolAbuseScanner
from src.injection.scanners.data_leakage_scanner import DataLeakageScanner
from src.injection.attacks.attack_engine import AttackEngine

# Tarayıcılar
scanner1 = IndirectInjectionScanner(llm_client, attack_engine, config)
scanner2 = ToolAbuseScanner(llm_client, attack_engine, config)
scanner3 = DataLeakageScanner(llm_client, attack_engine, config)

# Tarama çalıştırma
result = await scanner1.run(target, recon_report)
```

## Rapor Formatı

```json
{
  "timestamp": "2026-04-09T10:19:13.431096",
  "target": "http://localhost:11434",
  "total_probes": 20,
  "total_vulnerabilities": 9,
  "findings": [
    {
      "attack_type": "direct",
      "vulnerability_type": "injection",
      "is_vulnerable": true,
      "confidence": 0.95,
      "owasp": "ASI-03",
      "evidence": "Exact match found: 'pwned' in response",
      "response_snippet": "..."
    }
  ]
}
```

## Lisans

Apache License 2.0 - Copyright (c) 2024-2026 Tencent Zhuque Lab