# Fiziksel Cihaz Entegrasyonu

Bu dizin, CyberSurX projesine entegre edilen fiziksel pentest cihazlarının kurulum ve yönetim scriptlerini içerir.

## Kopyalanan Dosyalar

### Cihaz Kurulum Scriptleri
1. **wifi-pineapple-setup.sh** - WiFi Pineapple kurulum ve yapılandırma
2. **flipper-zero-setup.sh** - Flipper Zero entegrasyonu (ana kurulum)
3. **sharktap-setup.sh** - SharkTap network tap kurulumu (ana kurulum)
4. **setup-flipper.sh** - Flipper Zero alternatif kurulum scripti
5. **setup-sharktap.sh** - SharkTap alternatif kurulum scripti

### Otomasyon ve AI
6. **ai-orchestrator.py** - 34 AI model koordinasyon sistemi
7. **pentest-cli.sh** - Ana CLI (Python wrapper için referans)
8. **pentest-pipeline.sh** - Otomasyon pipeline scripti

### Yapılandırma
9. **sharktap.conf** - SharkTap yapılandırma dosyası

## AI Orchestrator Adaptasyon Notları

### Mevcut Özellikler:
- ThreadPoolExecutor ile paralel model çalıştırma
- Ollama entegrasyonu (11 model)
- Trae (14 model), Antigravity (6), Gemini (3) desteği
- JSON çıktı formatı
- 120 saniye timeout

### Projeye Adaptasyon İçin:
1. **Path Güncellemeleri**: Çıktı dosyası yolları proje yapısına ayarlanmalı
   - Mevcut: `/Users/myz/Desktop/Zumrut2/ai_analysis.json`
   - Yeni: `/Users/mehmetzumrut/Desktop/Zumrut2/CyberSurX/data/ai_analysis.json`

2. **Modüler Yapı**: Python wrapper class olarak yeniden düzenlenecek
   - `src/ai/` modülü altına taşınacak
   - Pentest süreçleriyle entegrasyon sağlanacak

3. **Gerekli Path Düzeltmeleri**:
   - Tüm hardcoded path'ler proje bazlı relative path'lere çevrilecek
   - Config dosyasından okuma eklenecek

4. **Python Wrapper Planı**:
   - `pentest-cli.sh` -> Python'a çevrilecek
   - Device management modülü eklenecek
   - Async/await desteği eklenecek

## Python Wrapper Geliştirme Planı

```
src/
├── devices/
│   ├── __init__.py
│   ├── base_device.py       # Temel device sınıfı
│   ├── wifi_pineapple.py    # WiFi Pineapple wrapper
│   ├── flipper_zero.py      # Flipper Zero wrapper
│   └── sharktap.py          # SharkTap wrapper
├── ai/
│   ├── __init__.py
│   └── orchestrator.py      # ai-orchestrator.py adaptasyonu
└── cli/
    ├── __init__.py
    └── main.py              # pentest-cli.sh -> Python
```

## Kullanım Örneği

```python
from src.ai.orchestrator import AIOrchestrator
from src.devices.wifi_pineapple import WiFiPineapple

# AI analizi başlat
orchestrator = AIOrchestrator()
results = orchestrator.analyze_network("192.168.1.0/24")

# Cihaz kontrolü
pineapple = WiFiPineapple()
pineapple.setup()
pineapple.start_capture()
```

## Güvenlik Notları
- Tüm cihaz scriptleri root yetkisi gerektirebilir
- Yapılandırma dosyalarında hassas bilgiler şifrelenmeli
- AI API anahtarları environment variable'dan alınmalı

---
Kopyalama tarihi: $(date)
Kaynak: /Users/mehmetzumrut/Desktop/Zumrut2/toplama/
Hedef: /Users/mehmetzumrut/Desktop/Zumrut2/CyberSurX/src/devices/
