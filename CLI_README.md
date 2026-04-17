# CyberSurX RedTeam Physical Suite CLI

Modern, renkli CLI arayüzü `pentest-cli.sh` tabanlı olarak Python'a çevrildi.

## Özellikler

- ✅ Rich ile renkli tablolar ve progress bar'lar
- ✅ Typer ile modern alt komut yapısı
- ✅ ASCII art banner (pyfiglet)
- ✅ Interactive mode
- ✅ Spinner'lar ve loading göstergeleri
- ✅ Sistem durumu canlı izleme

## Kurulum

```bash
# Gerekli bağımlılıkları yükle
pip install -r requirements.txt

# VEYA editable modda kur
pip install -e .
```

## Kullanım

### Temel Komutlar

```bash
# Banner ve yardım
cybersurx --version

# Sistem durumu
cybersurx status
cybersurx status --watch

# Network taraması
cybersurx scan 192.168.1.0/24
cybersurx scan 192.168.1.0/24 -p 1-65535 --intensity 5

# Injection testleri
cybersurx inject https://hedef.com
cybersurx inject https://hedef.com --technique encoding

# Cihaz kontrolü
cybersurx device pineapple info
cybersurx device flipper enumerate
cybersurx device sharktap capture --duration 120

# Rapor oluşturma
cybersurx report --format html
cybersurx report --format json --output report.json

# Tam pipeline
cybersurx full 192.168.1.0/24
cybersurx full 192.168.1.0/24 --devices pineapple,flipper --exploit
```

### Interactive Mode

```bash
cybersurx --interactive
# VEYA sadece
cybersurx
```

Interactive mod senaryoları gösterir ve komut girmenizi sağlar.

## Komut Referansı

| Komut | Açıklama |
|-------|----------|
| `status` | Kali, Pineapple, Flipper, SharkTap durumu |
| `scan` | Nmap network taraması |
| `inject` | AI Injection testleri |
| `device` | Fiziksel cihaz kontrolü |
| `report` | Rapor oluşturma |
| `full` | Tam pipeline (scan+inject+device+report) |

## Ekran Görüntüleri

### Banner
```
   ____      _                  ____            __  _______
  / ___|   _| |__   ___ _ __   / ___|_   _ _   _\ \/ /___ /
 | |  | | | | '_ \ / _ \ '__| | |  _| | | | | | |\  /  |_ \
 | |__| |_| | |_) |  __/ |    | |_| | |_| | |_| |/  \ ___) |
  \____\__, |_.__/ \___|_|     \____|\__, |\___//_/\_\____/
       |___/                         |___/
        RedTeam Physical Security Suite
```

### Durum Tablosu
```
╔═══════════════════════════════════════════════════════════════╗
║                    🔄 SİSTEM DURUMU                           ║
╚═══════════════════════════════════════════════════════════════╝

Docker Kali:        ✅ Çalışıyor
Wi-Fi Pineapple:    ✅ Bağlı (172.16.42.1)
Flipper Zero:       ✅ USB'de tanımlandı
SharkTap:           ✅ Interface bulundu
```

## Bağımlılıklar

- `typer>=0.9.0` - CLI framework
- `rich>=13.0.0` - Görsel output
- `pyfiglet>=1.0.0` - ASCII art

## Hazır Senaryolar

CLI içinde 4 hazır senaryo bulunur:

1. **Wi-Fi AUDIT** - Aircrack-ng + Pineapple
2. **MAN-IN-THE-MIDDLE** - Bettercap + SharkTap
3. **RFID/NFC PENTEST** - Flipper Zero
4. **COMPLIANCE AUTOMATION** - SOC2/HIPAA/NIST

## Lisans

MIT License - CyberSurX
