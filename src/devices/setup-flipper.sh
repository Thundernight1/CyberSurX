#!/bin/bash
# Flipper Zero + Wi-Fi Board Kurulumu

echo "[+] Flipper Zero kurulumu başlıyor..."

# USB cihaz kontrolü
echo "[*] USB cihazları tarama..."
lsusb | grep -i flipper || echo "[!] Flipper USB'de görünmüyor"

# qFlipper CLI
if [ ! -f "/usr/local/bin/qFlipper" ]; then
    echo "[+] qFlipper CLI indiriliyor..."
    curl -sL https://update.flipperzero.com/latest/qFlipper.dmg -o /tmp/qFlipper.dmg
    echo "[*] Manuel kurulum için: /tmp/qFlipper.dmg"
fi

# Flipper Python SDK
pip3 install --quiet flipperzero-toolchain 2>/dev/null || echo "[*] flipperzero-toolchain pip ile kurulacak"

# Wi-Fi Board için araçlar
echo "[+] Wi-Fi Board araçları..."
pip3 install --quiet marauder-flipper 2>/dev/null || true

echo ""
echo "=== Flipper Komutları ==="
echo "Cihaz bilgisi:      qFlipper info"
echo "Firmware güncelle:  qFlipper flash \u003cfirmware\u003e"
echo "Dosya transfer:     qFlipper file \u003clocal\u003e \u003cremote\u003e"
echo ""
echo "Wi-Fi Board (Marauder):"
echo "  Scan:             marauder-flipper -s"
echo "  Deauth:           marauder-flipper -d \u003cbssid\u003e"
echo "  Probe:            marauder-flipper -p"
