#!/bin/bash  
# Flipper Zero Setup
echo "[+] Flipper Zero kurulumu..."

# qFlipper CLI
if [ ! -f "/usr/local/bin/qFlipper" ]; then
    echo "[+] qFlipper indiriliyor..."
    curl -sL https://update.flipperzero.com/latest/qFlipper.dmg -o /tmp/qFlipper.dmg
    # macOS'ta mount edip kurulum yapilacak
fi

# Flipper CLI tools
curl -sL https://raw.githubusercontent.com/flipperdevices/flipperzero-toolchain/main/install.sh | bash

echo "[+] Flipper Zero hazir."
