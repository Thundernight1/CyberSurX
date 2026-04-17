#!/bin/bash
# SharkTap Pasif Dinleme Kurulumu

echo "[+] SharkTap kurulumu..."

# Interface tespiti
SHARK_IF="eth1"
echo "[*] Varsayılan interface: $SHARK_IF"

# Konfigürasyon dosyası
mkdir -p /etc/sharktap
cat > /etc/sharktap/config << EOF
INTERFACE=$SHARK_IF
MODE=pasif
OUTPUT_DIR=/workspace/captures
EOF

# Capture dizini
mkdir -p /workspace/captures

# SharkTap başlatma scripti
cat > /usr/local/bin/sharktap-start << 'EOF'
#!/bin/bash
IFACE=${1:-eth1}
FILE=${2:-/workspace/captures/capture_$(date +%Y%m%d_%H%M%S).pcap}

echo "[+] SharkTap başlatılıyor: $IFACE"
echo "[+] Çıkış: $FILE"

tcpdump -i $IFACE -w $FILE -s 65535 -C 100 -W 10
echo "[+] Capture kaydedildi: $FILE"
EOF
chmod +x /usr/local/bin/sharktap-start

echo ""
echo "=== SharkTap Komutları ==="
echo "Başlat:             sharktap-start [interface] [dosya]"
echo "Canlı izle:         tshark -i eth1"
echo "PCAP oku:           tshark -r capture.pcap"
echo "Wireshark GUI:      wireshark &"
echo ""
