#!/bin/bash
# SharkTap Setup
echo "[+] SharkTap kurulumu..."

# SharkTap pasif dinleme için
sudo apt-get install -y -qq tcpdump tshark wireshark

# SharkTap interface tespiti
SHARK_IF="eth1"
echo "interface=$SHARK_IF" > /workspace/sharktap.conf

echo "[+] SharkTap hazir. Pasif dinleme baslatilabilir."
