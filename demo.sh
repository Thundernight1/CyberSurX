#!/bin/bash
# CyberSurX Yerel Demo - 3 Adımda Çalıştır

echo "=== CyberSurX Yerel Demo ==="
echo ""

# Adım 1: Bağımlılıkları kur
echo "[1/3] Bağımlılıklar yükleniyor..."
pip install -q sqlalchemy fastapi uvicorn python-jose[cryptography] passlib bcrypt requests python-nmap typer rich pydantic

# Adım 2: Database oluştur
echo "[2/3] Database oluşturuluyor..."
cd src
python init_db.py

# Adım 3: API başlat
echo "[3/3] API başlatılıyor..."
echo ""
echo "✅ TAMAM! API çalışıyor:"
echo "   http://localhost:8000/docs"
echo ""
echo "Test komutları:"
echo "  curl http://localhost:8000/health"
echo "  curl -X POST "http://localhost:8000/api/v1/auth/register?username=demo\&email=demo@test.com\&password=12345678""
echo ""

python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
