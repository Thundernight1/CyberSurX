#!/usr/bin/env python3
"""CyberSurX Basit Test - Fiziksel cihaz yok, sadece yazılım"""

import sys
import json
sys.path.insert(0, "src")

print("="*60)
print("CyberSurX Yazılım Testi")
print("="*60)

tests_passed = 0
tests_failed = 0

# Test 1: Database bağlantısı
print("\n[1/5] Database test...")
try:
    from database import engine
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"   ✅ Database bağlı - {len(tables)} tablo")
    print(f"      Tablolar: {', '.join(tables[:5])}...")
    tests_passed += 1
except Exception as e:
    print(f"   ❌ Hata: {e}")
    tests_failed += 1

# Test 2: JWT Auth
print("\n[2/5] JWT Authentication test...")
try:
    from core.auth_utils import create_access_token, decode_token
    token = create_access_token({"user_id": 1, "username": "test"})
    decoded = decode_token(token)
    assert decoded["user_id"] == 1
    print(f"   ✅ JWT çalışıyor")
    print(f"      Token: {token[:50]}...")
    tests_passed += 1
except Exception as e:
    print(f"   ❌ Hata: {e}")
    tests_failed += 1

# Test 3: API App
print("\n[3/5] FastAPI test...")
try:
    from fastapi.testclient import TestClient
    from api.main import app
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print(f"   ✅ API çalışıyor - /health OK")
    tests_passed += 1
except Exception as e:
    print(f"   ❌ Hata: {e}")
    tests_failed += 1

# Test 4: Scanner modülü
print("\n[4/5] Scanner modülü test...")
try:
    from redteam.modules.scanner import NmapScanner
    scanner = NmapScanner()
    nmap_available = scanner.check_nmap()
    print(f"   ✅ Scanner modülü yüklü")
    print(f"      Nmap kurulu: {'Evet' if nmap_available else 'Hayır (opsiyonel)'}")
    tests_passed += 1
except Exception as e:
    print(f"   ❌ Hata: {e}")
    tests_failed += 1

# Test 5: Injection modülü
print("\n[5/5] Injection test modülü...")
try:
    from injection.scanners.web_vuln_scanner import WebVulnerabilityScanner
    scanner = WebVulnerabilityScanner()
    payloads = len(scanner.SQLI_PAYLOADS)
    print(f"   ✅ Injection modülü yüklü")
    print(f"      SQLi payload sayısı: {payloads}")
    tests_passed += 1
except Exception as e:
    print(f"   ❌ Hata: {e}")
    tests_failed += 1

# Özet
print("\n" + "="*60)
print(f"SONUÇ: {tests_passed} başarılı, {tests_failed} başarısız")
print("="*60)

if tests_passed == 5:
    print("\n✅ TÜM TESTLER BAŞARILI")
    print("\nYazılım hazır. Fiziksel cihazları (Pineapple, Flipper, SharkTap)")
    print("daha sonra entegre edebilirsin.")
    sys.exit(0)
else:
    print("\n❌ Bazı testler başarısız")
    sys.exit(1)
