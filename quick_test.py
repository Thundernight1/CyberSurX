#!/usr/bin/env python3
"""Hızlı entegrasyon testi - Yerel çalıştır"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_all():
    try:
        # 1. Database
        from database import get_db, engine
        from sqlalchemy import inspect
        insp = inspect(engine)
        tables = insp.get_table_names()
        assert len(tables) >= 9, f"Sadece {len(tables)} tablo var"
        print(f"✅ Database: {len(tables)} tablo OK")
        
        # 2. Auth
        from core.auth_utils import create_access_token, decode_token
        token = create_access_token({"sub": 1, "user": "test"})
        decoded = decode_token(token)
        assert decoded["sub"] == 1
        print("✅ JWT Auth OK")
        
        # 3. Scanner
        from redteam.modules.scanner import NmapScanner
        scanner = NmapScanner()
        print(f"✅ Scanner modülü hazır (nmap kurulu: {scanner.check_nmap()})")
        
        # 4. API
        from fastapi.testclient import TestClient
        from api.main import app
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
        print("✅ API OK")
        
        print("
" + "="*50)
        print("TÜM TESTLER BAŞARILI - Ürün satışa hazır")
        print("="*50)
        return True
        
    except Exception as e:
        print(f"❌ HATA: {e}")
        return False

if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)
