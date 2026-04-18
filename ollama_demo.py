#!/usr/bin/env python3
"""Ollama Integration Demo - CyberSurX + Local LLM"""

import sys
sys.path.insert(0, "src")

from integrations.ollama_client import OllamaClient

def main():
    print("="*60)
    print("CyberSurX + Ollama Entegrasyon Demo")
    print("="*60)
    
    client = OllamaClient()
    
    # Test 1: Ollama kontrol
    print("
[1/4] Ollama kontrol ediliyor...")
    if client.check_ollama():
        print("✅ Ollama çalışıyor")
        models = client.list_models()
        print(f"   Modeller: {', '.join(models) if models else 'Hiç yok'}")
    else:
        print("❌ Ollama çalışmıyor")
        print("   Komut: ollama serve")
        return
    
    # Test 2: Zafiyet analizi
    print("
[2/4] LLM ile zafiyet analizi...")
    scan_results = {
        "id": 1,
        "scan_type": "port_scan",
        "target": "192.168.1.1",
        "findings": [
            {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 7.4"},
            {"port": 80, "state": "open", "service": "http", "version": "nginx 1.18"}
        ]
    }
    
    analysis = client.analyze_vulnerability(scan_results)
    if analysis["status"] == "success":
        print("✅ Analiz tamamlandı")
        print(f"   Model: {analysis['model']}")
        print(f"   Sonuç: {analysis['analysis'][:200]}...")
    else:
        print(f"❌ Hata: {analysis['error']}")
    
    # Test 3: Payload oluşturma
    print("
[3/4] Test payloadı oluşturuluyor...")
    payload = client.generate_exploit_payload(
        "SQL Injection",
        {"host": "test.local", "port": 80, "service": "mysql"}
    )
    if payload["status"] == "success":
        print("✅ Payload oluşturuldu")
        print(f"   Tip: {payload['payload_type']}")
        print(f"   Payload: {payload['payload'][:100]}...")
    else:
        print(f"❌ Hata: {payload['error']}")
    
    # Test 4: Rapor oluşturma
    print("
[4/4] Rapor oluşturuluyor...")
    report = client.generate_report(
        {"findings": [{"severity": "high", "type": "sqli"}]},
        "executive"
    )
    if report["status"] == "success":
        print("✅ Rapor oluşturuldu")
        print(f"   Tip: {report['type']}")
        print(f"   İçerik: {report['report'][:150]}...")
    else:
        print(f"❌ Hata: {report['error']}")
    
    print("
" + "="*60)
    print("Demo tamamlandı!")
    print("="*60)

if __name__ == "__main__":
    main()
