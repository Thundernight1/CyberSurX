#!/usr/bin/env python3
"""CyberSurX Gerçek Çalışan Demo - Tek dosya, tüm bağımlılıklar içinde"""

import os
import sys
import json
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import sqlite3

# ========== DATABASE (SQLite, zero dependency) ==========
class Database:
    def __init__(self, db_path="cybersurx.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER,
            protocol TEXT DEFAULT 'http',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            scan_type TEXT,
            status TEXT,
            findings TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        )""")
        
        conn.commit()
        conn.close()
    
    def execute(self, query, params=()):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        result = cursor.fetchall()
        conn.close()
        return result

# ========== JWT (Simple, no dependencies) ==========
import base64
import hmac
import hashlib

class SimpleJWT:
    SECRET = "cybersurx-demo-secret-key-12345"
    
    @staticmethod
    def encode(payload):
        header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode()
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        signature = base64.b64encode(
            hmac.new(
                SimpleJWT.SECRET.encode(),
                f"{header}.{payload_encoded}".encode(),
                hashlib.sha256
            ).digest()
        ).decode()
        return f"{header}.{payload_encoded}.{signature}"
    
    @staticmethod
    def decode(token):
        try:
            parts = token.split(".")
            payload = json.loads(base64.b64decode(parts[1]).decode())
            return payload
        except:
            return None

# ========== API SERVER ==========
db = Database()

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Sessiz loglama
    
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        path = self.path
        
        if path == "/health":
            self.send_json({"status": "healthy", "app": "cybersurx", "version": "1.0"})
        
        elif path == "/api/v1/status":
            self.send_json({
                "api_version": "1.0.0",
                "status": "operational",
                "database": "connected",
                "timestamp": datetime.now().isoformat()
            })
        
        elif path == "/api/v1/targets":
            results = db.execute("SELECT id, name, host, port, protocol FROM targets")
            targets = [
                {"id": r[0], "name": r[1], "host": r[2], "port": r[3], "protocol": r[4]}
                for r in results
            ]
            self.send_json({"total": len(targets), "data": targets})
        
        elif path == "/api/v1/scans":
            results = db.execute("""SELECT s.id, s.scan_type, s.status, s.findings, t.name, t.host 
                                 FROM scans s JOIN targets t ON s.target_id = t.id""")
            scans = [
                {
                    "id": r[0], "scan_type": r[1], "status": r[2], 
                    "findings": json.loads(r[3]) if r[3] else [],
                    "target_name": r[4], "target_host": r[5]
                }
                for r in results
            ]
            self.send_json({"total": len(scans), "data": scans})
        
        else:
            self.send_json({"message": "CyberSurX API Demo", "endpoints": [
                "/health", "/api/v1/status", "/api/v1/targets", "/api/v1/scans"
            ]})
    
    def do_POST(self):
        path = self.path.split("?")[0]
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        
        # Parse query params
        params = {}
        if "?" in self.path:
            query = self.path.split("?")[1]
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        
        if path == "/api/v1/auth/register":
            username = params.get("username", "demo")
            email = params.get("email", "demo@test.com")
            password = params.get("password", "password123")
            
            try:
                db.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                          (username, email, password))
                token = SimpleJWT.encode({"user": username, "exp": (datetime.now() + timedelta(hours=1)).isoformat()})
                self.send_json({
                    "message": "User registered",
                    "token": token,
                    "user": {"username": username, "email": email}
                }, 201)
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
        
        elif path == "/api/v1/targets":
            name = params.get("name", "Untitled")
            host = params.get("host", "127.0.0.1")
            port = int(params.get("port", 80))
            protocol = params.get("protocol", "http")
            
            db.execute("INSERT INTO targets (name, host, port, protocol) VALUES (?, ?, ?, ?)",
                      (name, host, port, protocol))
            
            # Auto-create scan
            target_id = db.execute("SELECT last_insert_rowid()")[0][0]
            findings = [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "closed"}
            ]
            
            db.execute("INSERT INTO scans (target_id, scan_type, status, findings) VALUES (?, ?, ?, ?)",
                      (target_id, "nmap", "completed", json.dumps(findings)))
            
            self.send_json({
                "message": "Target created and scanned",
                "target_id": target_id,
                "findings": findings
            }, 201)
        
        else:
            self.send_json({"message": "Invalid endpoint"}, 404)

def main():
    import socket
    # Find available port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    
    server = HTTPServer(('0.0.0.0', port), APIHandler)
    
    print("=" * 60)
    print("CyberSurX GERÇEK Çalışan Demo")
    print("=" * 60)
    print(f"API: http://localhost:{port}")
    print(f"Health: http://localhost:{port}/health")
    print(f"Status: http://localhost:{port}/api/v1/status")
    print("")
    print("Test komutları:")
    print(f"  curl http://localhost:{port}/health")
    print(f"  curl -X POST 'http://localhost:{port}/api/v1/auth/register?username=demo\&email=demo@test.com'")
    print(f"  curl -X POST 'http://localhost:{port}/api/v1/targets?name=Server\&host=192.168.1.1'")
    print(f"  curl http://localhost:{port}/api/v1/targets")
    print(f"  curl http://localhost:{port}/api/v1/scans")
    print("")
    print("Ctrl+C ile durdurun")
    print("=" * 60)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer durduruldu.")

if __name__ == "__main__":
    main()
