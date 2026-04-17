# CyberSurX

**Production-Ready RedTeam Physical Security Suite**

A comprehensive penetration testing framework with AI injection testing, network reconnaissance, vulnerability scanning, physical device integration, and automated reporting.

## 🚀 Features

### Core Capabilities
- **🔐 JWT Authentication** - Full user management with role-based access
- **🗃️ Database-Backed** - SQLite/PostgreSQL with SQLAlchemy ORM
- **🌐 REST API** - FastAPI with 50+ endpoints
- **🔍 Real Scanning** - Nmap integration for port scanning
- **💉 Vulnerability Testing** - SQL injection, XSS detection
- **🛡️ Physical Devices** - WiFi Pineapple, Flipper Zero support
- **👤 Human-in-the-Loop** - Approval workflows for critical operations
- **📊 Multi-Format Reports** - PDF, HTML, JSON export

## 📦 Installation

### Requirements
```bash
Python 3.9+
nmap (system package)
```

### Setup
```bash
# Clone repository
git clone https://github.com/Thundernight1/CyberSurX.git
cd CyberSurX

# Install dependencies
pip install -r requirements.txt

# Initialize database
python src/init_db.py

# Start API server
python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

## 🎯 Quick Start

### 1. API Authentication
```bash
# Register user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -d "username=admin" \
  -d "email=admin@cybersurx.com" \
  -d "password=SecurePass123"

# Login (get JWT token)
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -d "email=admin@cybersurx.com" \
  -d "password=SecurePass123"
```

### 2. Create Target
```bash
curl -X POST "http://localhost:8000/api/v1/targets/" \
  -H "Authorization: Bearer $TOKEN" \
  -d "name=Test Server" \
  -d "host=192.168.1.1"
```

### 3. Run Nmap Scan
```bash
# Check nmap installed
curl "http://localhost:8000/api/v1/scans/nmap-check" -H "Authorization: Bearer $TOKEN"

# Start scan
curl -X POST "http://localhost:8000/api/v1/scans/nmap?target_id=1&ports=80,443" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Test for SQL Injection
```bash
curl -X POST "http://localhost:8000/api/v1/injection/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d "target_url=http://testphp.vulnweb.com" \
  -d "test_type=sqli"
```

## 📚 API Documentation

### Authentication Endpoints
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login (returns JWT)
- `GET /api/v1/auth/me` - Current user info

### Target Management
- `GET /api/v1/targets/` - List targets
- `POST /api/v1/targets/` - Create target
- `GET /api/v1/targets/{id}` - Get target
- `PUT /api/v1/targets/{id}` - Update target
- `DELETE /api/v1/targets/{id}` - Delete target

### Scan Operations
- `GET /api/v1/scans/nmap-check` - Check nmap installation
- `POST /api/v1/scans/nmap` - Start nmap scan
- `GET /api/v1/scans/` - List scans
- `GET /api/v1/scans/{id}` - Get scan results
- `DELETE /api/v1/scans/{id}` - Delete scan

### Injection Testing
- `GET /api/v1/injection/payloads` - Get available payloads
- `POST /api/v1/injection/scan` - Run injection test
- `GET /api/v1/injection/tests` - List tests
- `GET /api/v1/injection/tests/{id}` - Get test results

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run specific test files
pytest tests/database/test_models.py
pytest tests/api/test_endpoints.py
pytest tests/cli/test_commands.py
```

## 🔧 Architecture

```
CyberSurX/
├── src/
│   ├── api/              # FastAPI application
│   │   ├── main.py       # App entry point
│   │   ├── dependencies.py  # Auth middleware
│   │   └── routes/       # API endpoints
│   │       ├── auth.py   # JWT authentication
│   │       ├── targets.py
│   │       ├── scans.py  # Nmap integration
│   │       ├── injection.py
│   │       └── ...
│   ├── core/             # Core framework
│   │   ├── auth_utils.py # JWT utilities
│   │   ├── base_agent.py
│   │   └── hitl.py       # Human-in-the-loop
│   ├── database/         # SQLAlchemy ORM
│   │   ├── connection.py
│   │   └── models.py     # 9 tables
│   ├── redteam/          # Red team operations
│   │   └── modules/
│   │       ├── scanner.py        # Real nmap
│   │       └── exploit_executor.py
│   └── injection/        # Security testing
│       └── scanners/
│           └── web_vuln_scanner.py  # Real HTTP tests
├── tests/                # Test suite
└── requirements.txt
```

## ⚠️ Disclaimer

**For authorized security testing only.** Users must comply with applicable laws and obtain proper authorization before testing any systems they do not own.

## 📄 License

MIT License - See LICENSE file

## 👤 Author

**Thundernight1** - Cybersecurity Research & Development
