# CYBERSURX

A professional RedTeam Physical Security Suite combining AI-powered injection testing, network reconnaissance, vulnerability analysis, physical device integration (Flipper Zero, WiFi Pineapple, SharkTap), and automated reporting.

## 🚀 Overview

**CyberSurX** is a comprehensive penetration testing framework designed for red teams and security professionals. It integrates multiple open-source security tools into a unified command-line interface with intelligent orchestration.

### Key Features

- **AI Injection Testing**: Prompt security testing using G0DM0D3 jailbreak techniques
- **Network Reconnaissance**: Nmap-based port scanning and host discovery  
- **Vulnerability Analysis**: Automated CVE lookup and exploit planning
- **Physical Device Integration**: Support for Hak5 devices (Pineapple, Flipper, SharkTap)
- **Human-in-the-Loop (HITL)**: Approval workflows for critical operations
- **Multi-Format Reporting**: HTML, PDF, JSON, and Markdown output
- **34 AI Model Orchestration**: Cross-model coordination via Ollama

## 📋 Requirements

- Python 3.9+
- Ollama (for AI features)
- Nmap (for network scanning)
- Physical devices (optional): WiFi Pineapple, Flipper Zero, SharkTap

## 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/Thundernight1/CyberSurX.git
cd CyberSurX

# Install dependencies
pip install -r requirements.txt

# Configure the tool
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
```

## 💻 Usage

### Interactive Mode
```bash
python -m src.cli --interactive
```

### Command Line Usage

```bash
# Show help
python -m src.cli --help

# Scan a target
python -m src.cli scan 192.168.1.1

# Run injection tests
python -m src.cli inject https://target.com

# Control physical devices
python -m src.cli device pineapple
python -m src.cli device flipper
python -m src.cli device sharktap

# Generate reports
python -m src.cli report --format html
python -m src.cli report --format pdf

# Run full pipeline
python -m src.cli full 192.168.1.1

# Check status
python -m src.cli status --watch
```

## 📁 Project Structure

```
CyberSurX/
├── src/
│   ├── cli.py                 # Main CLI interface
│   ├── redteam_master.py      # Core orchestrator
│   ├── __main__.py            # Entry point
│   ├── core/
│   │   ├── base_agent.py      # Agent framework base
│   │   ├── llm_client.py      # Ollama integration
│   │   └── hitl.py            # Human-in-the-loop
│   ├── injection/             # AI injection testing
│   ├── redteam/               # Pentesting modules
│   └── devices/               # Physical device scripts
├── config.yaml.example        # Configuration template
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## ⚠️ Disclaimer

**This tool is for authorized security testing only.** Users are responsible for complying with applicable laws and obtaining proper authorization before testing any systems they do not own.

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

**Thundernight1** - Cybersecurity Research & Development

---

**Version**: 1.0.0  
**Status**: Production Release  
**Platform**: Kali Linux, macOS, Ubuntu
