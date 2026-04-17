"""
Cyber Agent Team - Merkezi Konfigürasyon
Ollama Cloud + Yerel Model Entegrasyonu
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Optional

# ============================================================
# OLLAMA CLOUD KONFİGÜRASYONU
# ============================================================
OLLAMA_CLOUD_BASE_URL = "https://ollama.com/api"
OLLAMA_LOCAL_BASE_URL = "http://localhost:11434/api"
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")

# Varsayılan olarak cloud kullan, yerel fallback
USE_CLOUD = True

# ============================================================
# SHODAN KONFİGÜRASYONU
# ============================================================
# OSS (ücretsiz) plan: myip, dns lookup, host count destekler
# Membership+ plan: host lookup, search, scan gerektirir
# Gerçek erişim için: https://account.shodan.io
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_USE_MCP = True   # MCP connector varsa önce onu kullan (daha yetkili)
SHODAN_ENABLED = True

# ============================================================
# MODEL ATAMALARI - Her ajana özel model
# ============================================================
MODEL_ASSIGNMENTS = {
    # === OPERATOR KATMANI ===
    "network_operator": "devstral-small-2:24b-cloud",       # Hızlı, hafif tarama işleri
    "wireless_operator": "gemma3:27b-cloud",                 # Kablosuz ağ analizi
    "passive_operator": "nemotron-3-nano:30b-cloud",         # Pasif trafik izleme
    "physical_operator": "gemma3:27b-cloud",                 # Fiziksel gözlem

    # === ANALİZ KATMANI ===
    "asset_correlation": "qwen3-coder-next:cloud",           # Varlık korelasyonu - kod/yapı odaklı
    "vulnerability_analysis": "kimi-k2-thinking:cloud",      # Zafiyet analizi - derin düşünme
    "credential_analysis": "cogito-2.1:671b-cloud",          # Kimlik bilgisi analizi - büyük model
    "exposure_analysis": "mistral-large-3:675b-cloud",       # Dış yüzey analizi

    # === KARAR KATMANI ===
    "attack_path": "kimi-k2-thinking:cloud",                 # Saldırı yolu - reasoning güçlü
    "risk_prioritization": "glm-4.7:cloud",                  # Risk önceliklendirme
    "detection_gap": "deepseek-v3.2:cloud",                  # Tespit boşlukları
    "mitigation_strategy": "mistral-large-3:675b-cloud",     # Savunma stratejisi
    "report_agent": "qwen3-coder:480b-cloud",                # Rapor üretimi

    # === DESTEK AJANLARI ===
    "fullstack_engineer": "qwen3-coder-next:cloud",          # Fullstack geliştirme
    "ui_engineer": "deepseek-v3.2:cloud",                    # UI/UX tasarım
    "orchestrator": "cogito-2.1:671b-cloud",                 # Mor Takım Lideri
    "devsecops": "devstral-small-2:24b-cloud",               # DevSecOps - hızlı görevler
}

# ============================================================
# GÜVENLİK ARAÇLARI KONFİGÜRASYONU
# ============================================================
def _tool_path(env_key: str, default: str) -> str:
    return os.getenv(env_key, default)

SECURITY_TOOLS = {
    "nmap": {
        "path": _tool_path("NMAP_PATH", "nmap"),
        "enabled": True,
        "category": "network_discovery",
    },
    "nikto": {
        "path": _tool_path("NIKTO_PATH", "nikto"),
        "enabled": True,
        "category": "web_scanner",
    },
    "sqlmap": {
        "path": _tool_path("SQLMAP_PATH", "sqlmap"),
        "enabled": True,
        "category": "sql_injection",
    },
    "nuclei": {
        "path": _tool_path("NUCLEI_PATH", "nuclei"),
        "enabled": True,
        "category": "vulnerability_scanner",
    },
    "zap": {
        "path": _tool_path("ZAP_PATH", "zap-cli"),
        "enabled": True,
        "category": "web_security",
    },
    "trivy": {
        "path": _tool_path("TRIVY_PATH", "trivy"),
        "enabled": True,
        "category": "container_security",
    },
    "metasploit": {
        "path": _tool_path("METASPLOIT_PATH", "msfconsole"),
        "enabled": True,
        "category": "exploitation",
    },
    "shodan": {
        "path": _tool_path("SHODAN_PATH", "shodan"),
        "enabled": True,
        "category": "osint",
    },
    "burpsuite": {
        "path": _tool_path("BURPSUITE_PATH", "burpsuite"),
        "enabled": True,
        "category": "web_proxy",
    },
}

# ============================================================
# AJAN TAKIM YAPISI
# ============================================================
@dataclass
class AgentProfile:
    name: str
    role: str
    layer: str  # operator | analysis | decision | support
    model: str
    description: str
    tools: list = field(default_factory=list)
    system_prompt: str = ""

TEAM_ROSTER = {
    # --- OPERATOR KATMANI ---
    "network_operator": AgentProfile(
        name="NetScan",
        role="Network Operator",
        layer="operator",
        model=MODEL_ASSIGNMENTS["network_operator"],
        description="Ağ keşfi ve servis bilgisi toplama",
        tools=["nmap", "masscan"],
    ),
    "wireless_operator": AgentProfile(
        name="WifiRecon",
        role="Wireless Operator",
        layer="operator",
        model=MODEL_ASSIGNMENTS["wireless_operator"],
        description="Kablosuz ortam verileri ve erişim noktası karakteristikleri",
        tools=["aircrack", "kismet"],
    ),
    "passive_operator": AgentProfile(
        name="PassiveEye",
        role="Passive Network Operator",
        layer="operator",
        model=MODEL_ASSIGNMENTS["passive_operator"],
        description="Pasif trafik ve kimlik doğrulama kalıpları yakalama",
        tools=["tcpdump", "wireshark"],
    ),
    "physical_operator": AgentProfile(
        name="PhysRecon",
        role="Physical Observation Operator",
        layer="operator",
        model=MODEL_ASSIGNMENTS["physical_operator"],
        description="Fiziksel erişim ve cihaz etkileşim gözlemleri",
        tools=[],
    ),
    # --- ANALİZ KATMANI ---
    "asset_correlation": AgentProfile(
        name="AssetMap",
        role="Asset Correlation Agent",
        layer="analysis",
        model=MODEL_ASSIGNMENTS["asset_correlation"],
        description="Ağ, kablosuz ve fiziksel verileri birleşik saldırı yüzeyine dönüştürme",
        tools=[],
    ),
    "vulnerability_analysis": AgentProfile(
        name="VulnHunter",
        role="Vulnerability Analysis Agent",
        layer="analysis",
        model=MODEL_ASSIGNMENTS["vulnerability_analysis"],
        description="Yazılım ve konfigürasyonları bilinen zafiyetlere eşleme",
        tools=["nuclei", "nikto", "sqlmap"],
    ),
    "credential_analysis": AgentProfile(
        name="CredCheck",
        role="Credential & Access Analysis Agent",
        layer="analysis",
        model=MODEL_ASSIGNMENTS["credential_analysis"],
        description="Kimlik doğrulama zayıflıkları ve yanal hareket potansiyeli",
        tools=[],
    ),
    "exposure_analysis": AgentProfile(
        name="ExposureRadar",
        role="Exposure Analysis Agent",
        layer="analysis",
        model=MODEL_ASSIGNMENTS["exposure_analysis"],
        description="Dışarıdan erişilebilir riskleri önceliklendirme",
        tools=["zap", "trivy"],
    ),
    # --- KARAR KATMANI ---
    "attack_path": AgentProfile(
        name="PathFinder",
        role="Attack Path Agent",
        layer="decision",
        model=MODEL_ASSIGNMENTS["attack_path"],
        description="Keşfedilen zafiyetlerden gerçekçi saldırı zincirleri oluşturma",
        tools=[],
    ),
    "risk_prioritization": AgentProfile(
        name="RiskEngine",
        role="Risk Prioritization Agent",
        layer="decision",
        model=MODEL_ASSIGNMENTS["risk_prioritization"],
        description="Teknik riski operasyonel/iş etkisine dönüştürme",
        tools=[],
    ),
    "detection_gap": AgentProfile(
        name="BlindSpot",
        role="Detection Gap Agent",
        layer="decision",
        model=MODEL_ASSIGNMENTS["detection_gap"],
        description="Görünürlük ve loglama zayıflıklarını tespit etme",
        tools=[],
    ),
    "mitigation_strategy": AgentProfile(
        name="ShieldPlanner",
        role="Mitigation Strategy Agent",
        layer="decision",
        model=MODEL_ASSIGNMENTS["mitigation_strategy"],
        description="İyileştirme ve savunma önerileri üretme",
        tools=[],
    ),
    "report_agent": AgentProfile(
        name="ReportGen",
        role="Report Agent",
        layer="decision",
        model=MODEL_ASSIGNMENTS["report_agent"],
        description="Yapılandırılmış değerlendirme çıktıları oluşturma",
        tools=[],
    ),
    # --- DESTEK AJANLARI ---
    "fullstack_engineer": AgentProfile(
        name="FullStack",
        role="Fullstack Engineer",
        layer="support",
        model=MODEL_ASSIGNMENTS["fullstack_engineer"],
        description="Backend API, veritabanı, entegrasyonlar",
        tools=[],
    ),
    "ui_engineer": AgentProfile(
        name="UIForge",
        role="UI/UX Engineer",
        layer="support",
        model=MODEL_ASSIGNMENTS["ui_engineer"],
        description="Web dashboard, raporlama arayüzü, görsel tasarım",
        tools=[],
    ),
    "orchestrator": AgentProfile(
        name="PurpleLead",
        role="Purple Team Orchestrator",
        layer="support",
        model=MODEL_ASSIGNMENTS["orchestrator"],
        description="Tüm ajanları koordine eden mor takım lideri",
        tools=[],
    ),
    "devsecops": AgentProfile(
        name="SecOps",
        role="DevSecOps Engineer",
        layer="support",
        model=MODEL_ASSIGNMENTS["devsecops"],
        description="CI/CD güvenliği, konteyner tarama, altyapı güvenliği",
        tools=["trivy", "nuclei"],
    ),
}

# ============================================================
# SUNUCU KONFİGÜRASYONU
# ============================================================
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8443
LOG_DIR = Path(os.path.dirname(os.path.dirname(__file__))) / "logs"
REPORT_DIR = Path(os.path.dirname(os.path.dirname(__file__))) / "reports"

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
