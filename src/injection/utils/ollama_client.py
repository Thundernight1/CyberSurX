"""
AIG-AgentTeam Ollama İstemcisi

Yerel Ollama proxy üzerinden cloud modellere erişir.
Ollama desktop app cloud modelleri otomatik proxy eder:
  localhost:11434 → gemini-3-flash-preview:cloud → ollama.com bulut model

DOĞRU ENDPOINT: http://localhost:11434/api/chat
MODEL FORMATI: "model-name:cloud" (ör: kimi-k2.5:cloud)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

import httpx
import yaml

logger = logging.getLogger("aig-agentteam.ollama")


# ──────────────────────────────────────────────────────────────
# Model Tanımları — Hepsi Ollama Pro Bulut
# ──────────────────────────────────────────────────────────────

OLLAMA_MODELS = {
    # ☁️ Cloud modeller (hassas veri gönderir — şirketler için RİSKLİ)
    "glm-5.1":          {"id": "glm-5.1:cloud",                  "desc": "Genel amaç, Türkçe güçlü", "local": False},
    "gemma4":           {"id": "gemma4:31b-cloud",               "desc": "Kod analizi, mimari tasarım", "local": False},
    "minimax-m2.7":     {"id": "minimax-m2.7:cloud",             "desc": "Uzun metin, özetleme", "local": False},
    "qwen3.5":         {"id": "qwen3.5:cloud",                  "desc": "Çok dilli, mantık", "local": False},
    "qwen3-coder":      {"id": "qwen3-coder-next:cloud",        "desc": "Kod üretimi, debugging", "local": False},
    "nemotron-3":       {"id": "nemotron-3-super:cloud",         "desc": "Akıl yürütme, analiz", "local": False},
    "kimi-k2.5":        {"id": "kimi-k2.5:cloud",                "desc": "Güvenlik tarama, red-teaming", "local": False},
    "gemini-flash":     {"id": "gemini-3-flash-preview:cloud",   "desc": "Hızlı iterasyon", "local": False},
    "cogito":           {"id": "cogito-2.1:671b-cloud",          "desc": "Derin düşünme, planlama", "local": False},
    "deepseek":         {"id": "deepseek-v3.2:cloud",            "desc": "Güvenlik analizi, inceleme", "local": False},
    
    # 🏠 Lokal modeller (veri dışarı çıkmaz — şirketler için GÜVENLİ)
    "nu11secur1ty":      {"id": "f0rc3ps/nu11secur1tyAI4:latest",           "desc": "Lokal güvenlik AI (15GB)", "local": True},
    "nu11secur1ty-lite": {"id": "f0rc3ps/nu11secur1tyAIRedTeamLite:latest", "desc": "Lokal güvenlik AI hafif (5GB)", "local": True},
}

# Ajan → Model eşlemesi
AGENT_MODEL_MAP = {
    # 🏠 LOCAL modeller — veri dışarı çıkmaz! Hassas veriler için güvenli.
    "orchestrator":                 "nu11secur1ty-lite",
    "data_leakage_scanner":         "nu11secur1ty-lite",
    "indirect_injection_scanner":   "nu11secur1ty",
    "tool_abuse_scanner":           "nu11secur1ty-lite",
    "attack_engine":                "nu11secur1ty",
    "code_explorer":                "nu11secur1ty-lite",
    "code_architect":               "nu11secur1ty",
    "code_reviewer_dev":            "nu11secur1ty",
    "comment_analyzer":             "nu11secur1ty-lite",
    "test_analyzer":                "nu11secur1ty",
    "silent_failure_hunter":        "nu11secur1ty",
    "type_design_analyzer":         "nu11secur1ty-lite",
    "code_reviewer":                "nu11secur1ty",
    "code_simplifier":              "nu11secur1ty-lite",
    "planner":                      "nu11secur1ty",
    "executor":                     "nu11secur1ty-lite",
    "evaluator":                    "nu11secur1ty",
}


@dataclass
class OllamaConfig:
    """
    Ollama API yapılandırması.
    
    Yerel proxy: http://localhost:11434 (Ollama desktop app üzerinden cloud modeller)
    """
    base_url: str = "http://localhost:11434"
    api_key: str = ""  # Lokal modda API key gereksiz
    timeout: float = 300.0       # Büyük lokal modeller için uzun timeout
    default_temperature: float = 0.3
    default_max_tokens: int = 4096
    local_model: str = "f0rc3ps/nu11secur1tyAI4:latest"  # Lokal güvenlik modeli
    local_model_lite: str = "f0rc3ps/nu11secur1tyAIRedTeamLite:latest"  # Hafif versiyon
    data_local_only: bool = True  # True = hassas veri dışarı çıkmaz

    @classmethod
    def from_yaml(cls, path: str) -> "OllamaConfig":
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls(
            base_url=data.get("base_url", "http://localhost:11434"),
            timeout=data.get("timeout", 300),
        )

    @classmethod
    def from_env(cls) -> "OllamaConfig":
        return cls(
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            timeout=float(os.environ.get("OLLAMA_TIMEOUT", "300")),
        )


class OllamaClient:
    """
    Ollama İstemcisi — Yerel proxy üzerinden cloud modellere erişir.
    
    Kullanım:
        client = OllamaClient()
        response = await client.chat("kimi-k2.5", "Attack this system...")
    """

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig.from_env()
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
        )

    async def chat(
        self,
        model: str,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Ollama /api/chat endpoint ile sohbet.
        Yerel proxy → cloud model.
        """
        model_id = self._resolve_model(model)
        messages = []

        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model_id,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature or self.config.default_temperature,
                "num_predict": max_tokens or self.config.default_max_tokens,
            },
        }

        try:
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")

        except httpx.HTTPStatusError as e:
            logger.error(f"[Ollama] HTTP {e.response.status_code}: {e.response.text[:200]}")
            return f"Error: HTTP {e.response.status_code}"
        except httpx.ConnectError:
            logger.error("[Ollama] Bağlantı hatası — Ollama desktop app çalışıyor mu?")
            return "Error: Ollama bağlantı hatası"
        except Exception as e:
            logger.error(f"[Ollama] Hata: {e}")
            return f"Error: {str(e)}"

    async def chat_stream(
        self,
        model: str,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> AsyncGenerator[str, None]:
        """Akış modunda sohbet"""
        model_id = self._resolve_model(model)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model_id,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": temperature or self.config.default_temperature,
            },
        }

        try:
            async with self._client.stream("POST", "/api/chat", json=payload) as response:
                async for line in response.aiter_lines():
                    if line.strip():
                        data = json.loads(line)
                        if "message" in data and data["message"].get("content"):
                            yield data["message"]["content"]
        except Exception as e:
            logger.error(f"[Ollama] Stream hatası: {e}")
            yield f"Error: {str(e)}"

    async def list_models(self) -> list[dict]:
        """Kullanılabilir modelleri listele"""
        try:
            response = await self._client.get("/api/tags")
            response.raise_for_status()
            data = response.json()
            return data.get("models", [])
        except Exception as e:
            logger.error(f"[Ollama] Model listesi hatası: {e}")
            return []

    async def health_check(self) -> bool:
        """Ollama'nın çalışıp çalışmadığını kontrol et"""
        try:
            response = await self._client.get("/api/tags")
            return response.status_code == 200
        except Exception:
            return False

    def _resolve_model(self, model: str) -> str:
        """Model kısa adını tam ada çevir"""
        if model in OLLAMA_MODELS:
            return OLLAMA_MODELS[model]["id"]
        # Zaten :cloud sonekli olabilir
        if ":cloud" in model or ":671b-cloud" in model:
            return model
        return model

    def get_model_for_agent(self, agent_name: str) -> str:
        """Ajan adına göre model döndür"""
        return AGENT_MODEL_MAP.get(agent_name, "cogito")

    async def close(self):
        await self._client.aclose()


class OllamaTargetClient:
    """
    Hedef ajanla iletişim istemcisi.
    Tarama sırasında hedef ajana sorular gönderir.
    """

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig()
        self._client = httpx.AsyncClient(timeout=self.config.timeout)

    async def chat(self, target_url: str, prompt: str, system: Optional[str] = None) -> str:
        """
        Hedef ajanla sohbet.
        target_url bir Ollama endpoint ise cloud model ile sorgu gönderir.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Ollama endpoint — doğrudan cloud model kullan
        # localhost:11434 ise Ollama proxy
        if "11434" in target_url or "localhost" in target_url or "127.0.0.1" in target_url:
            # Hedef model — gemini-flash hızlı olduğu için varsayılan
            for model_id in ["gemini-3-flash-preview:cloud", "gpt-oss:20b", "deepseek-v3.2:cloud"]:
                try:
                    response = await self._client.post(
                        f"{target_url}/api/chat",
                        json={"model": model_id, "messages": messages, "stream": False},
                        headers={"Content-Type": "application/json"},
                        timeout=120.0,
                    )
                    if response.status_code == 200:
                        data = response.json()
                        return data.get("message", {}).get("content", "")
                except Exception:
                    continue

        # OpenAI uyumlu endpoint
        try:
            response = await self._client.post(
                f"{target_url}/v1/chat/completions",
                json={"model": "target-agent", "messages": messages, "stream": False},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception:
            pass

        # Basit POST
        try:
            response = await self._client.post(
                target_url,
                json={"prompt": prompt, "messages": messages},
                timeout=60.0,
            )
            if response.status_code == 200:
                return response.text
        except Exception as e:
            logger.error(f"[Target] İletişim hatası: {e}")

        return f"Error: could not reach target at {target_url}"

    async def close(self):
        await self._client.aclose()