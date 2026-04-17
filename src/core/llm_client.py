"""
Ollama Cloud + Local LLM Client
All agents access models through this client.
Anthropic-compatible API and native Ollama API support.
"""
import json
import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, AsyncGenerator
from dataclasses import dataclass
from core.config.settings import (
    OLLAMA_CLOUD_BASE_URL,
    OLLAMA_LOCAL_BASE_URL,
    OLLAMA_API_KEY,
    USE_CLOUD,
)

logger = logging.getLogger("cyber-agent.llm")


@dataclass
class LLMResponse:
    content: str
    model: str
    total_duration: Optional[int] = None
    eval_count: Optional[int] = None
    done: bool = True
    raw: Optional[dict] = None


class OllamaClient:
    """
    Unified client for Ollama Cloud and local models.
    - Cloud models: ollama.com API (API key required)
    - Local models: localhost:11434 (ollama serve)
    """

    def __init__(self, api_key: str = None, prefer_cloud: bool = True):
        self.api_key = api_key or OLLAMA_API_KEY
        self.prefer_cloud = prefer_cloud
        self._cloud_disabled = False
        self._session: Optional[aiohttp.ClientSession] = None

    def _get_base_url(self, model: str) -> str:
        """Return cloud or local base URL for the model."""
        if self._cloud_disabled:
            return OLLAMA_LOCAL_BASE_URL
        if model.endswith("-cloud") or ":cloud" in model:
            return OLLAMA_CLOUD_BASE_URL
        if self.prefer_cloud and self.api_key:
            return OLLAMA_CLOUD_BASE_URL
        return OLLAMA_LOCAL_BASE_URL

    def _get_headers(self, model: str) -> Dict:
        """Build API headers."""
        headers = {"Content-Type": "application/json"}
        if self._get_base_url(model) == OLLAMA_CLOUD_BASE_URL and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=300)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ---------------------------------------------------------
    # CHAT COMPLETION (Ana endpoint)
    # ---------------------------------------------------------
    async def chat(
        self,
        model: str,
        messages: List[Dict[str, str]],
        system_prompt: str = None,
        temperature: float = 0.7,
        stream: bool = False,
        format: str = None,
    ) -> LLMResponse:
        """
        Send request to Ollama chat endpoint.

        Args:
            model: Model name (e.g. "kimi-k2-thinking:cloud")
            messages: [{"role": "user", "content": "..."}]
            system_prompt: System prompt
            temperature: Temperature (0.0 - 1.0)
            stream: Streaming mode
            format: Output format ("json" supported)
        """
        base_url = self._get_base_url(model)
        headers = self._get_headers(model)
        session = await self._get_session()

        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": temperature,
            },
        }

        if system_prompt:
            payload["messages"] = [
                {"role": "system", "content": system_prompt}
            ] + messages

        if format:
            payload["format"] = format

        url = f"{base_url}/chat"
        logger.info(f"LLM Request -> {model} @ {base_url}")

        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.error(f"LLM Error [{resp.status}]: {error_text}")
                    # If cloud fails, fall back to local
                    if base_url == OLLAMA_CLOUD_BASE_URL:
                        if resp.status in {401, 403}:
                            self._cloud_disabled = True
                            logger.warning("Cloud auth failed; switching to local for this session.")
                        else:
                            logger.warning("Cloud failed; switching to local fallback.")
                        return await self._fallback_local(
                            model, messages, system_prompt, temperature
                        )
                    raise ConnectionError(f"Ollama API error: {resp.status}")

                if stream:
                    return await self._handle_stream(resp, model)

                data = await resp.json()
                return LLMResponse(
                    content=data.get("message", {}).get("content", ""),
                    model=model,
                    total_duration=data.get("total_duration"),
                    eval_count=data.get("eval_count"),
                    done=data.get("done", True),
                    raw=data,
                )

        except aiohttp.ClientError as e:
            logger.error(f"Connection error: {e}")
            if base_url == OLLAMA_CLOUD_BASE_URL:
                self._cloud_disabled = True
                return await self._fallback_local(
                    model, messages, system_prompt, temperature
                )
            raise

    async def _fallback_local(
        self, model, messages, system_prompt, temperature
    ) -> LLMResponse:
        """Fallback to local Ollama if cloud fails."""
        local_model = model.replace(":cloud", "").replace("-cloud", "")
        logger.info(f"Local fallback: {local_model}")

        session = await self._get_session()
        payload = {
            "model": local_model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system_prompt:
            payload["messages"] = [
                {"role": "system", "content": system_prompt}
            ] + messages

        url = f"{OLLAMA_LOCAL_BASE_URL}/chat"
        try:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    return LLMResponse(
                        content="[ERROR] Both cloud and local models failed to respond.",
                        model=model,
                        done=True,
                    )
                data = await resp.json()
                return LLMResponse(
                    content=data.get("message", {}).get("content", ""),
                    model=local_model,
                    total_duration=data.get("total_duration"),
                    eval_count=data.get("eval_count"),
                    done=True,
                    raw=data,
                )
        except Exception:
            return LLMResponse(
                content="[ERROR] Model unreachable. Check your Ollama service.",
                model=model,
                done=True,
            )

    async def _handle_stream(self, resp, model) -> LLMResponse:
        """Collect streaming response."""
        full_content = []
        async for line in resp.content:
            decoded = line.decode("utf-8").strip()
            if not decoded:
                continue
            try:
                chunk = json.loads(decoded)
                msg = chunk.get("message", {}).get("content", "")
                if msg:
                    full_content.append(msg)
                if chunk.get("done"):
                    break
            except json.JSONDecodeError:
                continue

        return LLMResponse(
            content="".join(full_content),
            model=model,
            done=True,
        )

    # ---------------------------------------------------------
    # GENERATE (Simple text completion)
    # ---------------------------------------------------------
    async def generate(
        self,
        model: str,
        prompt: str,
        system: str = None,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Basit text generation endpoint'i."""
        base_url = self._get_base_url(model)
        headers = self._get_headers(model)
        session = await self._get_session()

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        url = f"{base_url}/generate"
        async with session.post(url, json=payload, headers=headers) as resp:
            data = await resp.json()
            return LLMResponse(
                content=data.get("response", ""),
                model=model,
                done=True,
                raw=data,
            )

    # ---------------------------------------------------------
    # MODEL YÖNETİMİ
    # ---------------------------------------------------------
    async def list_models(self, cloud: bool = True) -> List[Dict]:
        """Mevcut modelleri listele."""
        session = await self._get_session()
        base = OLLAMA_CLOUD_BASE_URL if cloud else OLLAMA_LOCAL_BASE_URL
        headers = self._get_headers("dummy:cloud" if cloud else "dummy")

        async with session.get(f"{base}/tags", headers=headers) as resp:
            data = await resp.json()
            return data.get("models", [])

    async def health_check(self) -> Dict[str, bool]:
        """Cloud ve local bağlantı durumunu kontrol et."""
        result = {"cloud": False, "local": False}
        session = await self._get_session()

        # Cloud kontrol
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            async with session.get(
                f"{OLLAMA_CLOUD_BASE_URL}/tags",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                result["cloud"] = resp.status == 200
        except Exception:
            pass

        # Local kontrol
        try:
            async with session.get(
                f"{OLLAMA_LOCAL_BASE_URL}/tags",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                result["local"] = resp.status == 200
        except Exception:
            pass

        return result


# Singleton instance
_client: Optional[OllamaClient] = None


def get_llm_client() -> OllamaClient:
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client
