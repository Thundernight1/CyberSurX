"""
AIG-AgentTeam Model Yönlendirici
Görev tipine göre doğru Ollama Pro bulut modelini seçer
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger("aig-agentteam.router")


class TaskType(str, Enum):
    """Görev tipleri"""
    SECURITY_SCAN = "security_scan"
    ATTACK_GENERATION = "attack_generation"
    CODE_ANALYSIS = "code_analysis"
    ARCHITECTURE = "architecture"
    CODE_REVIEW = "code_review"
    CODE_GENERATION = "code_generation"
    PLANNING = "planning"
    REASONING = "reasoning"
    FAST_ITERATION = "fast_iteration"
    DOCUMENTATION = "documentation"


# Görev → Model eşlemesi
TASK_MODEL_MAP = {
    TaskType.SECURITY_SCAN: "kimi-k2.5",        # Red-teaming uzmanı
    TaskType.ATTACK_GENERATION: "kimi-k2.5",    # Saldırı vektörü üretimi
    TaskType.CODE_ANALYSIS: "qwen3.5",          # Çok dilli kod analizi
    TaskType.ARCHITECTURE: "gemma4",             # Mimari tasarım
    TaskType.CODE_REVIEW: "deepseek",            # Güvenlik incelemesi
    TaskType.CODE_GENERATION: "qwen3-coder",     # Kod üretimi
    TaskType.PLANNING: "cogito",                 # Derin düşünme
    TaskType.REASONING: "nemotron-3",            # Akıl yürütme
    TaskType.FAST_ITERATION: "gemini-flash",     # Hızlı iterasyon
    TaskType.DOCUMENTATION: "qwen3.5",          # Dokümantasyon
}

# Güvenlik bağlamı önceliklendirmesi
SECURITY_PRIORITY_MODELS = [
    "kimi-k2.5",     # En güvenlik odaklı
    "deepseek",       # İkincil güvenlik
    "nemotron-3",     # Akıl yürütme
]

# Hız önceliklendirmesi
SPEED_PRIORITY_MODELS = [
    "gemini-flash",  # En hızlı
    "qwen3.5",       # Hızlı ve çok dilli
    "qwen3-coder",   # Hızlı kod üretimi
]


class ModelRouter:
    """
    Görev tipine göre Ollama Pro bulut modelini yönlendirir.
    Her görev için en uygun modeli seçer.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._overrides: dict[TaskType, str] = {}

    def get_model(self, task: TaskType) -> str:
        """Görev tipi için uygun modeli döndür"""
        if task in self._overrides:
            return self._overrides[task]
        return TASK_MODEL_MAP.get(task, "cogito")

    def override(self, task: TaskType, model: str):
        """Belirli bir görev için model override et"""
        self._overrides[task] = model
        logger.info(f"[Router] Override: {task.value} → {model}")

    def get_security_model(self) -> str:
        """Güvenlik taraması için en iyi modeli döndür"""
        return SECURITY_PRIORITY_MODELS[0]

    def get_fast_model(self) -> str:
        """Hızlı işlemler için en hızlı modeli döndür"""
        return SPEED_PRIORITY_MODELS[0]

    def list_assignments(self) -> dict[str, str]:
        """Tüm görev-model atamalarını listele"""
        assignments = {}
        for task, model in TASK_MODEL_MAP.items():
            if task in self._overrides:
                assignments[task.value] = f"{model} → {self._overrides[task]} (override)"
            else:
                assignments[task.value] = model
        return assignments