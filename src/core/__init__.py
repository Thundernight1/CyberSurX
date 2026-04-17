"""
Core module - Pentest Platform Base Agent System

Modules:
    base_agent: BaseAgent class, TaskResult dataclass, AgentLayer/AgentStatus enums
    llm_client: OllamaClient for Cloud/Local LLM integration
    config.settings: MODEL_ASSIGNMENTS, TEAM_ROSTER, security tools config
"""

from .base_agent import BaseAgent, TaskResult, SharedState, AgentLayer, AgentStatus
from .llm_client import get_llm_client, LLMResponse, OllamaClient
from .config.settings import (
    MODEL_ASSIGNMENTS,
    TEAM_ROSTER,
    AgentProfile,
    SECURITY_TOOLS,
)

__all__ = [
    "BaseAgent",
    "TaskResult",
    "SharedState",
    "AgentLayer",
    "AgentStatus",
    "get_llm_client",
    "LLMResponse",
    "OllamaClient",
    "MODEL_ASSIGNMENTS",
    "TEAM_ROSTER",
    "AgentProfile",
    "SECURITY_TOOLS",
]
