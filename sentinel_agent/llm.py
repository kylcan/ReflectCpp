"""
LLM factory and utility functions shared across all agents.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_openai import ChatOpenAI


def get_llm(temperature: float = 0.0, **overrides: Any) -> ChatOpenAI:
    """Create a ChatOpenAI instance from environment configuration.

    Env vars (in priority order):
        GPT5_KEY / OPENAI_API_KEY      – API key
        CHATGPT_MODEL / AUDIT_MODEL    – model name (default: gpt-4o)
        CHATGPT_BASE_URL / OPENAI_BASE_URL – custom endpoint
    """
    api_key = os.getenv("GPT5_KEY") or os.getenv("OPENAI_API_KEY")
    model = os.getenv("CHATGPT_MODEL") or os.getenv("AUDIT_MODEL", "gpt-4o")
    base_url = (
        os.getenv("CHATGPT_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE")
    )

    kwargs: dict[str, Any] = {"model": model, "temperature": temperature}
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url.rstrip("/")
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


def message_text(content: Any) -> str:
    """Normalize LangChain message content to a plain string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)
