"""
Base class for all SentinelAgent tools.

Each tool follows a consistent interface so the agent can dynamically
select and invoke tools based on its plan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseTool(ABC):
    """Interface that all agent tools must implement."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def execute(self, **kwargs: Any) -> str:
        """Run the tool and return a string observation."""
        ...

    def schema(self) -> dict:
        """Return a JSON-schema-like description for the LLM."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self._parameters(),
        }

    def _parameters(self) -> dict:
        """Override to declare tool parameters."""
        return {}
