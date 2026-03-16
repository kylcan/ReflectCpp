"""
Agent working memory – scratchpad and findings accumulator.

Provides an in-memory store that agents use to track intermediate
findings, file analysis status, and cross-reference observations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkingMemory:
    """Mutable scratchpad shared across agent iterations."""

    # Files already analyzed (path → summary)
    analyzed_files: dict[str, str] = field(default_factory=dict)

    # Tool outputs keyed by (tool_name, target)
    tool_cache: dict[str, str] = field(default_factory=dict)

    # Cross-references: "function_name" → list of files where it appears
    function_index: dict[str, list[str]] = field(default_factory=dict)

    # Notes from the agent's reasoning
    notes: list[str] = field(default_factory=list)

    def mark_analyzed(self, file_path: str, summary: str) -> None:
        self.analyzed_files[file_path] = summary

    def is_analyzed(self, file_path: str) -> bool:
        return file_path in self.analyzed_files

    def cache_tool_result(self, key: str, output: str) -> None:
        self.tool_cache[key] = output

    def get_cached(self, key: str) -> str | None:
        return self.tool_cache.get(key)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def register_function(self, func_name: str, file_path: str) -> None:
        if func_name not in self.function_index:
            self.function_index[func_name] = []
        if file_path not in self.function_index[func_name]:
            self.function_index[func_name].append(file_path)

    def summary(self) -> str:
        lines = [
            f"Analyzed files: {len(self.analyzed_files)}",
            f"Cached tool results: {len(self.tool_cache)}",
            f"Indexed functions: {len(self.function_index)}",
            f"Agent notes: {len(self.notes)}",
        ]
        return "\n".join(lines)
