"""
File reader tool – allows the agent to read source files on demand.

This gives the agent the ability to selectively read files it decides
are relevant, rather than loading everything upfront.
"""

from __future__ import annotations

import os
from typing import Any

from .base import BaseTool


class FileReaderTool(BaseTool):
    name = "file_reader"
    description = (
        "Read the contents of a source file. Can read the full file or "
        "a specific line range. Input: file_path, optional start_line and end_line."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file to read."},
                "start_line": {"type": "integer", "description": "Start line (1-indexed, default: 1)."},
                "end_line": {"type": "integer", "description": "End line (inclusive, default: end of file)."},
            },
            "required": ["file_path"],
        }

    def execute(self, **kwargs: Any) -> str:
        file_path = kwargs.get("file_path", "")
        start = kwargs.get("start_line", 1)
        end = kwargs.get("end_line", 0)

        if not file_path or not os.path.isfile(file_path):
            return f"Error: file not found: {file_path}"

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as exc:
            return f"Error reading file: {exc}"

        total_lines = len(lines)
        start = max(1, start)
        if end <= 0:
            end = total_lines
        end = min(end, total_lines)

        selected = lines[start - 1:end]

        # Add line numbers
        numbered: list[str] = []
        for i, line in enumerate(selected, start):
            numbered.append(f"{i:4d} | {line.rstrip()}")

        header = f"File: {file_path} (lines {start}-{end} of {total_lines})"
        return header + "\n" + "\n".join(numbered)
