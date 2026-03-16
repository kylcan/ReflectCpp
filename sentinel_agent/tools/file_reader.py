"""
File reader tool – allows the agent to read source files on demand.

This gives the agent the ability to selectively read files it decides
are relevant, rather than loading everything upfront.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
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
                "repo_root": {"type": "string", "description": "Optional repo root; file_path must be within this directory."},
                "start_line": {"type": "integer", "description": "Start line (1-indexed, default: 1)."},
                "end_line": {"type": "integer", "description": "End line (inclusive, default: end of file)."},
                "max_bytes": {"type": "integer", "description": "Max file size to read (default: 200000)."},
                "max_lines": {"type": "integer", "description": "Max number of lines to return (default: 1000)."},
            },
            "required": ["file_path"],
        }

    def execute(self, **kwargs: Any) -> str:
        file_path = kwargs.get("file_path", "")
        repo_root = kwargs.get("repo_root", "")
        start = kwargs.get("start_line", 1)
        end = kwargs.get("end_line", 0)
        max_bytes = int(kwargs.get("max_bytes", 200_000) or 0)
        max_lines = int(kwargs.get("max_lines", 1000) or 0)

        if not file_path:
            payload = {"tool": self.name, "human": "Error: file_path is required."}
            return json.dumps(payload, ensure_ascii=False)

        try:
            candidate = Path(file_path)
            if repo_root:
                root = Path(repo_root).expanduser().resolve()
                if not candidate.is_absolute():
                    candidate = (root / candidate)
                resolved = candidate.expanduser().resolve()
                if not resolved.is_relative_to(root):
                    payload = {"tool": self.name, "human": f"Error: access denied (outside repo_root): {resolved}"}
                    return json.dumps(payload, ensure_ascii=False)
                file_path = str(resolved)
            else:
                file_path = str(candidate.expanduser().resolve()) if not os.path.isabs(file_path) else file_path
        except Exception as exc:
            payload = {"tool": self.name, "human": f"Error resolving path: {exc}"}
            return json.dumps(payload, ensure_ascii=False)

        if not file_path or not os.path.isfile(file_path):
            payload = {"tool": self.name, "human": f"Error: file not found: {file_path}"}
            return json.dumps(payload, ensure_ascii=False)

        if max_bytes:
            try:
                if os.path.getsize(file_path) > max_bytes:
                    payload = {"tool": self.name, "human": f"Error: file too large (> {max_bytes} bytes): {file_path}"}
                    return json.dumps(payload, ensure_ascii=False)
            except OSError as exc:
                payload = {"tool": self.name, "human": f"Error stat file: {exc}"}
                return json.dumps(payload, ensure_ascii=False)

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as exc:
            payload = {"tool": self.name, "human": f"Error reading file: {exc}"}
            return json.dumps(payload, ensure_ascii=False)

        total_lines = len(lines)
        start = max(1, start)
        if end <= 0:
            end = total_lines
        end = min(end, total_lines)

        if max_lines and (end - start + 1) > max_lines:
            end = start + max_lines - 1

        selected = lines[start - 1:end]

        # Add line numbers
        numbered: list[str] = []
        for i, line in enumerate(selected, start):
            numbered.append(f"{i:4d} | {line.rstrip()}")

        header = f"File: {file_path} (lines {start}-{end} of {total_lines})"
        human = header + "\n" + "\n".join(numbered)
        payload = {
            "tool": self.name,
            "file": file_path,
            "start_line": start,
            "end_line": end,
            "total_lines": total_lines,
            "truncated": bool(max_lines and (end < (kwargs.get("end_line", 0) or total_lines))),
            "human": human,
        }
        return json.dumps(payload, ensure_ascii=False)
