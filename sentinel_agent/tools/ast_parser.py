"""
Lightweight AST parser for C/C++ files.

Extracts function signatures, call graph edges, and structural info
using regex-based heuristics (no tree-sitter dependency required,
but can be upgraded to tree-sitter for production use).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from .base import BaseTool

# Regex for C/C++ function definitions (handles common patterns)
_FUNC_DEF_RE = re.compile(
    r"^[\w\s\*&:<>,]+?\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?{"
    , re.MULTILINE
)

# Regex for function calls
_FUNC_CALL_RE = re.compile(r"\b(\w+)\s*\(")

# Known standard library / noise functions to exclude from call graph
_STDLIB_FUNCS = {
    "if", "while", "for", "switch", "return", "sizeof", "typeof", "alignof",
    "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast",
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf",
    "malloc", "calloc", "realloc", "free", "new", "delete",
    "memcpy", "memset", "memmove", "strcpy", "strncpy", "strcat",
    "strlen", "strcmp", "strncmp", "strtol", "strtoul", "atoi", "atol",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
    "assert", "abort", "exit",
}


class ASTParserTool(BaseTool):
    name = "ast_parser"
    description = (
        "Parse a C/C++ source file to extract function definitions, "
        "call graph (which function calls which), and identify complex "
        "functions. Input: file_path."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the C/C++ file."},
            },
            "required": ["file_path"],
        }

    def execute(self, **kwargs: Any) -> str:
        file_path = kwargs.get("file_path", "")
        if not file_path or not os.path.isfile(file_path):
            payload = {"tool": self.name, "functions": {}, "call_graph": [], "human": f"Error: file not found: {file_path}"}
            return json.dumps(payload, ensure_ascii=False)

        try:
            source = open(file_path, encoding="utf-8", errors="replace").read()
        except Exception as exc:
            payload = {"tool": self.name, "functions": {}, "call_graph": [], "human": f"Error reading file: {exc}"}
            return json.dumps(payload, ensure_ascii=False)

        # Extract function definitions
        functions: dict[str, dict] = {}
        for match in _FUNC_DEF_RE.finditer(source):
            func_name = match.group(1)
            params = match.group(2).strip()
            start_line = source[:match.start()].count("\n") + 1

            # Find function body end (simple brace counting)
            body_start = match.end() - 1  # position of '{'
            depth = 1
            pos = body_start + 1
            while pos < len(source) and depth > 0:
                if source[pos] == "{":
                    depth += 1
                elif source[pos] == "}":
                    depth -= 1
                pos += 1

            end_line = source[:pos].count("\n") + 1
            body = source[body_start:pos]

            # Extract calls within this function
            calls = set()
            for call_match in _FUNC_CALL_RE.finditer(body):
                callee = call_match.group(1)
                if callee not in _STDLIB_FUNCS and callee != func_name:
                    calls.add(callee)

            line_count = end_line - start_line + 1
            functions[func_name] = {
                "params": params,
                "start_line": start_line,
                "end_line": end_line,
                "line_count": line_count,
                "calls": sorted(calls),
                "complexity": "high" if line_count > 50 else "medium" if line_count > 20 else "low",
            }

        if not functions:
            payload = {
                "tool": self.name,
                "file": os.path.basename(file_path),
                "functions": {},
                "call_graph": [],
                "human": "No function definitions found (file may not be C/C++ or uses unusual syntax).",
            }
            return json.dumps(payload, ensure_ascii=False)

        # Build output
        lines: list[str] = [
            f"File: {os.path.basename(file_path)}",
            f"Functions found: {len(functions)}",
            "",
        ]

        for fname, info in sorted(functions.items(), key=lambda x: x[1]["start_line"]):
            lines.append(f"## {fname}({info['params']})")
            lines.append(f"   Lines {info['start_line']}-{info['end_line']} ({info['line_count']} lines, complexity: {info['complexity']})")
            if info["calls"]:
                lines.append(f"   Calls: {', '.join(info['calls'])}")
            lines.append("")

        # Call graph summary
        lines.append("## Call Graph")
        for fname, info in sorted(functions.items()):
            if info["calls"]:
                for callee in info["calls"]:
                    lines.append(f"  {fname} → {callee}")

        # High-complexity warning
        complex_funcs = [f for f, i in functions.items() if i["complexity"] == "high"]
        if complex_funcs:
            lines.append(f"\n⚠ High-complexity functions (>50 lines): {', '.join(complex_funcs)}")

        call_graph: list[dict[str, str]] = []
        for fname, info in sorted(functions.items()):
            if info["calls"]:
                for callee in info["calls"]:
                    call_graph.append({"caller": fname, "callee": callee})

        payload = {
            "tool": self.name,
            "file": os.path.basename(file_path),
            "functions": functions,
            "call_graph": call_graph,
            "human": "\n".join(lines),
        }
        return json.dumps(payload, ensure_ascii=False)
