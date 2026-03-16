"""
Grep-based dangerous function scanner.

Searches for known dangerous C/C++ functions and patterns using
regex matching (uses Python re, not external grep).
"""

from __future__ import annotations

import os
import re
from typing import Any

from .base import BaseTool

# Dangerous function patterns with CWE mappings
_DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    (r"\bstrcpy\s*\(", "strcpy", "CWE-120: Unbounded string copy – use strncpy or strlcpy"),
    (r"\bstrcat\s*\(", "strcat", "CWE-120: Unbounded string concatenation"),
    (r"\bgets\s*\(", "gets", "CWE-242: Use of inherently dangerous function"),
    (r"\bsprintf\s*\(", "sprintf", "CWE-120: Unbounded formatted output – use snprintf"),
    (r"\bscanf\s*\((?![^)]*%\d)", "scanf", "CWE-120: Potentially unbounded input"),
    (r"\bsystem\s*\(", "system", "CWE-78: Potential OS command injection"),
    (r"\bexec[lv]p?\s*\(", "exec*", "CWE-78: Process execution – check for injection"),
    (r"\bmalloc\s*\([^)]*\)\s*;", "malloc-no-check", "CWE-476: malloc without NULL check on same line"),
    (r"\bfree\s*\(", "free", "CWE-415/416: Check for double-free or use-after-free"),
    (r"\brealloc\s*\(", "realloc", "CWE-401: realloc without saving original pointer"),
    (r"\bmemcpy\s*\(", "memcpy", "CWE-120: Check bounds of destination buffer"),
    (r"\bsetuid\s*\(0\)", "setuid(0)", "CWE-250: Execution with unnecessary privileges"),
    (r"\bchmod\s*\([^,]*,\s*0?777\)", "chmod-777", "CWE-732: Overly permissive file permissions"),
    (r"#pragma\s+warning\s*\(\s*disable", "pragma-disable", "CWE-710: Compiler warning suppression"),
    (r"\beval\s*\(", "eval", "CWE-95: Code injection via eval"),
    (r"\bRand\s*\(\)|(?<!\w)rand\s*\(\)", "rand", "CWE-338: Use of weak PRNG for security context"),
]


class GrepScannerTool(BaseTool):
    name = "grep_scanner"
    description = (
        "Scan C/C++ source files for dangerous function calls and patterns "
        "(strcpy, gets, system, malloc-without-check, etc.). Returns "
        "matches with file:line, function name, and CWE reference. "
        "Input: file_path or directory_path."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File or directory to scan."},
                "pattern": {"type": "string", "description": "Optional: custom regex pattern to search for."},
            },
            "required": ["path"],
        }

    def execute(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "")
        custom_pattern = kwargs.get("pattern", "")

        if not path or not os.path.exists(path):
            return f"Error: path not found: {path}"

        files: list[str] = []
        if os.path.isfile(path):
            files = [path]
        else:
            for root, _, filenames in os.walk(path):
                for fn in filenames:
                    if any(fn.endswith(ext) for ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx")):
                        files.append(os.path.join(root, fn))

        if not files:
            return "No C/C++ files found."

        results: list[str] = []

        for fpath in sorted(files):
            try:
                content = open(fpath, encoding="utf-8", errors="replace").read()
            except Exception:
                continue

            lines = content.splitlines()
            patterns = _DANGEROUS_PATTERNS
            if custom_pattern:
                patterns = [(custom_pattern, "custom", "User-specified pattern")] + list(patterns)

            for line_num, line in enumerate(lines, 1):
                for regex, func_name, cwe_note in patterns:
                    if re.search(regex, line):
                        rel_path = os.path.relpath(fpath)
                        results.append(f"{rel_path}:{line_num}: [{func_name}] {cwe_note}")
                        results.append(f"    {line.strip()}")

        if not results:
            return "No dangerous patterns found."

        return f"Found {len(results) // 2} matches:\n" + "\n".join(results)
