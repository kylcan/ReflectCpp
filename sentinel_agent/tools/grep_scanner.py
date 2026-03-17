"""
Grep-based dangerous function scanner.

Searches for known dangerous C/C++ functions and patterns using
regex matching (uses Python re, not external grep).
"""

from __future__ import annotations

import json
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
                "max_files": {"type": "integer", "description": "Max files to scan (default 2000)."},
                "max_matches": {"type": "integer", "description": "Stop after this many matches (default 2000)."},
                "max_file_size_bytes": {"type": "integer", "description": "Skip files larger than this (default 524288)."},
            },
            "required": ["path"],
        }

    def execute(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "")
        custom_pattern = kwargs.get("pattern", "")
        max_files = int(kwargs.get("max_files", 2000) or 0)
        max_matches = int(kwargs.get("max_matches", 2000) or 0)
        max_file_size = int(kwargs.get("max_file_size_bytes", 524288) or 0)

        if not path or not os.path.exists(path):
            payload = {"tool": self.name, "matches": [], "human": f"Error: path not found: {path}"}
            return json.dumps(payload, ensure_ascii=False)

        files: list[str] = []
        if os.path.isfile(path):
            files = [path]
        else:
            for root, _, filenames in os.walk(path):
                for fn in filenames:
                    if any(fn.endswith(ext) for ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx")):
                        files.append(os.path.join(root, fn))

        if max_files and len(files) > max_files:
            files = sorted(files)[:max_files]

        if not files:
            payload = {"tool": self.name, "matches": [], "human": "No C/C++ files found."}
            return json.dumps(payload, ensure_ascii=False)

        matches: list[dict[str, Any]] = []
        results_human: list[str] = []

        for fpath in sorted(files):
            if max_file_size and os.path.isfile(fpath):
                try:
                    if os.path.getsize(fpath) > max_file_size:
                        continue
                except OSError:
                    continue
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
                        cwe_id = ""
                        m = re.search(r"CWE-\d+", cwe_note)
                        if m:
                            cwe_id = m.group(0)
                        matches.append({
                            "file": rel_path,
                            "line": line_num,
                            "pattern": func_name,
                            "cwe": cwe_id,
                            "note": cwe_note,
                            "line_text": line.strip(),
                        })
                        results_human.append(f"{rel_path}:{line_num}: [{func_name}] {cwe_note}")
                        results_human.append(f"    {line.strip()}")

                        if max_matches and len(matches) >= max_matches:
                            break
                if max_matches and len(matches) >= max_matches:
                    break
            if max_matches and len(matches) >= max_matches:
                break

        if not matches:
            payload = {
                "tool": self.name,
                "matches": [],
                "human": "No dangerous patterns found.",
            }
            return json.dumps(payload, ensure_ascii=False)

        human = f"Found {len(matches)} matches:\n" + "\n".join(results_human)
        payload = {
            "tool": self.name,
            "matches": matches,
            "truncated": bool(max_matches and len(matches) >= max_matches),
            "human": human,
        }
        return json.dumps(payload, ensure_ascii=False)
