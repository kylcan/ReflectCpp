"""
cppcheck static analysis tool.

Runs cppcheck on a file or directory and returns diagnostic output.
Falls back to mock output when cppcheck is not installed.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .base import BaseTool

logger = logging.getLogger(__name__)


class CppcheckTool(BaseTool):
    name = "cppcheck"
    description = (
        "Run cppcheck static analysis on a C/C++ file or directory. Returns diagnostics "
        "including buffer overflows, null pointer dereferences, memory leaks, "
        "and style warnings. Input: file_path (string)."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to a C/C++ file or directory to analyze."},
            },
            "required": ["file_path"],
        }

    def execute(self, **kwargs: Any) -> str:
        file_path = kwargs.get("file_path", "")
        if not file_path:
            payload = {"tool": self.name, "findings": [], "human": "Error: file_path is required."}
            return json.dumps(payload, ensure_ascii=False)

        if not (os.path.isfile(file_path) or os.path.isdir(file_path)):
            payload = {"tool": self.name, "findings": [], "human": f"Error: path not found: {file_path}"}
            return json.dumps(payload, ensure_ascii=False)

        force_mock = os.getenv("SENTINEL_FORCE_MOCK_CPPCHECK") == "1"

        if force_mock or not shutil.which("cppcheck"):
            logger.warning("cppcheck not installed – using mock output.")
            text, findings = _mock_cppcheck_for_path(file_path)
            payload = {
                "tool": self.name,
                "target": os.path.basename(file_path),
                "engine": "mock" if force_mock or not shutil.which("cppcheck") else "cppcheck",
                "findings": findings,
                "human": text.strip(),
            }
            return json.dumps(payload, ensure_ascii=False)

        try:
            result = subprocess.run(
                ["cppcheck", "--enable=all", "--inconclusive", "--force",
                 "--quiet", str(file_path)],
                capture_output=True, text=True, timeout=60,
            )
            output = result.stderr or result.stdout
            text = output.strip() if output.strip() else "(cppcheck: no findings)"
            payload = {
                "tool": self.name,
                "target": os.path.basename(file_path),
                "engine": "cppcheck",
                "findings": _parse_cppcheck_text(text),
                "human": text,
            }
            return json.dumps(payload, ensure_ascii=False)
        except subprocess.TimeoutExpired:
            payload = {"tool": self.name, "target": os.path.basename(file_path), "findings": [], "human": "(cppcheck timed out after 60s)"}
            return json.dumps(payload, ensure_ascii=False)
        except Exception as exc:
            payload = {"tool": self.name, "target": os.path.basename(file_path), "findings": [], "human": f"(cppcheck error: {exc})"}
            return json.dumps(payload, ensure_ascii=False)


def _parse_cppcheck_text(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = re.match(r"\[(.+?):(\d+)\]:\s*\((\w+)\)\s*(.*)", line.strip())
        if not m:
            continue
        file_name, line_num, severity, message = m.groups()
        findings.append({
            "file": file_name,
            "line": int(line_num),
            "severity": severity,
            "message": message,
        })
    return findings


_C_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def _iter_cpp_files(target_path: str, max_files: int = 80) -> list[Path]:
    p = Path(target_path)
    if p.is_file():
        return [p]
    files: list[Path] = []
    for fp in p.rglob("*"):
        if fp.is_file() and fp.suffix.lower() in _C_EXTS:
            files.append(fp)
            if len(files) >= max_files:
                break
    return files


def _mock_cppcheck_for_path(target_path: str) -> tuple[str, list[dict[str, Any]]]:
    files = _iter_cpp_files(target_path)
    if not files:
        text = "(cppcheck mock: no C/C++ files found)"
        return text, []

    all_findings: list[dict[str, Any]] = []
    lines_out: list[str] = []

    root = Path(target_path)
    if root.is_file():
        root = root.parent

    for fp in files:
        rel = str(fp.relative_to(root)) if fp.is_relative_to(root) else fp.name
        text, findings = _mock_cppcheck_for_file(fp, display_name=rel)
        if text:
            lines_out.extend(text.splitlines())
        all_findings.extend(findings)

    if not lines_out:
        return "(cppcheck mock: no findings)", []
    return "\n".join(lines_out), all_findings


def _mock_cppcheck_for_file(file_path: Path, display_name: str | None = None) -> tuple[str, list[dict[str, Any]]]:
    display = display_name or file_path.name
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return f"[{display}:1]: (warning) Unable to read file for analysis.", [
            {"file": display, "line": 1, "severity": "warning", "message": "Unable to read file for analysis."}
        ]

    findings: list[dict[str, Any]] = []
    out_lines: list[str] = []

    # Extremely lightweight, deterministic heuristics.
    malloc_vars: dict[str, dict[str, Any]] = {}

    for i, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()

        if "strcpy(" in stripped:
            msg = "Possible buffer overflow via strcpy()"
            findings.append({"file": display, "line": i, "severity": "error", "message": msg})
            out_lines.append(f"[{display}:{i}]: (error) {msg}")

        if "memcpy(" in stripped and "sizeof(src)" in stripped:
            msg = "Possible buffer overflow: memcpy uses sizeof(src)"
            findings.append({"file": display, "line": i, "severity": "error", "message": msg})
            out_lines.append(f"[{display}:{i}]: (error) {msg}")

        if re.search(r"\bsystem\s*\(", stripped):
            msg = "Command execution with system() may be unsafe"
            findings.append({"file": display, "line": i, "severity": "warning", "message": msg})
            out_lines.append(f"[{display}:{i}]: (warning) {msg}")

        if re.search(r"\brand\s*\(", stripped):
            msg = "Use of rand() is a weak PRNG"
            findings.append({"file": display, "line": i, "severity": "style", "message": msg})
            out_lines.append(f"[{display}:{i}]: (style) {msg}")

        m = re.search(r"\b(\w+)\b\s*=\s*\([^)]*\)?\s*malloc\s*\(", stripped)
        if m:
            var = m.group(1)
            malloc_vars[var] = {"malloc_line": i, "checked": False}

        for var, state in list(malloc_vars.items()):
            if state.get("checked"):
                continue
            # Consider a check as any if statement mentioning the var.
            if re.search(rf"\bif\s*\(\s*!?\s*{re.escape(var)}\b", stripped):
                state["checked"] = True
                continue
            # Consider a use as indexing or deref/field access.
            if re.search(rf"\b{re.escape(var)}\s*(\[|->)", stripped) or re.search(rf"\*\s*{re.escape(var)}\b", stripped):
                msg = f"Possible null pointer dereference: {var} (malloc without NULL check)"
                findings.append({"file": display, "line": i, "severity": "warning", "message": msg})
                out_lines.append(f"[{display}:{i}]: (warning) {msg}")
                state["checked"] = True

    return "\n".join(out_lines), findings
