"""
cppcheck static analysis tool.

Runs cppcheck on a file or directory and returns diagnostic output.
Falls back to mock output when cppcheck is not installed.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

from .base import BaseTool

logger = logging.getLogger(__name__)

_MOCK_CPPCHECK = """\
[{file}:18]: (error) Array 'buffer[64]' accessed at index 128, which is out of bounds.
[{file}:34]: (warning) Possible null pointer dereference: ctx
[{file}:52]: (style) Variable 'key' is assigned a value that is never used.
[{file}:67]: (error) Memory leak: secret_buf
"""


class CppcheckTool(BaseTool):
    name = "cppcheck"
    description = (
        "Run cppcheck static analysis on a C/C++ file. Returns diagnostics "
        "including buffer overflows, null pointer dereferences, memory leaks, "
        "and style warnings. Input: file_path (string)."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the C/C++ file to analyze."},
            },
            "required": ["file_path"],
        }

    def execute(self, **kwargs: Any) -> str:
        file_path = kwargs.get("file_path", "")
        if not file_path:
            return "Error: file_path is required."

        if not os.path.isfile(file_path):
            return f"Error: file not found: {file_path}"

        if not shutil.which("cppcheck"):
            logger.warning("cppcheck not installed – using mock output.")
            return _MOCK_CPPCHECK.format(file=os.path.basename(file_path))

        try:
            result = subprocess.run(
                ["cppcheck", "--enable=all", "--inconclusive", "--force",
                 "--quiet", str(file_path)],
                capture_output=True, text=True, timeout=60,
            )
            output = result.stderr or result.stdout
            return output.strip() if output.strip() else "(cppcheck: no findings)"
        except subprocess.TimeoutExpired:
            return "(cppcheck timed out after 60s)"
        except Exception as exc:
            return f"(cppcheck error: {exc})"
