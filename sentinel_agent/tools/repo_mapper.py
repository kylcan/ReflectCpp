"""
Repository structure mapper tool.

Scans a directory to build a structural understanding of the codebase:
file tree, language distribution, and high-risk file identification.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .base import BaseTool

_EXTENSION_LANGUAGE = {
    ".c": "C", ".h": "C/C++ Header",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".hpp": "C++ Header", ".hxx": "C++ Header",
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift",
    ".cmake": "CMake", ".sh": "Shell", ".bash": "Shell",
}

_HIGH_RISK_PATTERNS = [
    "auth", "login", "crypto", "crypt", "password", "passwd",
    "secret", "token", "session", "admin", "privilege",
    "payment", "billing", "key", "cert", "ssl", "tls",
    "parse", "deserializ", "exec", "eval", "command",
    "buffer", "alloc", "malloc", "memory", "socket", "network",
]

_DEPENDENCY_FILES = {
    "CMakeLists.txt", "Makefile", "conanfile.txt", "conanfile.py",
    "vcpkg.json", "meson.build", "BUILD", "WORKSPACE",
    "package.json", "requirements.txt", "Cargo.toml", "go.mod",
    "pom.xml", "build.gradle",
}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
              "build", "dist", "target", ".cache", ".tox"}


class RepoMapperTool(BaseTool):
    name = "repo_mapper"
    description = (
        "Map a repository's structure: file tree, language distribution, "
        "dependency files, and high-risk files (auth, crypto, parsing, "
        "memory management). Input: directory path."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Root directory to map."},
                "max_depth": {"type": "integer", "description": "Max directory depth (default 5)."},
                "max_files": {"type": "integer", "description": "Max files to scan before stopping (default 20000)."},
            },
            "required": ["directory"],
        }

    def execute(self, **kwargs: Any) -> str:
        directory = kwargs.get("directory", "")
        max_depth = kwargs.get("max_depth", 5)
        max_files = kwargs.get("max_files", 20000)

        if not directory or not os.path.isdir(directory):
            return f"Error: not a directory: {directory}"

        root = Path(directory).resolve()
        file_tree: list[str] = []
        languages: dict[str, int] = {}
        high_risk: list[str] = []
        dep_files: list[str] = []
        total_files = 0
        truncated = False

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

            rel_dir = os.path.relpath(dirpath, root)
            depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
            if depth > max_depth:
                dirnames.clear()
                continue

            for fn in sorted(filenames):
                total_files += 1
                if max_files and total_files > int(max_files):
                    truncated = True
                    break
                rel_path = os.path.join(rel_dir, fn) if rel_dir != "." else fn
                file_tree.append(rel_path)

                ext = Path(fn).suffix.lower()
                lang = _EXTENSION_LANGUAGE.get(ext, "")
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1

                if fn in _DEPENDENCY_FILES:
                    dep_files.append(rel_path)

                fn_lower = fn.lower()
                if any(p in fn_lower for p in _HIGH_RISK_PATTERNS):
                    high_risk.append(rel_path)

            if truncated:
                break

        # Build human-readable output (kept for backward compatibility)
        lines: list[str] = [
            f"Repository: {root}",
            f"Total files: {total_files}" + (" (truncated)" if truncated else ""),
            "",
            "## Language Distribution",
        ]
        for lang, count in sorted(languages.items(), key=lambda x: -x[1]):
            lines.append(f"  {lang}: {count} files")

        if dep_files:
            lines.append("\n## Dependency Files")
            for f in dep_files[:200]:
                lines.append(f"  {f}")
            if len(dep_files) > 200:
                lines.append(f"  ... and {len(dep_files) - 200} more")

        if high_risk:
            lines.append(f"\n## High-Risk Files ({len(high_risk)})")
            for f in high_risk[:200]:
                lines.append(f"  ⚠ {f}")
            if len(high_risk) > 200:
                lines.append(f"  ... and {len(high_risk) - 200} more")

        lines.append(f"\n## File Tree ({min(len(file_tree), 100)} of {len(file_tree)} shown)")
        for f in file_tree[:100]:
            lines.append(f"  {f}")
        if len(file_tree) > 100:
            lines.append(f"  ... and {len(file_tree) - 100} more files")

        payload = {
            "tool": self.name,
            "root": str(root),
            "total_files": total_files,
            "truncated": truncated,
            "languages": languages,
            "dependency_files": dep_files[:500],
            "high_risk_files": high_risk[:500],
            "file_tree": file_tree[:1000],
            "human": "\n".join(lines),
        }
        return json.dumps(payload, ensure_ascii=False)
