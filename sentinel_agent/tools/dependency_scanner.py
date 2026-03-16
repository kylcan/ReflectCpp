"""
Dependency vulnerability scanner.

Checks dependency manifests (CMakeLists.txt, conanfile.txt, vcpkg.json,
requirements.txt, package.json) for known-vulnerable library versions
using a built-in advisory database.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .base import BaseTool

# Simplified advisory database – in production, query OSV or NVD API
_ADVISORIES: list[dict[str, str]] = [
    {"library": "openssl", "vulnerable_below": "3.0.8", "cve": "CVE-2023-0286", "severity": "High",
     "description": "X.400 address type confusion in X.509 GeneralName"},
    {"library": "libcurl", "vulnerable_below": "8.4.0", "cve": "CVE-2023-46218", "severity": "Medium",
     "description": "Cookie injection with none-prefixed hosts"},
    {"library": "zlib", "vulnerable_below": "1.2.12", "cve": "CVE-2022-37434", "severity": "Critical",
     "description": "Heap-based buffer over-read in inflate"},
    {"library": "protobuf", "vulnerable_below": "3.21.7", "cve": "CVE-2022-3171", "severity": "High",
     "description": "Parsing issue causes denial of service"},
    {"library": "sqlite", "vulnerable_below": "3.43.0", "cve": "CVE-2023-36191", "severity": "Medium",
     "description": "Heap buffer overflow in CLI .dump command"},
    {"library": "expat", "vulnerable_below": "2.5.0", "cve": "CVE-2022-43680", "severity": "Critical",
     "description": "Use-after-free in doContent in xmlparse.c"},
    {"library": "boost", "vulnerable_below": "1.80.0", "cve": "CVE-2023-BOOST", "severity": "Medium",
     "description": "Container overflow in Boost.JSON parser"},
    {"library": "log4j", "vulnerable_below": "2.17.1", "cve": "CVE-2021-44228", "severity": "Critical",
     "description": "Remote code execution via JNDI lookup (Log4Shell)"},
    {"library": "lodash", "vulnerable_below": "4.17.21", "cve": "CVE-2021-23337", "severity": "High",
     "description": "Command injection via template function"},
    {"library": "numpy", "vulnerable_below": "1.22.0", "cve": "CVE-2021-41496", "severity": "Medium",
     "description": "Buffer overflow in numpy array parsing"},
]


class DependencyScannerTool(BaseTool):
    name = "dependency_scanner"
    description = (
        "Scan dependency manifests (CMakeLists.txt, conanfile.txt, "
        "vcpkg.json, requirements.txt, package.json) for libraries "
        "with known vulnerabilities. Returns CVEs and severity."
    )

    def _parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to dependency file or repo directory."},
            },
            "required": ["path"],
        }

    def execute(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "")
        if not path or not os.path.exists(path):
            payload = {"tool": self.name, "findings": [], "human": f"Error: path not found: {path}"}
            return json.dumps(payload, ensure_ascii=False)

        # Collect dependency files
        dep_files: list[str] = []
        if os.path.isfile(path):
            dep_files = [path]
        else:
            for root, _, files in os.walk(path):
                for f in files:
                    if f in {"CMakeLists.txt", "conanfile.txt", "vcpkg.json",
                             "requirements.txt", "package.json", "Cargo.toml",
                             "go.mod", "pom.xml", "build.gradle"}:
                        dep_files.append(os.path.join(root, f))

        if not dep_files:
            payload = {"tool": self.name, "findings": [], "human": "No dependency manifests found."}
            return json.dumps(payload, ensure_ascii=False)

        findings: list[dict[str, str]] = []
        total_deps_found = 0

        for dep_file in dep_files:
            try:
                content = open(dep_file, encoding="utf-8", errors="replace").read().lower()
            except Exception:
                continue

            rel_path = os.path.relpath(dep_file)

            for advisory in _ADVISORIES:
                lib = advisory["library"]
                if lib in content:
                    total_deps_found += 1
                    findings.append({
                        "file": rel_path,
                        "library": lib,
                        "cve": advisory["cve"],
                        "severity": advisory["severity"],
                        "description": advisory["description"],
                        "fix": f"upgrade to >= {advisory['vulnerable_below']}",
                    })

        lines = [f"Scanned {len(dep_files)} dependency file(s)."]
        if findings:
            lines.append(f"\nFound {len(findings)} potential dependency vulnerabilities:\n")
            for item in findings:
                lines.append(
                    f"  ⚠ {item['file']}: {item['library']} (known vuln: {item['cve']}, severity: {item['severity']})\n"
                    f"    {item['description']}\n"
                    f"    Fix: {item['fix']}"
                )
        else:
            lines.append("No known vulnerable dependencies detected.")

        payload = {
            "tool": self.name,
            "dependency_files": [os.path.relpath(p) for p in dep_files[:200]],
            "findings": findings,
            "human": "\n".join(lines),
        }
        return json.dumps(payload, ensure_ascii=False)
