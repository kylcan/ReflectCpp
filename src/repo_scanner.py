"""
src/repo_scanner.py – Repo-level multi-file audit orchestrator.

Recursively discovers C/C++ source files under a directory, runs the
full audit pipeline on each, and produces a consolidated report.

Usage (CLI):
    python -m src.repo_scanner /path/to/repo

Usage (Python):
    from src.repo_scanner import scan_repo
    results = scan_repo("/path/to/repo")
"""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .graph import run_audit

logger = logging.getLogger(__name__)

# File extensions to scan
_CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"}


@dataclass
class FileAuditResult:
    """Audit result for a single file."""
    file_path: str
    confirmed: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    iterations: int = 0
    report_markdown: str = ""
    latency_s: float = 0.0
    error: str | None = None


@dataclass
class RepoAuditResult:
    """Aggregated result for an entire repository."""
    root_dir: str
    files_scanned: int = 0
    files_with_vulns: int = 0
    total_confirmed: int = 0
    total_rejected: int = 0
    total_latency_s: float = 0.0
    file_results: list[FileAuditResult] = field(default_factory=list)
    consolidated_report: str = ""


def discover_files(root: str | Path, extensions: set[str] | None = None) -> list[Path]:
    """Recursively find C/C++ source files under *root*."""
    exts = extensions or _CPP_EXTENSIONS
    root_path = Path(root)
    if not root_path.is_dir():
        raise FileNotFoundError(f"Not a directory: {root}")

    files = sorted(
        p for p in root_path.rglob("*")
        if p.is_file() and p.suffix.lower() in exts
    )
    logger.info("Discovered %d C/C++ files under %s", len(files), root)
    return files


def audit_file(file_path: Path) -> FileAuditResult:
    """Run the full audit pipeline on a single file."""
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return FileAuditResult(
            file_path=str(file_path),
            error=f"Failed to read file: {exc}",
        )

    t0 = time.time()
    try:
        result = run_audit(source_code, source_file_path=str(file_path))
        latency = time.time() - t0

        vulns = result.get("vulnerabilities", [])
        confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
        rejected = [v for v in vulns if v.get("status") == "Rejected"]

        return FileAuditResult(
            file_path=str(file_path),
            confirmed=confirmed,
            rejected=rejected,
            iterations=result.get("iteration_count", 0),
            report_markdown=result.get("final_report", ""),
            latency_s=latency,
        )
    except Exception as exc:
        logger.exception("Audit failed for %s", file_path)
        return FileAuditResult(
            file_path=str(file_path),
            latency_s=time.time() - t0,
            error=str(exc),
        )


def _build_consolidated_report(repo_result: RepoAuditResult) -> str:
    """Build a Markdown summary across all scanned files."""
    lines: list[str] = []
    lines.append("# 🔒 Repository Security Audit Report\n")
    lines.append(f"**Root:** `{repo_result.root_dir}`  ")
    lines.append(f"**Files scanned:** {repo_result.files_scanned}  ")
    lines.append(f"**Files with vulnerabilities:** {repo_result.files_with_vulns}  ")
    lines.append(f"**Total confirmed:** {repo_result.total_confirmed}  ")
    lines.append(f"**Total rejected:** {repo_result.total_rejected}  ")
    lines.append(f"**Total time:** {repo_result.total_latency_s:.1f}s\n")

    # Summary table
    lines.append("## Per-File Summary\n")
    lines.append("| File | Confirmed | Rejected | Iterations | Time |")
    lines.append("|------|-----------|----------|------------|------|")
    for fr in repo_result.file_results:
        status = f"❌ {fr.error}" if fr.error else ""
        lines.append(
            f"| `{fr.file_path}` "
            f"| {len(fr.confirmed)} "
            f"| {len(fr.rejected)} "
            f"| {fr.iterations} "
            f"| {fr.latency_s:.1f}s {status}|"
        )

    # Per-file details (only files with confirmed vulns)
    files_with_vulns = [fr for fr in repo_result.file_results if fr.confirmed]
    if files_with_vulns:
        lines.append("\n## Detailed Findings\n")
        for fr in files_with_vulns:
            lines.append(f"### {fr.file_path}\n")
            for i, v in enumerate(fr.confirmed, 1):
                lines.append(f"**{i}. {v.get('vuln_type', '')}**")
                lines.append(f"- CWE: {v.get('cwe_id', 'N/A')}")
                lines.append(f"- Location: {v.get('location', '')}")
                lines.append(f"- Severity: {v.get('severity', '')} (CVSS {v.get('cvss_score', 'N/A')})")
                lines.append(f"- Description: {v.get('description', '')}")
                rem = v.get("remediation", "")
                if rem:
                    lines.append(f"- Remediation: {rem}")
                lines.append("")

    return "\n".join(lines)


def scan_repo(
    root: str | Path,
    extensions: set[str] | None = None,
) -> RepoAuditResult:
    """Scan all C/C++ files under *root* and return aggregated results."""
    files = discover_files(root, extensions)

    repo_result = RepoAuditResult(root_dir=str(root))
    repo_result.files_scanned = len(files)

    for i, fp in enumerate(files, 1):
        logger.info("[%d/%d] Auditing %s …", i, len(files), fp)
        fr = audit_file(fp)
        repo_result.file_results.append(fr)
        repo_result.total_confirmed += len(fr.confirmed)
        repo_result.total_rejected += len(fr.rejected)
        repo_result.total_latency_s += fr.latency_s
        if fr.confirmed:
            repo_result.files_with_vulns += 1

    repo_result.consolidated_report = _build_consolidated_report(repo_result)
    return repo_result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Repo-level C/C++ security audit")
    parser.add_argument("directory", help="Root directory to scan")
    parser.add_argument("-o", "--output", default=None, help="Output report path (default: <dir>/audit_report.md)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    result = scan_repo(args.directory)
    print(result.consolidated_report)

    out_path = Path(args.output) if args.output else Path(args.directory) / "audit_report.md"
    out_path.write_text(result.consolidated_report, encoding="utf-8")
    print(f"\n💾 Report saved to: {out_path}")


if __name__ == "__main__":
    main()
