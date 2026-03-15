"""
main.py – Entry point for the Autonomous Code Security Audit Agent.

Usage:
    python main.py                          # audit the bundled sample
    python main.py path/to/your_code.cpp    # audit a custom file
    python main.py --phase1                 # demo Phase 1 (naive prompt)

Environment variables:
    OPENAI_API_KEY   – required (or ANTHROPIC_API_KEY when using Claude)
    AUDIT_MODEL      – model name, default "gpt-4o"
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Ensure local package imports work even when launched by external wrappers.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Phase 1 – Naive single-prompt demonstration
# ---------------------------------------------------------------------------
# This function shows what happens when you simply throw code at an LLM
# without structure, grounding, or reflection.  The output is typically:
#   • Hallucinated line numbers
#   • False Positives caused by misunderstanding RAII / safe functions
#   • Missing the *real* subtle bugs (branch-specific overflow)
# ---------------------------------------------------------------------------

def run_phase1_demo(source_code: str) -> None:
    """Demonstrate how a naive single-prompt approach fails."""
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI

    print("\n" + "=" * 72)
    print("PHASE 1 – Naive Single-Prompt Audit (no reflection, no grounding)")
    print("=" * 72 + "\n")

    api_key = os.getenv("GPT5_KEY") or os.getenv("OPENAI_API_KEY")
    model = os.getenv("CHATGPT_MODEL") or os.getenv("AUDIT_MODEL", "gpt-4o")
    base_url = (
        os.getenv("CHATGPT_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE")
    )

    llm_kwargs = {
        "model": model,
        "temperature": 0.0,
    }
    if api_key:
        llm_kwargs["api_key"] = api_key
    if base_url:
        llm_kwargs["base_url"] = base_url.rstrip("/")

    llm = ChatOpenAI(**llm_kwargs)

    messages = [
        SystemMessage(content="You are a security auditor. Find all vulnerabilities in this C++ code."),
        HumanMessage(content=f"```cpp\n{source_code}\n```"),
    ]
    response = llm.invoke(messages)
    print(response.content)
    print("\n⚠️  Notice: Phase 1 typically produces hallucinated line numbers,")
    print("   false positives, and misses conditional bugs.\n")


# ---------------------------------------------------------------------------
# Phase 2 + 3 – Full multi-agent pipeline
# ---------------------------------------------------------------------------

def run_full_pipeline(source_code: str, file_path: str | None) -> str:
    """Run the complete LangGraph audit pipeline (Phase 2 + 3)."""
    from src.graph import run_audit

    print("\n" + "=" * 72)
    print("PHASE 2+3 – Multi-Agent Reflection Pipeline")
    print("  • Phase 2: Critic node filters False Positives")
    print("  • Phase 3: cppcheck static hints ground the analysis")
    print("=" * 72 + "\n")

    result = run_audit(source_code, source_file_path=file_path)
    report = result.get("final_report", "(no report generated)")
    print(report)

    # Also dump raw vulnerabilities for inspection
    vulns = result.get("vulnerabilities", [])
    print("\n--- Raw vulnerability data (JSON) ---")
    print(json.dumps(vulns, indent=2))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous C++ Code Security Audit Agent",
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Path to a .cpp file to audit (default: samples/vuln_sample.cpp)",
    )
    parser.add_argument(
        "--phase1",
        action="store_true",
        help="Run the Phase 1 naive-prompt demo instead of the full pipeline.",
    )
    parser.add_argument(
        "--all-phases",
        action="store_true",
        help="Run Phase 1 first, then the full pipeline, for comparison.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    parser.add_argument(
        "--repo",
        action="store_true",
        help="Treat FILE as a directory and audit all C/C++ files recursively.",
    )
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Resolve source file
    if args.file:
        cpp_path = Path(args.file)
    else:
        cpp_path = Path(__file__).parent / "samples" / "vuln_sample.cpp"

    # --- Repo-level scan mode ---
    if args.repo:
        from src.repo_scanner import scan_repo

        repo_dir = cpp_path if cpp_path.is_dir() else cpp_path.parent
        if not repo_dir.is_dir():
            print(f"Error: not a directory – {repo_dir}", file=sys.stderr)
            sys.exit(1)

        print(f"📁 Scanning repository: {repo_dir}")
        result = scan_repo(str(repo_dir))
        print(result.consolidated_report)

        report_path = repo_dir / "audit_report.md"
        report_path.write_text(result.consolidated_report, encoding="utf-8")
        print(f"\n💾 Report saved to: {report_path}")
        return

    # --- Single file mode ---
    if not cpp_path.is_file():
        print(f"Error: file not found – {cpp_path}", file=sys.stderr)
        sys.exit(1)

    source_code = cpp_path.read_text(encoding="utf-8")
    print(f"📄 Auditing: {cpp_path}  ({len(source_code)} bytes)")

    if args.phase1 or args.all_phases:
        run_phase1_demo(source_code)

    if not args.phase1 or args.all_phases:
        report = run_full_pipeline(source_code, str(cpp_path))

        # Save report to file
        report_path = cpp_path.with_suffix(".audit_report.md")
        report_path.write_text(report, encoding="utf-8")
        print(f"\n💾 Report saved to: {report_path}")


if __name__ == "__main__":
    main()
