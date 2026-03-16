#!/usr/bin/env python3
"""
sentinel_run.py – CLI entry point for SentinelAgent.

Usage:
    python sentinel_run.py path/to/repo              # audit a repository
    python sentinel_run.py path/to/file.cpp           # audit a single file
    python sentinel_run.py path/to/repo --trace       # show reasoning trace
    python sentinel_run.py path/to/repo -o report.md  # save report to file

Environment variables:
    GPT5_KEY / OPENAI_API_KEY     – LLM API key
    CHATGPT_MODEL / AUDIT_MODEL   – model name (default: gpt-4o)
    CHATGPT_BASE_URL              – custom endpoint
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure local imports work
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="🛡️ SentinelAgent – Autonomous AI Security Auditing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python sentinel_run.py samples/vuln_sample.cpp
  python sentinel_run.py /path/to/repo --max-iter 15
  python sentinel_run.py . --trace -o report.md
  python sentinel_run.py . --json-report audit.json
        """,
    )
    parser.add_argument(
        "target",
        help="Repository directory or single file to audit.",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Save Markdown report to this file.",
    )
    parser.add_argument(
        "--json-report",
        default=None,
        help="Save JSON report to this file.",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=10,
        help="Max reasoning loop iterations (default: 10).",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print the full reasoning trace.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target not found – {target}", file=sys.stderr)
        sys.exit(1)

    from sentinel_agent.graph import run_agent

    print(f"\n🛡️  SentinelAgent v1.0.0")
    print(f"{'='*60}")
    print(f"Target: {target}")
    print(f"Mode: {'Single file' if target.is_file() else 'Repository'}")
    print(f"Max iterations: {args.max_iter}")
    print(f"{'='*60}\n")

    result = run_agent(
        repo_path=str(target),
        max_iterations=args.max_iter,
    )

    # Print report
    report = result.get("final_report", "(no report generated)")
    print(report)

    # Print reasoning trace if requested
    if args.trace:
        trace = result.get("reasoning_trace", [])
        print(f"\n{'='*60}")
        print(f"REASONING TRACE ({len(trace)} steps)")
        print(f"{'='*60}\n")
        for entry in trace:
            step = entry.get("step", "?")
            phase = entry.get("phase", "?")
            print(f"Step {step} [{phase.upper()}]")
            if entry.get("thought"):
                print(f"  Thought:     {entry['thought']}")
            if entry.get("action"):
                print(f"  Action:      {entry['action']}")
            if entry.get("observation"):
                obs = entry['observation']
                if len(obs) > 200:
                    obs = obs[:200] + "..."
                print(f"  Observation: {obs}")
            if entry.get("decision"):
                print(f"  Decision:    {entry['decision']}")
            print()

    # Save outputs
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report, encoding="utf-8")
        print(f"\n💾 Markdown report saved to: {out_path}")
    elif target.is_file():
        default_path = target.with_suffix(".sentinel_report.md")
        default_path.write_text(report, encoding="utf-8")
        print(f"\n💾 Report saved to: {default_path}")
    else:
        default_path = target / "sentinel_report.md"
        default_path.write_text(report, encoding="utf-8")
        print(f"\n💾 Report saved to: {default_path}")

    if args.json_report:
        json_path = Path(args.json_report)
        report_json = result.get("report_json", {})
        json_path.write_text(json.dumps(report_json, indent=2, default=str), encoding="utf-8")
        print(f"💾 JSON report saved to: {json_path}")

    # Summary
    vulns = result.get("vulnerabilities", [])
    confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
    print(f"\n🛡️  Audit complete: {len(confirmed)} confirmed vulnerabilities.")


if __name__ == "__main__":
    main()
