"""
Report Generator Agent – compiles findings into a structured security report.

Produces both human-readable Markdown and machine-readable JSON output.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ..state import AgentPhase, AgentState

logger = logging.getLogger(__name__)


def _severity_order(sev: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(sev, 5)


def node_report_generator(state: AgentState) -> dict:
    """Generate the final audit report in Markdown + JSON."""
    vulns = state.get("vulnerabilities", [])
    confirmed = sorted(
        [v for v in vulns if v.get("status") == "Confirmed"],
        key=lambda v: _severity_order(v.get("severity", "Info")),
    )
    rejected = [v for v in vulns if v.get("status") == "Rejected"]
    trace = state.get("reasoning_trace", [])
    plan = state.get("plan", {})
    repo_path = state.get("repo_path", "unknown")
    iterations = state.get("iteration_count", 0)

    # ── Markdown Report ───────────────────────────────────────────────────
    lines: list[str] = []
    lines.append("# 🛡️ SentinelAgent Security Audit Report\n")
    lines.append(f"**Repository:** `{repo_path}`  ")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Agent Iterations:** {iterations}  ")
    lines.append(f"**Confirmed Vulnerabilities:** {len(confirmed)}  ")
    lines.append(f"**Rejected (False Positives):** {len(rejected)}\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    if confirmed:
        crit_count = sum(1 for v in confirmed if v.get("severity") == "Critical")
        high_count = sum(1 for v in confirmed if v.get("severity") == "High")
        med_count = sum(1 for v in confirmed if v.get("severity") == "Medium")
        low_count = sum(1 for v in confirmed if v.get("severity") in ("Low", "Info"))
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        if crit_count:
            lines.append(f"| 🔴 Critical | {crit_count} |")
        if high_count:
            lines.append(f"| 🟠 High | {high_count} |")
        if med_count:
            lines.append(f"| 🟡 Medium | {med_count} |")
        if low_count:
            lines.append(f"| 🟢 Low/Info | {low_count} |")
        lines.append("")
    else:
        lines.append("✅ No confirmed vulnerabilities found.\n")

    # Audit Strategy
    if plan:
        lines.append("## Audit Strategy\n")
        lines.append(f"**Objective:** {plan.get('objective', 'N/A')}  ")
        lines.append(f"**Strategy:** {plan.get('strategy', 'N/A')}  ")
        tasks = plan.get("tasks", [])
        completed_tasks = [t for t in tasks if t.get("status") == "completed"]
        lines.append(f"**Tasks Executed:** {len(completed_tasks)}/{len(tasks)}\n")

    # Confirmed Vulnerabilities
    if confirmed:
        lines.append("## Confirmed Vulnerabilities\n")
        for i, v in enumerate(confirmed, 1):
            sev = v.get("severity", "Medium")
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
            lines.append(f"### {i}. {sev_icon} {v.get('vuln_type', 'Unknown')}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **CWE** | {v.get('cwe_id', 'N/A')} |")
            lines.append(f"| **Location** | `{v.get('location', '')}` |")
            lines.append(f"| **Severity** | {sev} (CVSS: {v.get('cvss_score', 'N/A')}) |")
            lines.append(f"| **Confidence** | {v.get('confidence', 'N/A')} |")
            lines.append(f"| **Exploitability** | {v.get('exploitability', 'N/A')} |")
            lines.append("")
            lines.append(f"**Description:** {v.get('description', '')}\n")

            data_flow = v.get("data_flow", "")
            if data_flow:
                lines.append(f"**Data Flow:** `{data_flow}`\n")

            evidence = v.get("evidence", [])
            if evidence:
                lines.append("**Evidence:**")
                for e in evidence:
                    lines.append(f"- `{e}`")
                lines.append("")

            remediation = v.get("remediation", "")
            if remediation:
                lines.append(f"**Remediation:** {remediation}\n")

            fix_verified = v.get("fix_verified")
            if fix_verified is not None:
                icon = "✅" if fix_verified else "⚠️"
                lines.append(f"**Fix Verified:** {icon} {v.get('fix_review', '')}\n")

            funcs = v.get("related_functions", [])
            if funcs:
                lines.append(f"**Related Functions:** {', '.join(f'`{f}`' for f in funcs)}\n")
            lines.append("---\n")

    # Rejected Findings
    if rejected:
        lines.append("## Rejected Findings (False Positives)\n")
        lines.append("| # | Type | Location | Reason |")
        lines.append("|---|------|----------|--------|")
        for i, v in enumerate(rejected, 1):
            lines.append(
                f"| {i} | {v.get('vuln_type','')} "
                f"| `{v.get('location','')}` "
                f"| {v.get('fix_review', v.get('description',''))[:100]} |"
            )
        lines.append("")

    # Reasoning Trace
    if trace:
        lines.append("## Agent Reasoning Trace\n")
        lines.append("| Step | Phase | Thought | Action | Decision |")
        lines.append("|------|-------|---------|--------|----------|")
        for t in trace:
            lines.append(
                f"| {t.get('step', '')} "
                f"| {t.get('phase', '')} "
                f"| {t.get('thought', '')[:60]} "
                f"| {t.get('action', '')[:60]} "
                f"| {t.get('decision', '')[:60]} |"
            )
        lines.append("")

    # Reflection Notes
    refl_notes = state.get("reflection_notes", [])
    if refl_notes:
        lines.append("## Reflection Notes\n")
        for idx, note in enumerate(refl_notes, 1):
            lines.append(f"### Round {idx}\n{note}\n")

    report_md = "\n".join(lines)

    # ── JSON Report ───────────────────────────────────────────────────────
    report_json: dict[str, Any] = {
        "repository": repo_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "iterations": iterations,
        "confirmed_count": len(confirmed),
        "rejected_count": len(rejected),
        "confirmed_vulnerabilities": confirmed,
        "rejected_vulnerabilities": rejected,
        "reasoning_trace": trace,
        "plan": plan,
    }

    logger.info("Report generated: %d confirmed, %d rejected, %d trace steps.",
                len(confirmed), len(rejected), len(trace))

    trace_entry = {
        "step": len(trace) + 1,
        "phase": AgentPhase.REPORT.value,
        "thought": "Compiling final audit report.",
        "action": f"Generated report with {len(confirmed)} confirmed vulnerabilities.",
        "observation": "",
        "decision": "Audit complete.",
    }

    return {
        "final_report": report_md,
        "report_json": report_json,
        "current_phase": AgentPhase.DONE.value,
        "reasoning_trace": [trace_entry],
    }
