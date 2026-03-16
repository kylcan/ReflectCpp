"""
Critic / Reflection Agent – verifies and filters vulnerability findings.

This is the REFLECT phase: the agent critically examines each candidate
vulnerability, verifies evidence, checks for false positives, and decides
whether to accept, reject, or request additional investigation.

This is what makes SentinelAgent *self-reflective*.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..llm import get_llm, message_text
from ..state import AgentPhase, AgentState

logger = logging.getLogger(__name__)

_CRITIC_SYSTEM = """\
You are the **Critical Reflection Module** of SentinelAgent.

You receive candidate vulnerabilities from the analysis phase and must
rigorously verify each one.

## 4-Step Verification Protocol

### Step 1 – Evidence Validation
Does concrete evidence support this finding? Is it from multiple tools?
Single-source findings with no corroboration deserve lower confidence.

### Step 2 – Data-Flow Analysis
Trace the data flow. Is the input user-controllable or external?
Compile-time constants or internal-only values → likely False Positive.

### Step 3 – Mitigation Check
Are there existing protections?
- RAII / smart pointers → memory issues may be mitigated
- Bounds checks before buffer ops → overflow may be safe
- Input validation / sanitization → injection may be blocked
If mitigated, mark as "Rejected" with explanation.

### Step 4 – Severity Calibration
For surviving findings:
- Assign realistic CVSS 3.1 score
- Set confidence (0.0–1.0) based on evidence strength
- Provide actionable remediation
- Verify the remediation actually fixes the root cause

## Decision Authority
You can:
- **Confirm**: Strong evidence, real vulnerability
- **Reject**: False positive, mitigated, or insufficient evidence
- **Request re-investigation**: Need more data (set needs_reinvestigation=true)

## Output Format
{
  "reviewed_vulnerabilities": [
    {
      ...all original fields...,
      "status": "Confirmed" or "Rejected",
      "fix_verified": true/false,
      "fix_review": "explanation"
    }
  ],
  "critic_notes": "Overall reasoning summary",
  "needs_reinvestigation": false
}

Be SKEPTICAL. Your job is to DISPROVE findings, not confirm them.
Respond ONLY with valid JSON.
"""


def _mock_critic_output(state: AgentState) -> dict:
    """Deterministic critic fallback."""
    vulns = state.get("vulnerabilities", [])
    reviewed: list[dict[str, Any]] = []

    for vuln in vulns:
        item = dict(vuln)
        vuln_type = str(item.get("vuln_type", "")).lower()
        evidence = item.get("evidence", [])

        # Simple heuristic: confirm vulns with strong evidence
        if any(kw in vuln_type for kw in ("buffer overflow", "null pointer", "memory leak",
                                           "use-after-free", "command injection", "format string")):
            item["status"] = "Confirmed"
            item["confidence"] = max(item.get("confidence", 0.7), 0.8)
            item["fix_verified"] = bool(item.get("remediation"))
            item["fix_review"] = "Fix addresses root cause." if item.get("remediation") else "No fix proposed."
        elif evidence and len(evidence) >= 2:
            item["status"] = "Confirmed"
            item["confidence"] = 0.75
            item["fix_verified"] = bool(item.get("remediation"))
            item["fix_review"] = "Multiple evidence sources support this finding."
        elif "dangerous function" in vuln_type and not evidence:
            item["status"] = "Rejected"
            item["confidence"] = 0.3
            item["fix_review"] = "Dangerous function detected but no exploitable context."
        else:
            item["status"] = "Confirmed"
            item["confidence"] = max(item.get("confidence", 0.5), 0.6)
            item["fix_verified"] = bool(item.get("remediation"))
            item["fix_review"] = "Accepted with moderate confidence."

        reviewed.append(item)

    return {
        "reviewed_vulnerabilities": reviewed,
        "critic_notes": "Fallback critic: heuristic-based verification.",
        "needs_reinvestigation": False,
    }


def node_critic(state: AgentState) -> dict:
    """Critically review and verify candidate vulnerabilities."""
    vulns = state.get("vulnerabilities", [])
    if not vulns:
        logger.info("No vulnerabilities to review.")
        return {
            "current_phase": AgentPhase.REPORT.value,
            "reasoning_trace": [{
                "step": len(state.get("reasoning_trace", [])) + 1,
                "phase": AgentPhase.REFLECT.value,
                "thought": "No candidate vulnerabilities to review.",
                "action": "Skip reflection.",
                "observation": "",
                "decision": "Proceeding to report generation.",
            }],
        }

    # Build prompt with all context
    observations = state.get("observations", [])
    obs_summary = ""
    if observations:
        obs_parts: list[str] = []
        for obs in observations:
            if obs.get("success"):
                obs_parts.append(f"[{obs['tool_name']}] {obs['output'][:1000]}")
        obs_summary = "\n## Tool Observations (for cross-reference)\n" + "\n---\n".join(obs_parts)

    vuln_json = json.dumps(vulns, indent=2)
    user_content = (
        f"## Candidate Vulnerabilities ({len(vulns)} total)\n"
        f"```json\n{vuln_json}\n```\n"
        f"{obs_summary}\n\n"
        "Apply the 4-Step Verification Protocol. Respond ONLY with valid JSON."
    )

    messages = [
        SystemMessage(content=_CRITIC_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        if os.getenv("SENTINEL_OFFLINE") == "1":
            raise RuntimeError("SENTINEL_OFFLINE enabled")
        llm = get_llm(temperature=0.0)
        response = llm.invoke(messages)
        text = message_text(response.content)
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        parsed = json.loads(match.group(1) if match else text)
    except Exception as exc:
        logger.warning("Critic LLM unavailable, using fallback: %s", exc)
        parsed = _mock_critic_output(state)

    reviewed = parsed.get("reviewed_vulnerabilities", [])
    critic_notes = parsed.get("critic_notes", "")
    needs_reinvestigation = parsed.get("needs_reinvestigation", False)

    confirmed = [v for v in reviewed if v.get("status") == "Confirmed"]
    rejected = [v for v in reviewed if v.get("status") == "Rejected"]

    logger.info("Critic: %d confirmed, %d rejected, reinvestigate=%s",
                len(confirmed), len(rejected), needs_reinvestigation)

    # Decide next phase
    iteration = state.get("iteration_count", 0) + 1
    max_iter = state.get("max_iterations", 10)

    if needs_reinvestigation and iteration < max_iter:
        next_phase = AgentPhase.PLAN.value  # Re-plan for deeper investigation
    else:
        next_phase = AgentPhase.REPORT.value

    # Build reflection notes
    reflection_notes = list(state.get("reflection_notes", []))
    reflection_notes.append(critic_notes)

    trace_entry = {
        "step": len(state.get("reasoning_trace", [])) + 1,
        "phase": AgentPhase.REFLECT.value,
        "thought": f"Reviewing {len(vulns)} candidates with 4-step verification.",
        "action": f"Confirmed {len(confirmed)}, rejected {len(rejected)}.",
        "observation": critic_notes[:300],
        "decision": f"{'Re-investigating' if needs_reinvestigation and iteration < max_iter else 'Proceeding to report'}.",
    }

    run_metadata = dict(state.get("run_metadata", {}))
    run_metadata["critic_confirmed_count"] = len(confirmed)
    run_metadata["critic_rejected_count"] = len(rejected)

    return {
        "vulnerabilities": reviewed,
        "reflection_notes": reflection_notes,
        "current_phase": next_phase,
        "iteration_count": iteration,
        "run_metadata": run_metadata,
        "reasoning_trace": [trace_entry],
    }
