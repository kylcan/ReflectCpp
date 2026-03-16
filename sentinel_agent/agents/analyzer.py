"""
Security Analyzer Agent – synthesizes observations into vulnerability findings.

This is the OBSERVE phase: the agent reviews all tool observations
collected during the ACT phase and uses LLM reasoning to identify
actual vulnerabilities with structured evidence.
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

_ANALYZER_SYSTEM = """\
You are the **Security Analysis Module** of SentinelAgent, an autonomous AI security auditor.

You have just completed a series of tool-based analyses on a codebase. Your job is to
synthesize ALL the observations below into a structured vulnerability report.

## Analysis Rules
1. Cross-reference tool outputs: a grep match + cppcheck warning on the same location = high confidence.
2. Trace data flows: is the input user-controllable? External? Compile-time constant?
3. Check for existing mitigations (bounds checks, smart pointers, RAII).
4. Distinguish between real vulnerabilities and safe patterns.
5. Assign realistic severity based on exploitability and impact.

## Output Format
Return a JSON object:
{
  "vulnerabilities": [
    {
      "vuln_id": "V-001",
      "vuln_type": "Buffer Overflow (CWE-120)",
      "cwe_id": "CWE-120",
      "location": "file.cpp:42",
      "description": "Detailed explanation",
      "severity": "High",
      "status": "Candidate",
      "cvss_score": 8.1,
      "confidence": 0.9,
      "evidence": ["tool output line 1", "code snippet"],
      "data_flow": "user_input → strcpy → buffer[64]",
      "exploitability": "Likely",
      "remediation": "Replace with strncpy",
      "related_functions": ["func_name"]
    }
  ],
  "analysis_notes": "Summary of your analysis reasoning"
}

Be thorough but precise. Only report genuine findings with evidence.
Use severity values: Critical, High, Medium, Low, Info.
Respond ONLY with valid JSON.
"""


def _build_observation_summary(state: AgentState) -> str:
    """Compile all observations into a prompt-friendly summary."""
    observations = state.get("observations", [])
    parts: list[str] = []

    for i, obs in enumerate(observations, 1):
        tool = obs.get("tool_name", "unknown")
        success = obs.get("success", False)
        output = obs.get("output", "")
        args = obs.get("arguments", {})
        output_json = obs.get("output_json")

        parts.append(f"### Observation {i}: {tool}")
        parts.append(f"Arguments: {json.dumps(args)}")
        parts.append(f"Status: {'success' if success else 'FAILED'}")
        if output_json is not None:
            try:
                parts.append(f"Structured:\n{json.dumps(output_json, indent=2)[:3000]}")
            except Exception:
                parts.append("Structured: (unserializable)")
        parts.append(f"Output:\n{output}")
        parts.append("")

    return "\n".join(parts)


def _mock_analyzer_output(state: AgentState) -> dict:
    """Deterministic analyzer fallback."""
    observations = state.get("observations", [])
    vulns: list[dict[str, Any]] = []
    vuln_counter = 1

    for obs in observations:
        tool = obs.get("tool_name", "")
        output = obs.get("output", "")

        if tool == "cppcheck":
            # Parse cppcheck output for findings
            for line in output.splitlines():
                match = re.match(r"\[(.+?):(\d+)\]:\s*\((\w+)\)\s*(.*)", line)
                if match:
                    file_name, line_num, severity_str, desc = match.groups()
                    sev_map = {"error": "High", "warning": "Medium", "style": "Low", "information": "Info"}
                    vulns.append({
                        "vuln_id": f"V-{vuln_counter:03d}",
                        "vuln_type": _guess_cwe_from_desc(desc),
                        "cwe_id": _guess_cwe_id(desc),
                        "location": f"{file_name}:{line_num}",
                        "description": desc,
                        "severity": sev_map.get(severity_str, "Medium"),
                        "status": "Candidate",
                        "cvss_score": None,
                        "confidence": 0.7,
                        "evidence": [line.strip()],
                        "data_flow": "",
                        "exploitability": "Likely" if severity_str == "error" else "Unknown",
                        "remediation": "",
                        "related_functions": [],
                    })
                    vuln_counter += 1

        elif tool == "grep_scanner":
            # Parse grep matches
            for line in output.splitlines():
                match = re.match(r"(.+?):(\d+):\s*\[(.+?)\]\s*(.*)", line)
                if match:
                    file_name, line_num, func, cwe_note = match.groups()
                    vulns.append({
                        "vuln_id": f"V-{vuln_counter:03d}",
                        "vuln_type": f"Dangerous Function: {func}",
                        "cwe_id": m.group(0) if (m := re.search(r"CWE-\d+", cwe_note)) else "",
                        "location": f"{file_name}:{line_num}",
                        "description": cwe_note,
                        "severity": "Medium",
                        "status": "Candidate",
                        "cvss_score": None,
                        "confidence": 0.6,
                        "evidence": [line.strip()],
                        "data_flow": "",
                        "exploitability": "Unknown",
                        "remediation": "",
                        "related_functions": [],
                    })
                    vuln_counter += 1

    return {
        "vulnerabilities": vulns,
        "analysis_notes": "Fallback analyzer: parsed tool outputs without LLM reasoning.",
    }


def _guess_cwe_from_desc(desc: str) -> str:
    desc_lower = desc.lower()
    if "buffer" in desc_lower or "overflow" in desc_lower or "out of bounds" in desc_lower:
        return "Buffer Overflow (CWE-120)"
    if "null pointer" in desc_lower or "null" in desc_lower:
        return "Null Pointer Dereference (CWE-476)"
    if "memory leak" in desc_lower or "leak" in desc_lower:
        return "Memory Leak (CWE-401)"
    if "uninitialized" in desc_lower:
        return "Uninitialized Variable (CWE-457)"
    return "Code Quality Issue"


def _guess_cwe_id(desc: str) -> str:
    desc_lower = desc.lower()
    if "buffer" in desc_lower or "overflow" in desc_lower or "out of bounds" in desc_lower:
        return "CWE-120"
    if "null pointer" in desc_lower:
        return "CWE-476"
    if "memory leak" in desc_lower or "leak" in desc_lower:
        return "CWE-401"
    return ""


def node_analyzer(state: AgentState) -> dict:
    """Synthesize tool observations into structured vulnerability findings."""
    observations = state.get("observations", [])
    if not observations:
        logger.info("No observations to analyze.")
        return {
            "vulnerabilities": [],
            "current_phase": AgentPhase.REFLECT.value,
            "reasoning_trace": [{
                "step": len(state.get("reasoning_trace", [])) + 1,
                "phase": AgentPhase.OBSERVE.value,
                "thought": "No tool observations collected.",
                "action": "Skip analysis.",
                "observation": "",
                "decision": "Proceeding with empty findings.",
            }],
        }

    # Build the analysis prompt
    obs_summary = _build_observation_summary(state)

    # Include file contents from cache for deeper analysis
    file_cache = state.get("file_contents_cache", {})
    file_context = ""
    if file_cache:
        file_parts: list[str] = []
        for path, content in list(file_cache.items())[:5]:  # Limit to 5 files
            file_parts.append(f"### {path}\n```\n{content[:3000]}\n```")
        file_context = "\n## Source Files\n" + "\n".join(file_parts)

    user_content = (
        f"## Tool Observations ({len(observations)} total)\n\n"
        f"{obs_summary}"
        f"{file_context}\n\n"
        "Analyze these observations and produce a vulnerability report.\n"
        "Respond ONLY with valid JSON."
    )

    messages = [
        SystemMessage(content=_ANALYZER_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        if os.getenv("SENTINEL_OFFLINE") == "1":
            raise RuntimeError("SENTINEL_OFFLINE enabled")
        llm = get_llm(temperature=0.1)
        response = llm.invoke(messages)
        text = message_text(response.content)
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        parsed = json.loads(match.group(1) if match else text)
    except Exception as exc:
        logger.warning("Analyzer LLM unavailable, using fallback: %s", exc)
        parsed = _mock_analyzer_output(state)

    vulns = parsed.get("vulnerabilities", [])
    notes = parsed.get("analysis_notes", "")

    logger.info("Analysis complete: %d candidate vulnerabilities found.", len(vulns))

    trace_entry = {
        "step": len(state.get("reasoning_trace", [])) + 1,
        "phase": AgentPhase.OBSERVE.value,
        "thought": f"Analyzed {len(observations)} tool observations.",
        "action": f"Identified {len(vulns)} candidate vulnerabilities.",
        "observation": notes[:300],
        "decision": "Proceeding to reflection phase for verification.",
    }

    run_metadata = dict(state.get("run_metadata", {}))
    run_metadata["analyzer_candidate_count"] = len(vulns)

    return {
        "vulnerabilities": vulns,
        "current_phase": AgentPhase.REFLECT.value,
        "run_metadata": run_metadata,
        "reasoning_trace": [trace_entry],
    }
