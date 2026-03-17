"""Tool contribution attribution.

We approximate "tool success" by checking whether a tool's observation
contains signals that correspond to CWEs that were ultimately Confirmed.

This is intentionally heuristic and deterministic (works offline).
"""

from __future__ import annotations

import json
import re
from typing import Any


def _guess_cwe_id_from_text(text: str) -> str:
    t = (text or "").lower()
    if "use-after-free" in t or "use after free" in t:
        return "CWE-416"
    if "command" in t and ("system" in t or "injection" in t or "exec" in t):
        return "CWE-78"
    if "buffer" in t or "overflow" in t or "out of bounds" in t:
        # Prefer a more specific stack overflow if present.
        if "stack" in t or "stack-based" in t:
            return "CWE-121"
        return "CWE-120"
    if "null pointer" in t or "malloc" in t:
        return "CWE-476"
    m = re.search(r"cwe-\d+", t)
    return m.group(0).upper() if m else ""


def extract_cwes_from_observation(observation: dict[str, Any]) -> set[str]:
    tool = str(observation.get("tool_name", "") or "")
    output_json = observation.get("output_json")
    output_text = str(observation.get("output", "") or "")

    cwes: set[str] = set()

    if isinstance(output_json, dict):
        if tool == "grep_scanner":
            for m in output_json.get("matches", []) or []:
                cwe = str((m or {}).get("cwe", "") or "").strip()
                if cwe:
                    cwes.add(cwe)
        elif tool == "cppcheck":
            for f in output_json.get("findings", []) or []:
                msg = str((f or {}).get("message", "") or "")
                cwe = _guess_cwe_id_from_text(msg)
                if cwe:
                    cwes.add(cwe)

    # Fallback: mine text for CWE ids / hints
    for m in re.findall(r"CWE-\d+", output_text):
        cwes.add(m)

    guessed = _guess_cwe_id_from_text(output_text)
    if guessed:
        cwes.add(guessed)

    # Normalize common equivalences
    if "CWE-121" in cwes:
        cwes.add("CWE-120")

    return cwes


def update_history_from_run(
    *,
    observations: list[dict[str, Any]],
    reviewed_vulnerabilities: list[dict[str, Any]],
    history,
) -> dict[str, Any]:
    """Update ToolHistory based on confirmed vulnerabilities.

    Returns a small summary suitable for run_metadata logging.
    """
    confirmed_cwes: set[str] = set()
    for v in reviewed_vulnerabilities or []:
        if (v or {}).get("status") == "Confirmed":
            cwe = str((v or {}).get("cwe_id", "") or "").strip()
            if cwe:
                confirmed_cwes.add(cwe)

    # If we have CWE-121 confirmed, treat CWE-120 signals as relevant too.
    if "CWE-121" in confirmed_cwes:
        confirmed_cwes.add("CWE-120")

    updates: dict[str, dict[str, int]] = {}

    for obs in observations or []:
        tool = str((obs or {}).get("tool_name", "") or "")
        if not tool:
            continue

        # Only count as a success when the tool produced relevant CWE signals.
        obs_cwes = extract_cwes_from_observation(obs)
        tool_success = bool(confirmed_cwes and (obs_cwes & confirmed_cwes))

        # Reward-based update:
        # +1 => observation contained confirmed-relevant signals
        #  0 => neutral (no relevant signal). We do not assign -1 here because
        #      determining "misleading" requires stronger ground-truth.
        reward = 1.0 if tool_success else 0.0

        # Record for all tools so success rates evolve over time.
        history.record(tool, reward=reward)
        updates.setdefault(tool, {"success": 0, "fail": 0})
        updates[tool]["success" if tool_success else "fail"] += 1

    history.save()

    return {
        "confirmed_cwes": sorted(confirmed_cwes),
        "updates": updates,
    }
