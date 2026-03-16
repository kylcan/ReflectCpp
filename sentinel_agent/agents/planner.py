"""
Planner Agent – generates a multi-step audit strategy.

The planner examines the repository structure and produces an ordered
task list that the executor will work through. This is what makes
SentinelAgent a *planning* agent rather than a fixed pipeline.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..llm import get_llm, message_text
from ..state import AgentPhase, AgentState

logger = logging.getLogger(__name__)

_PLANNER_SYSTEM = """\
You are the **Planning Module** of SentinelAgent, an autonomous security auditing AI.

Your job: given a repository structure, produce a concrete, ordered audit plan.

## Available Tools
You can plan tasks that use any of these tools:
- **repo_mapper**: Map directory structure, find high-risk files, identify languages
- **file_reader**: Read source file contents (full or specific line range)
- **cppcheck**: Run static analysis on a C/C++ file
- **grep_scanner**: Search for dangerous function patterns (strcpy, gets, system, etc.)
- **ast_parser**: Extract function definitions, call graph, complexity metrics
- **dependency_scanner**: Check dependency manifests for known vulnerable libraries

## Planning Guidelines
1. Start with repo_mapper to understand the codebase structure (if not already done).
2. Prioritize high-risk files: authentication, crypto, memory management, parsers.
3. For each high-risk file, plan: read → grep_scanner → cppcheck → ast_parser (as needed).
4. Include a dependency scan if dependency manifests exist.
5. Group related files together (e.g., all auth-related files).
6. Limit the plan to the most impactful tasks (max 15-20 tasks).
7. Add task dependencies where order matters.

## Output Format
Return a JSON object:
{
  "objective": "Security audit of <repo name>",
  "strategy": "Brief description of your approach",
  "tasks": [
    {
      "task_id": "T1",
      "description": "Map repository structure",
      "tool_hint": "repo_mapper",
      "target_files": [],
      "status": "pending",
      "depends_on": []
    },
    ...
  ],
  "priority_files": ["file1.cpp", "file2.cpp"]
}

Respond ONLY with valid JSON. No markdown fences.
"""


def _mock_planner_output(state: AgentState) -> dict:
    """Deterministic fallback plan when LLM is unavailable."""
    repo_ctx = state.get("repo_context", {})
    file_tree = repo_ctx.get("file_tree", [])
    target_files = state.get("target_files", [])

    # If specific files are targeted, plan around those
    if target_files:
        cpp_files = target_files
    else:
        cpp_files = [f for f in file_tree
                     if any(f.endswith(ext) for ext in (".c", ".cpp", ".cc", ".h", ".hpp"))]

    tasks: list[dict[str, Any]] = []
    task_id = 1

    # Task 1: always map the repo first
    if not repo_ctx.get("file_tree"):
        tasks.append({
            "task_id": f"T{task_id}",
            "description": "Map repository structure to identify files and languages",
            "tool_hint": "repo_mapper",
            "target_files": [],
            "status": "pending",
            "depends_on": [],
        })
        task_id += 1

    # Task 2: dependency scan
    dep_files = repo_ctx.get("dependency_files", [])
    if dep_files:
        tasks.append({
            "task_id": f"T{task_id}",
            "description": "Scan dependency manifests for known vulnerable libraries",
            "tool_hint": "dependency_scanner",
            "target_files": dep_files,
            "status": "pending",
            "depends_on": ["T1"] if task_id > 1 else [],
        })
        task_id += 1

    # Per-file analysis tasks
    for fpath in cpp_files[:10]:  # Limit to 10 files in fallback
        base_task_id = f"T{task_id}"

        tasks.append({
            "task_id": base_task_id,
            "description": f"Scan {fpath} for dangerous function patterns",
            "tool_hint": "grep_scanner",
            "target_files": [fpath],
            "status": "pending",
            "depends_on": ["T1"],
        })
        task_id += 1

        tasks.append({
            "task_id": f"T{task_id}",
            "description": f"Run static analysis on {fpath}",
            "tool_hint": "cppcheck",
            "target_files": [fpath],
            "status": "pending",
            "depends_on": [base_task_id],
        })
        task_id += 1

    return {
        "objective": f"Security audit of repository at {state.get('repo_path', 'unknown')}",
        "strategy": "Systematic scan: repo mapping → dependency check → per-file grep + cppcheck + AST analysis",
        "tasks": tasks,
        "priority_files": cpp_files[:5],
    }


def node_planner(state: AgentState) -> dict:
    """Generate an audit plan based on repository context.

    If repo_context is empty, plans a repo_mapper step first.
    """
    repo_ctx = state.get("repo_context", {})
    repo_path = state.get("repo_path", "")

    # Build the planner prompt
    context_parts: list[str] = [f"## Target Repository\nPath: {repo_path}"]

    if repo_ctx:
        context_parts.append(f"\n## Repository Context\n```json\n{json.dumps(repo_ctx, indent=2)}\n```")

    target_files = state.get("target_files", [])
    if target_files:
        context_parts.append(f"\n## Specific Target Files\n{chr(10).join(target_files)}")

    user_content = "\n".join(context_parts) + "\n\nProduce the audit plan."

    messages = [
        SystemMessage(content=_PLANNER_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        if os.getenv("SENTINEL_OFFLINE") == "1":
            raise RuntimeError("SENTINEL_OFFLINE enabled")
        llm = get_llm(temperature=0.2)
        response = llm.invoke(messages)
        text = message_text(response.content)
        # Try to parse JSON (handle markdown fences)
        import re
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        plan_dict = json.loads(match.group(1) if match else text)
    except Exception as exc:
        logger.warning("Planner LLM unavailable, using fallback plan: %s", exc)
        plan_dict = _mock_planner_output(state)

    logger.info("Plan generated: %d tasks, strategy: %s",
                len(plan_dict.get("tasks", [])),
                plan_dict.get("strategy", "")[:80])

    # Build trace entry
    trace_entry = {
        "step": len(state.get("reasoning_trace", [])) + 1,
        "phase": AgentPhase.PLAN.value,
        "thought": f"Analyzing repository at {repo_path} to create audit strategy.",
        "action": f"Generated plan with {len(plan_dict.get('tasks', []))} tasks.",
        "observation": plan_dict.get("strategy", ""),
        "decision": "Begin executing plan tasks sequentially.",
    }

    return {
        "plan": plan_dict,
        "current_phase": AgentPhase.ACT.value,
        "current_task_index": 0,
        "reasoning_trace": [trace_entry],
    }
