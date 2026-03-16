"""
Tool Executor Agent – executes tool calls and returns observations.

This is the ACT phase of the PLAN → ACT → OBSERVE → REFLECT loop.
The executor picks the next pending task from the plan, selects the
appropriate tool, executes it, and records the observation.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..state import AgentPhase, AgentState, TaskStatus
from ..tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)

# Instantiate all tools once
_TOOLS = {name: cls() for name, cls in TOOL_REGISTRY.items()}


def _resolve_file_path(repo_path: str, target: str) -> str:
    """Resolve a relative file path against the repo root."""
    if os.path.isabs(target) and os.path.exists(target):
        return target
    candidate = os.path.join(repo_path, target)
    if os.path.exists(candidate):
        return candidate
    return target  # Return as-is, tool will report error


def _execute_tool(tool_name: str, args: dict[str, Any]) -> tuple[str, bool]:
    """Execute a named tool and return (output, success)."""
    tool = _TOOLS.get(tool_name)
    if not tool:
        return f"Error: unknown tool '{tool_name}'", False
    try:
        output = tool.execute(**args)
        return output, True
    except Exception as exc:
        return f"Tool execution error: {exc}", False


def node_executor(state: AgentState) -> dict:
    """Execute the next pending task from the plan.

    Picks the task at current_task_index, determines the tool to call,
    runs it, and stores the observation.
    """
    plan = state.get("plan", {})
    tasks = plan.get("tasks", [])
    task_idx = state.get("current_task_index", 0)
    repo_path = state.get("repo_path", "")

    if task_idx >= len(tasks):
        logger.info("All tasks completed, moving to analysis phase.")
        return {"current_phase": AgentPhase.OBSERVE.value}

    task = tasks[task_idx]
    task_id = task.get("task_id", f"T{task_idx + 1}")
    tool_hint = task.get("tool_hint", "")
    target_files = task.get("target_files", [])
    description = task.get("description", "")

    logger.info("Executing task %s: %s (tool: %s)", task_id, description, tool_hint)

    # Mark task in-progress
    task["status"] = TaskStatus.IN_PROGRESS.value

    # Determine tool arguments
    tool_name = tool_hint
    tool_args: dict[str, Any] = {}

    if tool_name == "repo_mapper":
        tool_args["directory"] = repo_path
    elif tool_name == "cppcheck":
        if target_files:
            tool_args["file_path"] = _resolve_file_path(repo_path, target_files[0])
        else:
            tool_args["file_path"] = repo_path
    elif tool_name == "grep_scanner":
        if target_files:
            tool_args["path"] = _resolve_file_path(repo_path, target_files[0])
        else:
            tool_args["path"] = repo_path
    elif tool_name == "ast_parser":
        if target_files:
            tool_args["file_path"] = _resolve_file_path(repo_path, target_files[0])
    elif tool_name == "dependency_scanner":
        tool_args["path"] = repo_path
    elif tool_name == "file_reader":
        if target_files:
            tool_args["file_path"] = _resolve_file_path(repo_path, target_files[0])
            tool_args["repo_root"] = repo_path if os.path.isdir(repo_path) else os.path.dirname(repo_path)
    else:
        # Default: try grep_scanner on repo
        tool_name = "grep_scanner"
        tool_args["path"] = repo_path

    # Execute
    raw_output, success = _execute_tool(tool_name, tool_args)

    output_json: dict[str, Any] | None = None
    output_text = raw_output
    if success and isinstance(raw_output, str):
        candidate = raw_output.lstrip()
        if candidate.startswith("{") and candidate.rstrip().endswith("}"):
            try:
                parsed = json.loads(raw_output)
                if isinstance(parsed, dict):
                    output_json = parsed
                    human = parsed.get("human")
                    if isinstance(human, str) and human.strip():
                        output_text = human
            except Exception:
                output_json = None

    # Truncate only the human text shown in state
    if isinstance(output_text, str) and len(output_text) > 8000:
        output_text = output_text[:8000] + f"\n... (truncated, {len(output_text)} total chars)"

    # Mark task completed
    task["status"] = TaskStatus.COMPLETED.value

    # Update repo_context if we got a repo_mapper result
    repo_context = dict(state.get("repo_context", {}))
    if tool_name == "repo_mapper" and success:
        if output_json:
            repo_context["file_tree"] = output_json.get("file_tree", [])
            repo_context["high_risk_files"] = output_json.get("high_risk_files", [])
            repo_context["dependency_files"] = output_json.get("dependency_files", [])
            repo_context["languages"] = output_json.get("languages", {})
            repo_context["root_dir"] = repo_path
            repo_context["mapper_output"] = output_text
        else:
            repo_context["root_dir"] = repo_path
            repo_context["mapper_output"] = output_text

    # Cache file contents if file_reader was used
    file_cache = dict(state.get("file_contents_cache", {}))
    if tool_name == "file_reader" and success and target_files:
        file_cache[target_files[0]] = output_text

    # Build observation
    observation = {
        "tool_name": tool_name,
        "arguments": tool_args,
        "output": output_text,
        "output_json": output_json,
        "raw_output": raw_output if isinstance(raw_output, str) and len(raw_output) <= 20000 else "(raw output omitted)",
        "success": success,
        "error": "" if success else raw_output,
    }

    # Build trace entry
    trace_entry = {
        "step": len(state.get("reasoning_trace", [])) + 1,
        "phase": AgentPhase.ACT.value,
        "thought": f"Executing task {task_id}: {description}",
        "action": f"Tool: {tool_name}({', '.join(f'{k}={v!r}' for k, v in tool_args.items())})",
        "observation": output_text[:500] + ("..." if len(output_text) > 500 else ""),
        "decision": f"Task {task_id} {'completed' if success else 'failed'}.",
    }

    # Advance to next task
    next_idx = task_idx + 1

    # Decide next phase
    next_phase = AgentPhase.ACT.value
    if next_idx >= len(tasks):
        next_phase = AgentPhase.OBSERVE.value

    return {
        "plan": plan,
        "current_task_index": next_idx,
        "current_phase": next_phase,
        "observations": [observation],
        "repo_context": repo_context,
        "file_contents_cache": file_cache,
        "reasoning_trace": [trace_entry],
    }
