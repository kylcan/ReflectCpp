"""
SentinelAgent LangGraph workflow – the autonomous reasoning loop.

Architecture:
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│   START                                                          │
│     ↓                                                            │
│   repo_understanding    (map repo structure)                     │
│     ↓                                                            │
│   ┌─→ planner           (create/update audit plan)               │
│   │     ↓                                                        │
│   │   executor           (run tools per plan)  ←─┐               │
│   │     ↓                        │               │               │
│   │   [more tasks?] ─── yes ─────┘               │               │
│   │     ↓ no                                     │               │
│   │   analyzer           (synthesize findings)   │               │
│   │     ↓                                        │               │
│   │   critic             (verify/reject)         │               │
│   │     ↓                                        │               │
│   │   [reinvestigate?] ─── yes ──────────────────│──→ planner    │
│   │     ↓ no                                                     │
│   │   report_generator   (final output)                          │
│   │     ↓                                                        │
│   │   END                                                        │
│   └──────────────────────────────────────────────────────────────┘
│                                                                  │
│   Reasoning Loop: PLAN → ACT → OBSERVE → REFLECT → (loop/done)  │
└──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from langgraph.graph import END, StateGraph

from .agents.analyzer import node_analyzer
from .agents.critic import node_critic
from .agents.executor import node_executor
from .agents.planner import node_planner
from .agents.reporter import node_report_generator
from .state import AgentPhase, AgentState
from .tools.repo_mapper import RepoMapperTool

logger = logging.getLogger(__name__)


# ── Routing functions ─────────────────────────────────────────────────────

def route_after_executor(state: AgentState) -> str:
    """After executor: continue executing tasks or move to analysis."""
    phase = state.get("current_phase", "")
    if phase == AgentPhase.OBSERVE.value:
        return "analyzer"

    # Check if there are more tasks
    plan = state.get("plan", {})
    tasks = plan.get("tasks", [])
    idx = state.get("current_task_index", 0)
    if idx < len(tasks):
        return "executor"  # More tasks to execute

    return "analyzer"


def route_after_critic(state: AgentState) -> str:
    """After critic: re-plan for deeper investigation or generate report."""
    phase = state.get("current_phase", "")
    if phase == AgentPhase.PLAN.value:
        iteration = state.get("iteration_count", 0)
        max_iter = state.get("max_iterations", 10)
        if iteration < max_iter:
            return "planner"  # Re-investigate

    return "report_generator"


# ── Repo Understanding Node ──────────────────────────────────────────────

def node_repo_understanding(state: AgentState) -> dict:
    """Initial step: map repository structure for the planner."""
    repo_path = state.get("repo_path", "")

    if not repo_path or not os.path.exists(repo_path):
        logger.warning("Repo path does not exist: %s", repo_path)
        return {
            "repo_context": {"root_dir": repo_path, "file_tree": [], "error": "Path not found"},
            "reasoning_trace": [{
                "step": 1,
                "phase": AgentPhase.PLAN.value,
                "thought": f"Repository path '{repo_path}' not found.",
                "action": "Skipping repo mapping.",
                "observation": "",
                "decision": "Proceeding with limited context.",
            }],
        }

    mapper = RepoMapperTool()

    if os.path.isfile(repo_path):
        # Single file mode – create minimal context
        file_tree = [os.path.basename(repo_path)]
        return {
            "repo_context": {
                "root_dir": str(Path(repo_path).parent),
                "file_tree": file_tree,
                "total_files": 1,
                "single_file_mode": True,
            },
            "target_files": [repo_path],
            "reasoning_trace": [{
                "step": 1,
                "phase": AgentPhase.PLAN.value,
                "thought": f"Single file audit: {repo_path}",
                "action": "Set up single-file context.",
                "observation": f"File: {os.path.basename(repo_path)}",
                "decision": "Proceeding with single-file audit plan.",
            }],
        }

    # Directory mode – map the full repo
    output = mapper.execute(directory=repo_path)

    # Parse output into structured context
    file_tree: list[str] = []
    capture_tree = False
    for line in output.splitlines():
        if "## File Tree" in line:
            capture_tree = True
            continue
        if capture_tree and line.startswith("  ") and not line.startswith("  ..."):
            file_tree.append(line.strip())
        elif capture_tree and line.startswith("##"):
            capture_tree = False

    high_risk: list[str] = []
    capture_risk = False
    for line in output.splitlines():
        if "## High-Risk" in line:
            capture_risk = True
            continue
        if capture_risk and line.strip().startswith("⚠"):
            high_risk.append(line.strip().lstrip("⚠").strip())
        elif capture_risk and line.startswith("##"):
            capture_risk = False

    dep_files: list[str] = []
    capture_dep = False
    for line in output.splitlines():
        if "## Dependency" in line:
            capture_dep = True
            continue
        if capture_dep and line.strip():
            dep_files.append(line.strip())
        elif capture_dep and line.startswith("##"):
            capture_dep = False

    repo_ctx = {
        "root_dir": repo_path,
        "file_tree": file_tree,
        "total_files": len(file_tree),
        "high_risk_files": high_risk,
        "dependency_files": dep_files,
        "mapper_output": output,
    }

    logger.info("Repo mapped: %d files, %d high-risk, %d dependency manifests",
                len(file_tree), len(high_risk), len(dep_files))

    return {
        "repo_context": repo_ctx,
        "reasoning_trace": [{
            "step": 1,
            "phase": AgentPhase.PLAN.value,
            "thought": f"Mapping repository at {repo_path}.",
            "action": f"Discovered {len(file_tree)} files, {len(high_risk)} high-risk.",
            "observation": output[:500],
            "decision": "Repository mapped. Ready for planning.",
        }],
    }


# ── Graph Builder ─────────────────────────────────────────────────────────

def build_agent_graph():
    """Construct and compile the SentinelAgent LangGraph workflow."""

    workflow = StateGraph(AgentState)

    # Register nodes
    workflow.add_node("repo_understanding", node_repo_understanding)
    workflow.add_node("planner", node_planner)
    workflow.add_node("executor", node_executor)
    workflow.add_node("analyzer", node_analyzer)
    workflow.add_node("critic", node_critic)
    workflow.add_node("report_generator", node_report_generator)

    # Edges
    workflow.set_entry_point("repo_understanding")
    workflow.add_edge("repo_understanding", "planner")
    workflow.add_edge("planner", "executor")

    # Executor loop: execute tasks until all done, then analyze
    workflow.add_conditional_edges(
        "executor",
        route_after_executor,
        {"executor": "executor", "analyzer": "analyzer"},
    )

    workflow.add_edge("analyzer", "critic")

    # Critic decision: re-investigate or generate report
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {"planner": "planner", "report_generator": "report_generator"},
    )

    workflow.add_edge("report_generator", END)

    return workflow.compile()


# ── High-Level Entry Point ────────────────────────────────────────────────

def run_agent(
    repo_path: str,
    target_files: list[str] | None = None,
    max_iterations: int = 10,
) -> dict:
    """Run the SentinelAgent on a repository or file.

    Parameters
    ----------
    repo_path : str
        Path to a repository directory or a single source file.
    target_files : list[str] | None
        Specific files to audit (empty = auto-discover).
    max_iterations : int
        Maximum PLAN→ACT→OBSERVE→REFLECT cycles.

    Returns
    -------
    dict
        Final AgentState with report, vulnerabilities, and trace.
    """
    graph = build_agent_graph()

    initial_state: AgentState = {
        "repo_path": str(Path(repo_path).resolve()),
        "target_files": target_files or [],
        "repo_context": {},
        "current_phase": AgentPhase.PLAN.value,
        "plan": {},
        "current_task_index": 0,
        "pending_tool_calls": [],
        "observations": [],
        "vulnerabilities": [],
        "file_contents_cache": {},
        "reasoning_trace": [],
        "reflection_notes": [],
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "final_report": "",
        "report_json": {},
        "run_metadata": {},
    }

    logger.info("🛡️ SentinelAgent starting audit: %s", repo_path)
    result = graph.invoke(initial_state)
    logger.info("🛡️ Audit complete. %d vulnerabilities confirmed.",
                len([v for v in result.get("vulnerabilities", []) if v.get("status") == "Confirmed"]))

    return result
