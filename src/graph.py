"""
LangGraph workflow definition for the Code Security Audit Agent.

Graph topology:
  ┌──────────────────────────────────────────────────────────┐
  │  START                                                    │
  │    ↓                                                      │
  │  node_static_analysis                                     │
  │    ↓                                                      │
  │  node_security_scanner  ←──────────────┐                  │
  │    ↓                                   │ (rescan)         │
  │  node_critic_auditor  ──→ route ───────┘                  │
  │    ↓ (report)                                             │
  │  node_remediation_verifier  (logic back-check)            │
  │    ↓                                                      │
  │  node_report_generator                                    │
  │    ↓                                                      │
  │  END                                                      │
  └──────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from .nodes import (
    node_critic_auditor,
    node_remediation_verifier,
    node_report_generator,
    node_security_scanner,
    node_static_analysis,
    route_reflection,
)
from .schemas import GraphState

logger = logging.getLogger(__name__)


def build_audit_graph():
    """Construct and compile the LangGraph audit workflow."""

    workflow = StateGraph(GraphState)

    # --- Register nodes ---
    workflow.add_node("static_analysis", node_static_analysis)
    workflow.add_node("security_scanner", node_security_scanner)
    workflow.add_node("critic_auditor", node_critic_auditor)
    workflow.add_node("remediation_verifier", node_remediation_verifier)
    workflow.add_node("report_generator", node_report_generator)

    # --- Edges ---
    workflow.set_entry_point("static_analysis")
    workflow.add_edge("static_analysis", "security_scanner")
    workflow.add_edge("security_scanner", "critic_auditor")

    # Conditional edge: critic → scanner (rescan) or → reporter
    workflow.add_conditional_edges(
        "critic_auditor",
        route_reflection,
        {
            "rescan": "security_scanner",
            "report": "remediation_verifier",
        },
    )

    workflow.add_edge("remediation_verifier", "report_generator")
    workflow.add_edge("report_generator", END)

    return workflow.compile()


def run_audit(
    source_code: str,
    source_file_path: str | None = None,
) -> dict:
    """High-level entry point: run the full audit pipeline.

    Parameters
    ----------
    source_code : str
        The C++ source code to audit.
    source_file_path : str | None
        Optional path to the .cpp file on disk (for cppcheck).

    Returns
    -------
    dict
        Final GraphState containing *final_report* and all intermediate data.
    """
    graph = build_audit_graph()

    initial_state: GraphState = {
        "source_code": source_code,
        "source_file_path": source_file_path or "",
        "static_hints": "",
        "vulnerabilities": [],
        "critic_log": [],
        "needs_rescan": False,
        "iteration_count": 0,
        "final_report": "",
        "run_metadata": {},
    }

    logger.info("Starting audit pipeline …")
    result = graph.invoke(initial_state)
    logger.info("Audit complete after %d iteration(s).", result.get("iteration_count", 0))
    return result
