"""
SentinelAgent FastAPI REST API.

Endpoints:
    POST /audit          Submit repo/file for audit (async)
    GET  /audit/{id}     Poll task status / retrieve results
    GET  /health         Liveness probe
    GET  /tools          List available tools
"""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .graph import run_agent
from .state import AuditRequest, AuditResponse, AuditStatusEnum, TraceEntry, Vulnerability
from .tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)

app = FastAPI(
    title="SentinelAgent – Autonomous AI Security Auditor",
    version="1.0.0",
    description=(
        "An autonomous AI agent that plans, executes, and reflects on "
        "security audits of software repositories."
    ),
)

_tasks: dict[str, AuditResponse] = {}
_executor = ThreadPoolExecutor(max_workers=2)


def _run_audit_task(task_id: str, req: AuditRequest) -> None:
    """Execute audit in background thread."""
    _tasks[task_id] = AuditResponse(
        task_id=task_id, status=AuditStatusEnum.RUNNING,
    )
    try:
        result = run_agent(
            repo_path=req.repo_path,
            target_files=req.target_files,
            max_iterations=req.max_iterations,
        )

        vulns = result.get("vulnerabilities", [])
        confirmed = [Vulnerability(**v) for v in vulns if v.get("status") == "Confirmed"]
        trace = [TraceEntry(**t) for t in result.get("reasoning_trace", [])]

        _tasks[task_id] = AuditResponse(
            task_id=task_id,
            status=AuditStatusEnum.COMPLETED,
            vulnerabilities=confirmed,
            reasoning_trace=trace,
            report_markdown=result.get("final_report", ""),
        )
        logger.info("Task %s completed: %d vulnerabilities", task_id, len(confirmed))

    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        _tasks[task_id] = AuditResponse(
            task_id=task_id,
            status=AuditStatusEnum.FAILED,
            error=str(exc),
        )


@app.post("/audit", response_model=AuditResponse, status_code=202)
def submit_audit(req: AuditRequest) -> AuditResponse:
    """Submit a repository or file for security audit."""
    task_id = uuid.uuid4().hex[:12]
    _tasks[task_id] = AuditResponse(
        task_id=task_id, status=AuditStatusEnum.PENDING,
    )
    _executor.submit(_run_audit_task, task_id, req)
    return _tasks[task_id]


@app.get("/audit/{task_id}", response_model=AuditResponse)
def get_audit_status(task_id: str) -> AuditResponse:
    """Poll audit status or retrieve results."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@app.get("/health")
def health_check() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "agent": "SentinelAgent", "version": "1.0.0"}


class ToolInfo(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)


@app.get("/tools", response_model=list[ToolInfo])
def list_tools() -> list[ToolInfo]:
    """List all tools available to the agent."""
    tools = []
    for name, cls in TOOL_REGISTRY.items():
        instance = cls()
        tools.append(ToolInfo(
            name=instance.name,
            description=instance.description,
            parameters=instance._parameters(),
        ))
    return tools
