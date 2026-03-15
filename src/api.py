"""
FastAPI REST interface for the Code Security Audit Agent.

Endpoints
---------
POST /audit          Submit source code → returns task_id (async).
GET  /audit/{id}     Poll task status / retrieve results.
GET  /health         Liveness probe.

Run with:
    uvicorn src.api:app --reload
"""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI, HTTPException

from .graph import run_audit
from .repo_scanner import scan_repo
from .schemas import (
    AuditRequest,
    AuditResult,
    AuditStatus,
    RepoAuditRequest,
    TaskResponse,
    VulnerabilityOut,
)
from .tracing import configure_tracing

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App & in-memory task store
# ---------------------------------------------------------------------------

app = FastAPI(
    title="RepoAudit – Code Security Audit Agent",
    version="0.2.0",
    description="Multi-agent LangGraph pipeline for automated C++ security auditing.",
)


@app.on_event("startup")
def _on_startup() -> None:
    configure_tracing()

# In-memory task store (swap for Redis / DB in production)
_tasks: dict[str, TaskResponse] = {}

# Thread pool for background audit execution
_executor = ThreadPoolExecutor(max_workers=2)


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _run_audit_task(task_id: str, source_code: str, source_file_path: str) -> None:
    """Execute the audit pipeline in a background thread."""
    _tasks[task_id] = TaskResponse(
        task_id=task_id, status=AuditStatus.RUNNING
    )
    try:
        result = run_audit(source_code, source_file_path or None)

        vulns = result.get("vulnerabilities", [])
        confirmed = [
            VulnerabilityOut(**v)
            for v in vulns
            if v.get("status") == "Confirmed"
        ]
        rejected = [
            VulnerabilityOut(**v)
            for v in vulns
            if v.get("status") == "Rejected"
        ]

        _tasks[task_id] = TaskResponse(
            task_id=task_id,
            status=AuditStatus.COMPLETED,
            result=AuditResult(
                confirmed=confirmed,
                rejected=rejected,
                iterations=result.get("iteration_count", 0),
                report_markdown=result.get("final_report", ""),
            ),
        )
        logger.info("Task %s completed: %d confirmed, %d rejected",
                     task_id, len(confirmed), len(rejected))

    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        _tasks[task_id] = TaskResponse(
            task_id=task_id,
            status=AuditStatus.FAILED,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/audit", response_model=TaskResponse, status_code=202)
def submit_audit(req: AuditRequest) -> TaskResponse:
    """Submit C++ source code for asynchronous security audit."""
    task_id = uuid.uuid4().hex[:12]
    _tasks[task_id] = TaskResponse(
        task_id=task_id, status=AuditStatus.PENDING
    )
    _executor.submit(_run_audit_task, task_id, req.source_code, req.source_file_path)
    return _tasks[task_id]


@app.get("/audit/{task_id}", response_model=TaskResponse)
def get_audit_status(task_id: str) -> TaskResponse:
    """Poll the status of an audit task. Returns results when completed."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@app.get("/health")
def health_check() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Repo-level audit
# ---------------------------------------------------------------------------

def _run_repo_audit_task(task_id: str, directory: str) -> None:
    """Execute repo-level scan in a background thread."""
    _tasks[task_id] = TaskResponse(
        task_id=task_id, status=AuditStatus.RUNNING
    )
    try:
        repo_result = scan_repo(directory)

        all_confirmed: list[VulnerabilityOut] = []
        all_rejected: list[VulnerabilityOut] = []
        for fr in repo_result.file_results:
            for v in fr.confirmed:
                all_confirmed.append(VulnerabilityOut(**v))
            for v in fr.rejected:
                all_rejected.append(VulnerabilityOut(**v))

        _tasks[task_id] = TaskResponse(
            task_id=task_id,
            status=AuditStatus.COMPLETED,
            result=AuditResult(
                confirmed=all_confirmed,
                rejected=all_rejected,
                iterations=repo_result.files_scanned,
                report_markdown=repo_result.consolidated_report,
            ),
        )
        logger.info("Repo task %s completed: %d files, %d confirmed",
                     task_id, repo_result.files_scanned, len(all_confirmed))

    except Exception as exc:
        logger.exception("Repo task %s failed", task_id)
        _tasks[task_id] = TaskResponse(
            task_id=task_id,
            status=AuditStatus.FAILED,
            error=str(exc),
        )


@app.post("/audit/repo", response_model=TaskResponse, status_code=202)
def submit_repo_audit(req: RepoAuditRequest) -> TaskResponse:
    """Submit a directory for recursive C/C++ security audit."""
    task_id = uuid.uuid4().hex[:12]
    _tasks[task_id] = TaskResponse(
        task_id=task_id, status=AuditStatus.PENDING
    )
    _executor.submit(_run_repo_audit_task, task_id, req.directory)
    return _tasks[task_id]
