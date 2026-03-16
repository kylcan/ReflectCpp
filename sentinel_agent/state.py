"""
SentinelAgent state definitions and Pydantic schemas.

The AgentState is the central data structure passed through the LangGraph
reasoning loop.  It implements the PLAN → ACT → OBSERVE → REFLECT cycle
with full observability via the reasoning trace.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field
from typing_extensions import TypedDict


# ── Enums ─────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Exploitability(str, Enum):
    PROVEN = "Proven"
    LIKELY = "Likely"
    UNLIKELY = "Unlikely"
    UNKNOWN = "Unknown"


class VulnStatus(str, Enum):
    CANDIDATE = "Candidate"
    CONFIRMED = "Confirmed"
    REJECTED = "Rejected"


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class AgentPhase(str, Enum):
    """Which phase of the reasoning loop the agent is in."""
    PLAN = "plan"
    ACT = "act"
    OBSERVE = "observe"
    REFLECT = "reflect"
    REPORT = "report"
    DONE = "done"


# ── Tool Call / Observation ───────────────────────────────────────────────

class ToolCall(BaseModel):
    """A single tool invocation requested by the agent."""
    tool_name: str = Field(..., description="Name of the tool to call.")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments.")
    reasoning: str = Field(default="", description="Why the agent chose this tool.")


class ToolObservation(BaseModel):
    """Result returned after executing a tool."""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: str = Field(default="", description="Tool output (truncated if necessary).")
    success: bool = True
    error: str = ""


# ── Audit Task (from Planner) ────────────────────────────────────────────

class AuditTask(BaseModel):
    """A single task in the agent's plan."""
    task_id: str = Field(..., description="Unique task identifier, e.g. 'T1'.")
    description: str = Field(..., description="What this task should accomplish.")
    tool_hint: str = Field(default="", description="Suggested tool to use.")
    target_files: list[str] = Field(default_factory=list, description="Files to examine.")
    status: TaskStatus = Field(default=TaskStatus.PENDING)
    depends_on: list[str] = Field(default_factory=list, description="Task IDs this depends on.")


class AuditPlan(BaseModel):
    """The agent's plan for auditing a repository."""
    objective: str = Field(..., description="High-level audit objective.")
    strategy: str = Field(default="", description="Overall approach description.")
    tasks: list[AuditTask] = Field(default_factory=list, description="Ordered task list.")
    priority_files: list[str] = Field(default_factory=list, description="High-risk files to focus on.")


# ── Vulnerability ─────────────────────────────────────────────────────────

class Vulnerability(BaseModel):
    """A single security finding."""
    vuln_id: str = Field(default="", description="Unique ID, e.g. 'V-001'.")
    vuln_type: str = Field(..., description="CWE category, e.g. 'Buffer Overflow (CWE-120)'.")
    cwe_id: str = Field(default="", description="CWE identifier, e.g. 'CWE-120'.")
    location: str = Field(..., description="file:line, e.g. 'auth.cpp:42'.")
    description: str = Field(..., description="Detailed explanation.")
    severity: Severity = Field(default=Severity.MEDIUM)
    status: VulnStatus = Field(default=VulnStatus.CANDIDATE)
    cvss_score: float | None = Field(default=None, description="CVSS 3.1 base score.")
    confidence: float = Field(default=0.0, description="0.0–1.0 model confidence.")
    evidence: list[str] = Field(default_factory=list, description="Supporting code snippets.")
    data_flow: str = Field(default="", description="Source → sink path.")
    exploitability: Exploitability = Field(default=Exploitability.UNKNOWN)
    remediation: str = Field(default="", description="Suggested fix.")
    related_functions: list[str] = Field(default_factory=list)
    fix_verified: bool | None = Field(default=None)
    fix_review: str = Field(default="")


# ── Reasoning Trace Entry ─────────────────────────────────────────────────

class TraceEntry(BaseModel):
    """One step in the agent's observable reasoning trace."""
    step: int = Field(..., description="Step number.")
    phase: AgentPhase = Field(..., description="Current reasoning phase.")
    thought: str = Field(default="", description="Agent's internal reasoning.")
    action: str = Field(default="", description="Action taken (tool call or decision).")
    observation: str = Field(default="", description="What the agent observed.")
    decision: str = Field(default="", description="Decision made based on observation.")


# ── RepoContext ───────────────────────────────────────────────────────────

class FileInfo(BaseModel):
    """Metadata about a single file in the repository."""
    path: str
    language: str = ""
    size_bytes: int = 0
    risk_score: float = Field(default=0.0, description="Estimated risk 0.0-1.0.")
    functions: list[str] = Field(default_factory=list, description="Function names found.")


class RepoContext(BaseModel):
    """Structural understanding of the target repository."""
    root_dir: str = ""
    total_files: int = 0
    languages: dict[str, int] = Field(default_factory=dict, description="Language → file count.")
    file_tree: list[str] = Field(default_factory=list, description="Flat list of file paths.")
    high_risk_files: list[FileInfo] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list, description="e.g. CMakeLists.txt, conanfile.txt.")


# ── State Reducers ────────────────────────────────────────────────────────

def _append_trace(existing: list[dict], new: list[dict]) -> list[dict]:
    """Reducer: append new trace entries to existing."""
    return existing + new


def _replace_vulns(existing: list[dict], new: list[dict]) -> list[dict]:
    """Reducer: replace vulnerability list wholesale."""
    return new if new else existing


def _append_observations(existing: list[dict], new: list[dict]) -> list[dict]:
    """Reducer: append new observations."""
    return existing + new


# ── LangGraph Agent State ─────────────────────────────────────────────────

class AgentState(TypedDict, total=False):
    """Central state for the SentinelAgent LangGraph workflow.

    This flows through: PLAN → ACT → OBSERVE → REFLECT → (loop or REPORT)
    """
    # -- Input --
    repo_path: str                                # path or URL to audit
    target_files: list[str]                       # specific files (or empty = all)

    # -- Repository understanding --
    repo_context: dict                            # serialized RepoContext

    # -- Planning --
    current_phase: str                            # AgentPhase value
    plan: dict                                    # serialized AuditPlan
    current_task_index: int                       # which task we're executing

    # -- Execution --
    pending_tool_calls: list[dict]                # ToolCall dicts queued for execution
    observations: Annotated[list[dict], _append_observations]  # ToolObservation history

    # -- Analysis --
    vulnerabilities: Annotated[list[dict], _replace_vulns]
    file_contents_cache: dict[str, str]           # path → source code

    # -- Reflection --
    reasoning_trace: Annotated[list[dict], _append_trace]
    reflection_notes: list[str]
    iteration_count: int
    max_iterations: int

    # -- Output --
    final_report: str
    report_json: dict

    # -- Metadata --
    run_metadata: dict[str, Any]


# ── API Schemas ───────────────────────────────────────────────────────────

class AuditRequest(BaseModel):
    """POST /audit request body."""
    repo_path: str = Field(..., min_length=1, description="Repository path or URL.")
    target_files: list[str] = Field(default_factory=list, description="Specific files to audit (empty = all).")
    max_iterations: int = Field(default=10, ge=1, le=50, description="Max reasoning loop iterations.")


class AuditStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditResponse(BaseModel):
    """Audit result returned by the API."""
    task_id: str
    status: AuditStatusEnum
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    reasoning_trace: list[TraceEntry] = Field(default_factory=list)
    report_markdown: str = ""
    error: str = ""
