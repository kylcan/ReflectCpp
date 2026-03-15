"""
Pydantic schemas for structured LLM outputs and graph state.

These schemas enforce type safety and provide clear contracts between
the LangGraph nodes, ensuring the LLM produces parseable, validated data.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field
from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VulnerabilityStatus(str, Enum):
    CANDIDATE = "Candidate"
    CONFIRMED = "Confirmed"
    REJECTED = "Rejected"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Exploitability(str, Enum):
    """How likely this vulnerability can be exploited in practice."""
    PROVEN = "Proven"
    LIKELY = "Likely"
    UNLIKELY = "Unlikely"
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# Pydantic models – used for structured LLM output parsing
# ---------------------------------------------------------------------------

class Vulnerability(BaseModel):
    """A single security finding produced or reviewed by the LLM."""

    vuln_type: str = Field(
        ...,
        description="CWE category or short label, e.g. 'Buffer Overflow (CWE-120)'.",
    )
    cwe_id: str = Field(
        default="",
        description="Standardised CWE identifier, e.g. 'CWE-120'.",
    )
    location: str = Field(
        ...,
        description="File path and line number(s), e.g. 'vuln_sample.cpp:42'.",
    )
    description: str = Field(
        ...,
        description="Detailed explanation of why this is (or is not) a vulnerability.",
    )
    severity: Severity = Field(
        ...,
        description="CVSS-aligned severity rating.",
    )
    status: VulnerabilityStatus = Field(
        default=VulnerabilityStatus.CANDIDATE,
        description="Lifecycle status: Candidate → Confirmed / Rejected.",
    )
    cvss_score: float | None = Field(
        default=None,
        description="Optional numeric CVSS 3.1 base score (0.0 – 10.0).",
    )
    confidence: float = Field(
        default=0.0,
        description="Model self-assessed confidence (0.0 – 1.0).",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Supporting code snippets or static-analysis lines.",
    )
    data_flow: str = Field(
        default="",
        description="Source → sink data-flow path description.",
    )
    exploitability: Exploitability = Field(
        default=Exploitability.UNKNOWN,
        description="Exploitability assessment.",
    )
    remediation: str = Field(
        default="",
        description="Suggested fix or mitigation.",
    )
    related_functions: list[str] = Field(
        default_factory=list,
        description="Functions involved in this vulnerability.",
    )


class ScannerOutput(BaseModel):
    """Structured output expected from the Security Scanner node."""

    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list,
        description="List of potential vulnerabilities discovered.",
    )
    analysis_notes: str = Field(
        default="",
        description="Free-form reasoning the scanner used during analysis.",
    )


class CriticFeedback(BaseModel):
    """Structured output from the Critic / Auditor node."""

    reviewed_vulnerabilities: list[Vulnerability] = Field(
        default_factory=list,
        description="Vulnerabilities with updated status & reasoning.",
    )
    critic_notes: str = Field(
        default="",
        description="Summary of the critic's review rationale.",
    )
    needs_rescan: bool = Field(
        default=False,
        description="True if the critic wants the scanner to re-examine issues.",
    )


# ---------------------------------------------------------------------------
# Run metadata – tracks per-execution diagnostics
# ---------------------------------------------------------------------------

class RunMetadata(BaseModel):
    """Metrics collected across a single audit pipeline invocation."""

    run_id: str = Field(default="", description="Unique run identifier.")
    model_name: str = Field(default="", description="LLM model used.")
    total_prompt_tokens: int = Field(default=0)
    total_completion_tokens: int = Field(default=0)
    total_latency_s: float = Field(default=0.0)
    node_timings: dict[str, float] = Field(
        default_factory=dict,
        description="Wall-clock seconds per node name.",
    )


# ---------------------------------------------------------------------------
# LangGraph State – passed between every node
# ---------------------------------------------------------------------------

def _merge_vulnerabilities(
    existing: list[dict], new: list[dict]
) -> list[dict]:
    """Reducer: replace the vulnerability list wholesale on each update."""
    return new if new else existing


class GraphState(TypedDict, total=False):
    source_code: str
    source_file_path: str
    static_hints: str
    vulnerabilities: Annotated[list[dict], _merge_vulnerabilities]
    critic_log: list[str]
    needs_rescan: bool
    iteration_count: int
    final_report: str
    # --- P0 additions ---
    run_metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# API schemas – FastAPI request / response models
# ---------------------------------------------------------------------------

class AuditRequest(BaseModel):
    """POST /audit request body."""

    source_code: str = Field(
        ...,
        min_length=1,
        description="C++ source code to audit.",
    )
    source_file_path: str = Field(
        default="",
        description="Optional path to the .cpp file on disk (enables cppcheck).",
    )


class AuditStatus(str, Enum):
    """Lifecycle of an async audit task."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilityOut(BaseModel):
    """Single vulnerability in API response."""

    vuln_type: str
    cwe_id: str = ""
    location: str
    description: str
    severity: str
    status: str
    cvss_score: float | None = None
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    data_flow: str = ""
    exploitability: str = ""
    remediation: str = ""
    related_functions: list[str] = Field(default_factory=list)


class AuditResult(BaseModel):
    """Audit pipeline result embedded in task response."""

    confirmed: list[VulnerabilityOut] = Field(default_factory=list)
    rejected: list[VulnerabilityOut] = Field(default_factory=list)
    iterations: int = 0
    report_markdown: str = ""


class TaskResponse(BaseModel):
    """GET /audit/{task_id} response."""

    task_id: str
    status: AuditStatus
    result: AuditResult | None = None
    error: str | None = None


class RepoAuditRequest(BaseModel):
    """POST /audit/repo request body."""

    directory: str = Field(
        ...,
        min_length=1,
        description="Absolute path to the repository root directory to scan.",
    )
