# SentinelAgent Architecture

## Design Philosophy

SentinelAgent transforms a fixed pipeline into a **true AI agent** that demonstrates:

1. **Task decomposition** – LLM-driven planning, not hardcoded steps
2. **Tool use** – Agent dynamically selects from 6 tools
3. **Iterative reasoning** – PLAN→ACT→OBSERVE→REFLECT loop
4. **Self-correction** – Critic can reject findings and trigger re-investigation
5. **Observable reasoning** – Every decision is traced and auditable

## LangGraph Workflow

```
                    ┌──────────────────┐
                    │  START            │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ repo_understanding│   Map repo structure
                    └────────┬─────────┘
                             ↓
               ┌──→ ┌──────────────────┐
               │    │    planner        │   Generate audit plan
               │    └────────┬─────────┘
               │             ↓
               │    ┌──────────────────┐
               │    │    executor       │ ←─┐  Execute tools
               │    └────────┬─────────┘   │
               │             ↓             │
               │    ┌────────────────┐     │
               │    │ more tasks?    │─yes─┘
               │    └────────┬───────┘
               │             ↓ no
               │    ┌──────────────────┐
               │    │    analyzer       │   Synthesize findings
               │    └────────┬─────────┘
               │             ↓
               │    ┌──────────────────┐
               │    │    critic         │   Verify/reject
               │    └────────┬─────────┘
               │             ↓
               │    ┌────────────────┐
               └────│reinvestigate?  │
                yes └────────┬───────┘
                             ↓ no
                    ┌──────────────────┐
                    │ report_generator  │   Final output
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │      END          │
                    └──────────────────┘
```

## AgentState (Central Data Structure)

```python
class AgentState(TypedDict, total=False):
    # Input
    repo_path: str
    target_files: list[str]

    # Understanding
    repo_context: dict              # RepoContext serialized

    # Planning
    current_phase: str              # plan|act|observe|reflect|report|done
    plan: dict                      # AuditPlan with ordered tasks
    current_task_index: int

    # Execution
    pending_tool_calls: list[dict]  # Queued ToolCall objects
    observations: list[dict]        # ToolObservation history (append-only)

    # Analysis
    vulnerabilities: list[dict]     # Vulnerability objects (replaced each cycle)
    file_contents_cache: dict       # path → source code

    # Reflection
    reasoning_trace: list[dict]     # TraceEntry objects (append-only)
    reflection_notes: list[str]
    iteration_count: int
    max_iterations: int

    # Output
    final_report: str
    report_json: dict
```

### State Reducers

- `observations`: **append** — tool outputs accumulate across all execution steps
- `reasoning_trace`: **append** — every phase adds its trace entry
- `vulnerabilities`: **replace** — each analysis/reflection cycle produces a fresh list

## Node Responsibilities

### 1. repo_understanding
- **Input**: `repo_path`
- **Action**: Runs `RepoMapperTool` to map directory structure
- **Output**: `repo_context` with file tree, languages, high-risk files, dependency manifests
- **Single-file mode**: Creates minimal context for single-file audits

### 2. planner
- **Input**: `repo_context`, `target_files`
- **Action**: LLM generates an `AuditPlan` with ordered `AuditTask`s
- **Output**: `plan` with task queue, `current_phase = "act"`
- **Tool hints**: Each task suggests which tool to use (not mandatory)
- **Fallback**: Deterministic plan based on file types and known patterns

### 3. executor (loops)
- **Input**: `plan`, `current_task_index`
- **Action**: Picks next task, resolves tool + arguments, executes
- **Output**: `observations` (appended), advances `current_task_index`
- **Routing**: Loops back to itself until all tasks are done, then → analyzer

### 4. analyzer
- **Input**: All `observations` from tool execution
- **Action**: LLM synthesizes observations into structured `Vulnerability` objects
- **Cross-referencing**: Matches grep findings with cppcheck warnings for higher confidence
- **Output**: `vulnerabilities` list with Candidate status

### 5. critic
- **Input**: `vulnerabilities`, `observations` (for cross-reference)
- **4-Step Protocol**:
  1. Evidence validation (multi-source corroboration)
  2. Data-flow analysis (user-controllable input?)
  3. Mitigation check (RAII, bounds checks, smart pointers)
  4. Severity calibration (realistic CVSS scoring)
- **Decisions**: Confirm, Reject, or Request Re-investigation
- **Routing**: If `needs_reinvestigation` → back to planner (new cycle)

### 6. report_generator
- **Input**: Final `vulnerabilities`, `reasoning_trace`, `plan`
- **Output**: Markdown report + JSON report
- **Sections**: Executive summary, audit strategy, confirmed vulns, rejected FPs, reasoning trace, reflection notes

## Tool System

Each tool implements `BaseTool`:

```python
class BaseTool(ABC):
    name: str
    description: str

    def execute(self, **kwargs) -> str:
        """Run the tool, return string observation."""

    def schema(self) -> dict:
        """Return JSON schema for LLM to understand parameters."""
```

### Tool Registry

```python
TOOL_REGISTRY = {
    "cppcheck":            CppcheckTool,
    "grep_scanner":        GrepScannerTool,
    "repo_mapper":         RepoMapperTool,
    "ast_parser":          ASTParserTool,
    "dependency_scanner":  DependencyScannerTool,
    "file_reader":         FileReaderTool,
}
```

The executor resolves tool names through the registry. New tools are added by:
1. Create a class extending `BaseTool` in `sentinel_agent/tools/`
2. Add to `TOOL_REGISTRY` in `__init__.py`
3. The planner and executor will automatically discover it

## Prompts

### Planner Prompt (excerpt)
```
You are the Planning Module of SentinelAgent.
Given a repository structure, produce a concrete, ordered audit plan.

Available Tools: repo_mapper, file_reader, cppcheck, grep_scanner,
                 ast_parser, dependency_scanner

Planning Guidelines:
1. Start with repo_mapper to understand structure
2. Prioritize high-risk files (auth, crypto, memory)
3. Group related files together
4. Include dependency scanning if manifests exist
```

### Analyzer Prompt (excerpt)
```
You are the Security Analysis Module of SentinelAgent.
Synthesize ALL tool observations into structured vulnerability findings.

Analysis Rules:
1. Cross-reference: grep match + cppcheck warning = high confidence
2. Trace data flows: is input user-controllable?
3. Check for existing mitigations (RAII, bounds checks)
4. Distinguish real vulnerabilities from safe patterns
```

### Critic Prompt (excerpt)
```
You are the Critical Reflection Module of SentinelAgent.
Apply 4-Step Verification to each finding:
1. Evidence Validation (multi-source corroboration)
2. Data-Flow Analysis (user-controllable input?)
3. Mitigation Check (RAII, smart pointers, bounds checks)
4. Severity Calibration (realistic CVSS)

You can: Confirm, Reject, or Request Re-investigation.
Be SKEPTICAL — your job is to DISPROVE findings.
```

## Comparison: Pipeline vs Agent

```
OLD (RepoAudit Pipeline):
  cppcheck → LLM Scanner → LLM Critic → Report
  - Fixed order, no planning, no tool choice

NEW (SentinelAgent Agent):
  Understand → Plan → [Execute Tools] → Analyze → Reflect → Report
                 ↑                                    │
                 └────── re-investigate ───────────────┘
  - Dynamic planning, tool selection, iterative reasoning
```

## Extending SentinelAgent

### Adding a New Tool
```python
# sentinel_agent/tools/my_tool.py
from .base import BaseTool

class MyTool(BaseTool):
    name = "my_tool"
    description = "What this tool does and when to use it."

    def _parameters(self) -> dict:
        return {"type": "object", "properties": {...}, "required": [...]}

    def execute(self, **kwargs) -> str:
        # Implementation
        return "observation string"
```

### Adding a New Agent Node
```python
# sentinel_agent/agents/my_agent.py
from ..state import AgentState, AgentPhase

def node_my_agent(state: AgentState) -> dict:
    # Read state, do work, return updates
    return {
        "some_field": new_value,
        "reasoning_trace": [trace_entry],
    }
```

Then wire it into `graph.py`:
```python
workflow.add_node("my_agent", node_my_agent)
workflow.add_edge("previous_node", "my_agent")
```
