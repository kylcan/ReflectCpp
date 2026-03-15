# Architecture Design Document

## 1. System Overview

RepoAudit is a multi-agent security audit system that discovers vulnerabilities in C/C++ code through a LangGraph reflection workflow. The system combines static analysis tools (cppcheck) with LLM-powered reasoning to achieve higher precision than either approach alone.

## 2. Design Principles

1. **Grounded Analysis** — LLM reasoning is anchored to cppcheck's deterministic output, reducing hallucinations.
2. **Self-Reflection** — A dedicated Critic agent applies a 3-step verification protocol to eliminate false positives.
3. **Graceful Degradation** — When LLM APIs or cppcheck are unavailable, mock fallbacks ensure the system still runs.
4. **Structured Output** — Pydantic models enforce type safety between every node, ensuring parseable, validated data.
5. **Separation of Concerns** — Each node has a single responsibility; adding nodes doesn't require changing existing ones.

## 3. Core Pipeline

```
                        ┌─────────────────┐
                        │   User Input    │
                        │  (source code)  │
                        └────────┬────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Node 1: Static Analysis│
                    │  (cppcheck → hints)     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
               ┌───▶│  Node 2: Scanner (LLM) │
               │    │  Researcher persona     │
               │    └────────────┬────────────┘
               │                 │
               │    ┌────────────▼────────────┐
               │    │  Node 3: Critic (LLM)   │
               │    │  Skeptical reviewer      │
               │    └────────────┬────────────┘
               │                 │
               │         ┌──────▼──────┐
               │         │   Router    │
               │         └──┬──────┬───┘
               │            │      │
               │   rescan   │      │  all confirmed
               └────────────┘      │
                                   │
                    ┌──────────────▼──────────┐
                    │  Node 4: Report Gen     │
                    │  (Markdown output)      │
                    └─────────────────────────┘
```

### 3.1 Node Responsibilities

| Node | Input | Output | LLM? |
|------|-------|--------|------|
| Static Analysis | source_code | static_hints (cppcheck text) | No |
| Security Scanner | source_code + static_hints + critic_log | vulnerabilities (Candidate) | Yes |
| Critic Auditor | source_code + vulnerabilities + static_hints | vulnerabilities (Confirmed/Rejected) | Yes |
| Report Generator | vulnerabilities (final) | final_report (Markdown) | No |

### 3.2 Reflection Loop

The Critic → Scanner feedback loop runs a maximum of 3 iterations. Loop-back triggers when:
- Any vulnerability was rejected AND `needs_rescan` is true
- Not all vulnerabilities are confirmed yet
- Iteration count < MAX_ITERATIONS (3)

This mimics a real code review process where a senior reviewer sends findings back for re-examination.

## 4. State Management

LangGraph's `GraphState` (TypedDict) flows between all nodes:

```python
class GraphState(TypedDict, total=False):
    source_code: str                              # Input code
    source_file_path: str                         # File path for cppcheck
    static_hints: str                             # cppcheck output
    vulnerabilities: list[dict]                   # Current findings
    critic_log: list[str]                         # Accumulated critic notes
    needs_rescan: bool                            # Critic requests rescan
    iteration_count: int                          # Loop counter
    final_report: str                             # Output Markdown
    run_metadata: dict[str, Any]                  # Timing / token metrics
```

The `vulnerabilities` field uses a custom reducer that replaces the list wholesale on each update (not append), so each node sees only the latest findings.

## 5. Vulnerability Schema

Each vulnerability carries rich metadata for downstream processing:

```
vuln_type         "Buffer Overflow (CWE-120)"
cwe_id            "CWE-120"
location          "file.cpp:42"
description       "Unbounded strcpy may overflow buffer."
severity          High | Medium | Low | Critical | Info
status            Candidate → Confirmed / Rejected
cvss_score        8.1
confidence        0.9           (model self-assessment)
evidence          ["strcpy(buf, input);"]
data_flow         "input → strcpy → buf[64]"
exploitability    Proven | Likely | Unlikely | Unknown
remediation       "Use strncpy with bounds check."
related_functions ["process_request"]
```

## 6. Serving Layer

```
┌──────────┐     POST /audit      ┌──────────────┐
│  Client  │ ──────────────────▶  │  FastAPI      │
│          │ ◀────── 202 ───────  │  (src/api.py) │
│          │                      │               │
│          │  GET /audit/{id}     │  ThreadPool   │──▶ run_audit()
│          │ ──────────────────▶  │  (2 workers)  │
│          │ ◀── result/status ── │               │
└──────────┘                      └──────────────┘
```

- Async via `ThreadPoolExecutor` (not asyncio) for compatibility with LangGraph's sync API
- In-memory task store (production: swap to Redis)
- Auto-generated Swagger docs at `/docs`

## 7. Evaluation Framework

Three experiment configurations test the value of each architectural layer:

```
Baseline     =  single zero-shot LLM prompt
Reflection   =  Scanner + Critic (no cppcheck)
Grounded     =  Scanner + Critic + cppcheck
```

Ground truth: 10 C++ test cases (8 CWE vulnerabilities + 2 safe controls) with `labels.json`.

Metrics: Precision, Recall, F1, False Positive Rate — scored at CWE-ID level per file.

## 8. Deployment

```
┌─────────────────────────────────────┐
│  Docker Container                    │
│  python:3.11-slim + cppcheck        │
│                                      │
│  uvicorn src.api:app :8000          │
│                                      │
│  Env: GPT5_KEY, LANGSMITH_API_KEY   │
└─────────────────────────────────────┘
```

CI pipeline (GitHub Actions):
1. `lint-and-test` — ruff lint + CLI smoke test + eval import check
2. `docker-build` — build image + container health check

## 9. Future Work

| Feature | Priority | Description |
|---------|----------|-------------|
| Call Graph Tool | P3 | Parse function call relationships for cross-function analysis |
| SARIF Output | P3 | Standard format for GitHub Security integration |
| Streaming API | P4 | SSE endpoint for real-time progress updates |
| Multi-language | P4 | Extend beyond C/C++ to Python, Java, Go |
| RAG Knowledge Base | P4 | CWE database retrieval for enriched analysis |
