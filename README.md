# 🛡️ SentinelAgent

**Autonomous AI Security Auditing Agent for Software Repositories**

SentinelAgent is an AI agent that autonomously plans, executes, and reflects on security audits of C/C++ codebases. Unlike traditional static analysis pipelines, SentinelAgent operates in a **PLAN → ACT → OBSERVE → REFLECT** reasoning loop — dynamically choosing tools, adapting its strategy, and verifying its own findings.

## Architecture

```
User Request (repo path)
    ↓
┌─────────────────────────────────────────────────┐
│  REPO UNDERSTANDING                              │
│  Map structure → identify high-risk files         │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  PLANNER AGENT                                   │
│  Generate multi-step audit strategy               │
│  Output: ordered task queue with tool hints        │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  EXECUTOR (loop)                                 │
│  For each task in plan:                           │
│    Select tool → Execute → Record observation     │
│                                                   │
│  Tools: cppcheck, grep_scanner, ast_parser,       │
│         repo_mapper, dependency_scanner,           │
│         file_reader                                │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  ANALYZER AGENT                                  │
│  Synthesize observations → vulnerability list     │
│  Cross-reference multiple tool outputs             │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  CRITIC AGENT (reflection)                       │
│  4-step verification:                             │
│    Evidence → Data-flow → Mitigation → Severity   │
│  Can trigger re-investigation (back to PLANNER)    │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  REPORT GENERATOR                                │
│  Structured Markdown + JSON report                │
│  Full reasoning trace included                    │
└─────────────────────────────────────────────────┘
```

## Key Features

| Feature | Description |
|---------|-------------|
| **Task Planning** | LLM generates a multi-step audit plan based on repo structure |
| **Tool Calling** | 6 specialized tools the agent selects dynamically |
| **Iterative Reasoning** | PLAN→ACT→OBSERVE→REFLECT loop with re-investigation |
| **Self-Reflection** | Critic agent verifies findings with 4-step protocol |
| **Observable Traces** | Every reasoning step is logged and reportable |
| **Repo-Level Analysis** | Understands directory structure, identifies high-risk files |
| **Mock Fallbacks** | Runs fully offline with deterministic fallbacks |

## Quick Start

### Prerequisites
- Python 3.11+
- (Optional) `cppcheck` for real static analysis
- (Optional) OpenAI API key for LLM-powered analysis

### Install & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Audit a single file
python sentinel_run.py samples/vuln_sample.cpp

# Audit a repository directory
python sentinel_run.py /path/to/repo

# With reasoning trace output
python sentinel_run.py samples/vuln_sample.cpp --trace

# Save reports
python sentinel_run.py /path/to/repo -o report.md --json-report audit.json

# Verbose logging
python sentinel_run.py samples/vuln_sample.cpp -v --trace
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GPT5_KEY` / `OPENAI_API_KEY` | LLM API key | (mock fallback) |
| `CHATGPT_MODEL` / `AUDIT_MODEL` | Model name | `gpt-4o` |
| `CHATGPT_BASE_URL` / `OPENAI_BASE_URL` | Custom endpoint | OpenAI default |

### REST API

```bash
# Start server
uvicorn sentinel_agent.api:app --reload

# Submit audit
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo"}'

# Poll results
curl http://localhost:8000/audit/{task_id}

# List available tools
curl http://localhost:8000/tools
```

## Evaluation (50+ dataset)

This repo includes a lightweight eval harness with a deterministic synthetic dataset (60 cases).

```bash
# Force deterministic offline mode and run a quick eval
python -m eval.run_eval --regen
```

## Safety Boundaries

- **Sandbox root**: API only allows scanning paths under `SENTINEL_ALLOWED_ROOT` (default: current working directory).
- **Offline mode**: set `SENTINEL_OFFLINE=1` to disable network LLM calls and force deterministic fallbacks.
- **File reading limits**: `file_reader` enforces repo-root sandboxing and size/line limits.

### Docker

```bash
docker-compose up --build
```

## Project Structure

```
sentinel_agent/
├── __init__.py              # Package metadata
├── state.py                 # AgentState, Pydantic schemas, enums
├── graph.py                 # LangGraph workflow (the reasoning loop)
├── llm.py                   # LLM factory + utilities
├── api.py                   # FastAPI REST server
│
├── agents/                  # Agent node implementations
│   ├── planner.py           # Task planning from repo context
│   ├── executor.py          # Tool selection + execution
│   ├── analyzer.py          # Observation synthesis → vulnerabilities
│   ├── critic.py            # Reflection + verification
│   └── reporter.py          # Report generation (MD + JSON)
│
├── tools/                   # Tool definitions (agent's capabilities)
│   ├── base.py              # BaseTool interface
│   ├── cppcheck.py          # Static analysis via cppcheck
│   ├── grep_scanner.py      # Dangerous function pattern search
│   ├── repo_mapper.py       # Repository structure mapper
│   ├── ast_parser.py        # Function extraction + call graph
│   ├── dependency_scanner.py # Known-vulnerable dependency check
│   └── file_reader.py       # On-demand file reading
│
└── memory/                  # Agent working memory
    └── scratchpad.py        # Analysis cache + cross-references
```

## Agent Reasoning Trace (Example)

```
Step 1 [PLAN]
  Thought:     Single file audit: samples/vuln_sample.cpp
  Action:      Set up single-file context.
  Decision:    Proceeding with single-file audit plan.

Step 2 [PLAN]
  Thought:     Analyzing repository to create audit strategy.
  Action:      Generated plan with 2 tasks.
  Decision:    Begin executing plan tasks sequentially.

Step 3 [ACT]
  Thought:     Executing task T1: Scan for dangerous function patterns
  Action:      Tool: grep_scanner(path='samples/vuln_sample.cpp')
  Observation: Found 3 matches: strcpy (CWE-120), malloc-no-check (CWE-476), memcpy (CWE-120)
  Decision:    Task T1 completed.

Step 4 [ACT]
  Thought:     Executing task T2: Run static analysis
  Action:      Tool: cppcheck(file_path='samples/vuln_sample.cpp')
  Observation: 4 findings: buffer overflow, null pointer, unused var, memory leak
  Decision:    Task T2 completed.

Step 5 [OBSERVE]
  Thought:     Analyzed 2 tool observations.
  Action:      Identified 7 candidate vulnerabilities.
  Decision:    Proceeding to reflection phase for verification.

Step 6 [REFLECT]
  Thought:     Reviewing 7 candidates with 4-step verification.
  Action:      Confirmed 7, rejected 0.
  Decision:    Proceeding to report.

Step 7 [REPORT]
  Thought:     Compiling final audit report.
  Action:      Generated report with 7 confirmed vulnerabilities.
  Decision:    Audit complete.
```

## Tools

| Tool | Purpose | Input |
|------|---------|-------|
| `cppcheck` | Static analysis (buffer overflows, leaks, null derefs) | file path |
| `grep_scanner` | Dangerous function detection (strcpy, gets, system...) | file/dir path |
| `repo_mapper` | Repository structure, languages, high-risk files | directory |
| `ast_parser` | Function extraction, call graph, complexity metrics | file path |
| `dependency_scanner` | Known CVEs in dependency manifests | file/dir path |
| `file_reader` | Read source files with line ranges | file path + range |

## What Makes This an "Agent" (Not a Pipeline)

| Pipeline (old RepoAudit) | Agent (SentinelAgent) |
|---------------------------|----------------------|
| Fixed execution order | Dynamic task planning |
| Hardcoded tool usage | Agent selects tools based on context |
| Single pass | Iterative reasoning loop |
| No planning | LLM generates audit strategy |
| No self-reflection | Critic can trigger re-investigation |
| Opaque | Full reasoning trace |
| Per-file only | Repository-level understanding |

## Legacy System

The original RepoAudit pipeline is preserved in `src/` for comparison:
```bash
python main.py samples/vuln_sample.cpp  # Original pipeline
```

## License

MIT


