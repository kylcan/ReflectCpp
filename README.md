# 🔒 RepoAudit — Autonomous Code Security Audit Agent

A **production-ready, multi-agent LLM system** that automatically discovers security vulnerabilities in C/C++ codebases using LangGraph's reflection workflow.

> Built to demonstrate: LangGraph multi-agent orchestration · structured LLM output · static-analysis grounding · automated evaluation · FastAPI serving · LangSmith observability · Docker deployment

---

## ✨ Key Features

| Capability | Description |
|-----------|-------------|
| **Multi-Agent Reflection** | Scanner → Critic loop with up to 3 iterations to eliminate false positives |
| **Static-Analysis Grounding** | cppcheck output anchors LLM analysis to real diagnostics |
| **Rich Vulnerability Schema** | CWE IDs, data-flow paths, evidence, confidence scores, remediation suggestions |
| **Repo-Level Scanning** | Recursively audit all C/C++ files in a directory |
| **REST API** | Async `POST /audit` + polling `GET /audit/{id}` via FastAPI |
| **Evaluation Framework** | 10-case benchmark with Precision / Recall / F1 metrics |
| **Observability** | LangSmith tracing (opt-in via env vars) |
| **Containerized** | Dockerfile + docker-compose for one-command deployment |

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  START                                                        │
│    ↓                                                          │
│  🔧 Static Analysis (cppcheck)                               │
│    ↓                                                          │
│  🔍 Security Scanner (LLM)  ←───────────┐                    │
│    ↓                                     │ rescan (max 3x)    │
│  🧪 Critic Auditor (LLM)  ──→ route ────┘                    │
│    ↓ (all confirmed)                                          │
│  📝 Report Generator                                         │
│    ↓                                                          │
│  END                                                          │
└──────────────────────────────────────────────────────────────┘
```

**Why this design?**
- **Phase 1** (naive prompt) produces hallucinated line numbers and many false positives
- **Phase 2** (+ Critic) cuts false positives through a 3-step verification protocol
- **Phase 3** (+ cppcheck grounding) anchors the LLM to real static-analysis evidence

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- An OpenAI-compatible API key

### Install & Run

```bash
# Clone
git clone https://github.com/yourname/RepoAudit.git
cd RepoAudit

# Install dependencies
pip install -r requirements.txt

# Set your API key
export OPENAI_API_KEY="sk-..."

# Audit a single file
python main.py samples/vuln_sample.cpp

# Audit an entire directory
python main.py samples/ --repo

# Compare Phase 1 vs Phase 2+3
python main.py --all-phases
```

### Docker

```bash
docker compose up          # API on http://localhost:8000
# or
docker build -t repoaudit . && docker run -p 8000:8000 repoaudit
```

### API Usage

```bash
# Submit audit
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"source_code": "void f(char* s) { char b[8]; strcpy(b, s); }"}'

# Poll result
curl http://localhost:8000/audit/<task_id>

# Repo-level scan
curl -X POST http://localhost:8000/audit/repo \
  -H "Content-Type: application/json" \
  -d '{"directory": "/path/to/repo"}'

# Swagger docs
open http://localhost:8000/docs
```

---

## 📁 Project Structure

```
RepoAudit/
├── main.py                 # CLI entry point
├── src/
│   ├── schemas.py          # Pydantic models + GraphState + API schemas
│   ├── nodes.py            # 4 LangGraph nodes + mock fallbacks
│   ├── graph.py            # StateGraph wiring + run_audit()
│   ├── repo_scanner.py     # Repo-level multi-file orchestrator
│   ├── api.py              # FastAPI REST server
│   └── tracing.py          # LangSmith integration
├── eval/
│   ├── testcases/          # 10 C++ samples (8 CWE + 2 safe controls)
│   ├── dataset.py          # Test case loader
│   ├── metrics.py          # Precision / Recall / F1 scoring
│   ├── runner.py           # 3-config experiment runner
│   └── report.py           # Markdown + JSON report generator
├── samples/
│   └── vuln_sample.cpp     # Demo file with 4 planted vulnerabilities
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
└── requirements.txt
```

---

## 🧪 Evaluation

The eval framework benchmarks three configurations against ground-truth labels:

| Config | Description |
|--------|-------------|
| **Baseline** | Single zero-shot LLM prompt (no reflection) |
| **Reflection** | Scanner + Critic loop (no static hints) |
| **Grounded** | Full pipeline with cppcheck grounding |

```bash
python -m eval.runner           # runs all 3 configs
# Output: Precision / Recall / F1 / FPR per config
```

---

## 🔭 Observability (LangSmith)

```bash
export LANGCHAIN_TRACING_V2=true
export LANGSMITH_API_KEY="ls-..."
export LANGCHAIN_PROJECT="RepoAudit"

python main.py   # traces appear in https://smith.langchain.com
```

---

## 🛠 Configuration

| Env Variable | Description | Default |
|-------------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | — |
| `GPT5_KEY` | Alternative API key (priority) | — |
| `CHATGPT_MODEL` | Model name | `gpt-4o` |
| `CHATGPT_BASE_URL` | Custom endpoint | OpenAI default |
| `LANGSMITH_API_KEY` | LangSmith key (optional) | — |
| `LANGCHAIN_TRACING_V2` | Enable tracing | `false` |

---

## 📊 Sample Output

```
### 1. Buffer Overflow (CWE-120)

- **CWE:** CWE-120
- **Location:** vuln_sample.cpp:39
- **Severity:** High (CVSS 8.1)
- **Confidence:** 0.9
- **Exploitability:** Likely
- **Description:** Unbounded strcpy in admin branch may overflow buffer[64].
- **Data Flow:** `input parameter → strcpy → buffer[64]`
- **Evidence:**
  - `strcpy(buffer, input); // no bounds check`
- **Remediation:** Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).
- **Related Functions:** process_request
```

---

## License

MIT
