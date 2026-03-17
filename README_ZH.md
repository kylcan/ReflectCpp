# 🛡️ SentinelAgent

**面向软件仓库的自主式 AI 安全审计 Agent**

SentinelAgent 是一个用于 C/C++ 代码仓库安全审计的 AI Agent。  
与传统静态分析流水线不同，SentinelAgent 通过 **PLAN → ACT → OBSERVE → REFLECT** 的推理循环运行：  
自动规划审计策略、动态选择工具、分析结果并进行自我验证。

该项目展示了一个完整的 **LLM Agent + 工具调用 + 推理循环** 的系统实现。

---

# 项目架构

```
用户请求 (repo path)
        ↓
┌──────────────────────────────────────────────┐
│  仓库理解 (Repo Understanding)                │
│  分析目录结构 → 识别高风险文件                │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│  规划 Agent (Planner Agent)                  │
│  根据仓库结构生成多步骤审计计划               │
│  输出：任务队列 + 工具建议                    │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│  执行 Agent (Executor Loop)                  │
│  对每个任务：                                 │
│  选择工具 → 执行 → 记录观察结果                │
│                                              │
│  可调用工具：                                 │
│  cppcheck / grep_scanner / ast_parser        │
│  repo_mapper / dependency_scanner / file_reader
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│  分析 Agent (Analyzer Agent)                 │
│  综合多个工具结果 → 生成候选漏洞列表           │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│  反思 Agent (Critic Agent)                   │
│  四步验证：                                   │
│  Evidence → Data-flow → Mitigation → Severity │
│  如证据不足，可触发重新规划                    │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│  报告生成 (Report Generator)                 │
│  输出 Markdown + JSON 报告                    │
│  包含完整推理过程 (Reasoning Trace)           │
└──────────────────────────────────────────────┘
```

---

# 核心功能

| 功能 | 说明 |
|----|----|
| **任务规划** | LLM 根据仓库结构自动生成安全审计计划 |
| **工具调用** | Agent 可动态选择 6 个安全分析工具 |
| **迭代推理** | 通过 PLAN→ACT→OBSERVE→REFLECT 循环执行 |
| **自我验证** | Critic Agent 使用 4 步验证漏洞 |
| **可解释性** | 每一步推理都会记录 reasoning trace |
| **仓库级分析** | 不仅分析单文件，还理解项目结构 |
| **离线运行** | 提供 deterministic fallback，可完全离线运行 |

---

# 快速开始

## 环境要求

- Python 3.11+
- （可选）`cppcheck` 用于真实静态分析
- （可选）OpenAI API Key 用于 LLM 推理

---

## 安装依赖

```
pip install -r requirements.txt
```

---

## 运行安全审计

### 扫描单个文件

```
python sentinel_run.py samples/vuln_sample.cpp
```

### 扫描整个仓库

```
python sentinel_run.py /path/to/repo
```

### 显示 Agent 推理过程

```
python sentinel_run.py samples/vuln_sample.cpp --trace
```

### 保存报告

```
python sentinel_run.py /path/to/repo -o report.md --json-report audit.json
```

### 详细日志模式

```
python sentinel_run.py samples/vuln_sample.cpp -v --trace
```

---

# 环境变量

| 变量 | 说明 | 默认 |
|----|----|----|
| `GPT5_KEY` / `OPENAI_API_KEY` | LLM API Key | 使用 mock fallback |
| `CHATGPT_MODEL` / `AUDIT_MODEL` | 模型名称 | gpt-4o |
| `CHATGPT_BASE_URL` / `OPENAI_BASE_URL` | 自定义 API endpoint | OpenAI 默认 |

---

# REST API

启动服务：

```
uvicorn sentinel_agent.api:app --reload
```

提交审计任务：

```
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo"}'
```

查询任务结果：

```
curl http://localhost:8000/audit/{task_id}
```

查看可用工具：

```
curl http://localhost:8000/tools
```

---

# 评估 (Evaluation)

项目提供一个轻量级评估工具，包含约 60 个合成漏洞样例。

运行：

```
python -m eval.run_eval --regen
```

---

# 安全限制

- **沙盒路径**：API 只能扫描 `SENTINEL_ALLOWED_ROOT` 下的目录
- **离线模式**：设置 `SENTINEL_OFFLINE=1` 禁用 LLM 网络调用
- **文件读取限制**：`file_reader` 限制最大文件大小与行数

---

# Docker 运行

```
docker-compose up --build
```

---

# 项目结构

```
sentinel_agent/
├── __init__.py
├── state.py              # AgentState + 数据结构定义
├── graph.py              # LangGraph Agent 推理循环
├── llm.py                # LLM 工厂与接口
├── api.py                # FastAPI 服务
│
├── agents/               # Agent 实现
│   ├── planner.py        # 审计计划生成
│   ├── executor.py       # 工具选择与执行
│   ├── analyzer.py       # 分析观察结果
│   ├── critic.py         # 漏洞验证
│   └── reporter.py       # 报告生成
│
├── tools/                # Agent 可调用工具
│   ├── base.py
│   ├── cppcheck.py
│   ├── grep_scanner.py
│   ├── repo_mapper.py
│   ├── ast_parser.py
│   ├── dependency_scanner.py
│   └── file_reader.py
│
└── memory/
    └── scratchpad.py
```

---

# Agent 推理示例

```
Step 1 [PLAN]
Thought: 分析仓库结构
Action: repo_mapper

Step 2 [ACT]
Thought: 搜索危险函数
Action: grep_scanner

Observation:
login.cpp: strcpy(buffer,input)

Step 3 [ACT]
Thought: 进行静态分析
Action: cppcheck

Observation:
buffer overflow warning

Step 4 [REFLECT]
Decision: 确认为缓冲区溢出漏洞

Step 5 [REPORT]
生成漏洞报告
```

---

# 可用工具

| 工具 | 功能 |
|----|----|
| `cppcheck` | 静态分析（溢出、内存泄漏等） |
| `grep_scanner` | 危险函数检测（strcpy / gets / system 等） |
| `repo_mapper` | 仓库结构分析 |
| `ast_parser` | 函数与调用关系解析 |
| `dependency_scanner` | 依赖漏洞检测 |
| `file_reader` | 按行读取源码 |

---

# 为什么这是一个 Agent（而不是 Pipeline）

| 传统 Pipeline | SentinelAgent |
|----|----|
| 固定执行顺序 | 动态任务规划 |
| 工具调用固定 | Agent 自主选择工具 |
| 单次执行 | 多轮推理循环 |
| 无规划能力 | LLM 自动生成审计策略 |
| 无验证 | Critic Agent 验证漏洞 |
| 黑盒执行 | 完整 reasoning trace |

---

# 原始系统

旧版本 RepoAudit 仍保留在 `src/` 目录，用于对比：

```
python main.py samples/vuln_sample.cpp
```

---

# License

MIT