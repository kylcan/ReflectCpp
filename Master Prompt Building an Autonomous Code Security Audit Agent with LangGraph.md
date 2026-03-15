# Master Prompt: Building an Autonomous Code Security Audit Agent with LangGraph

## 1. Role & Context

You are a Senior AI Engineer specializing in **LLM Agents** and **Cybersecurity**. Your task is to develop a production-ready, modular Python system for an automated C++ code security audit.

The goal of this project is to showcase how a **Multi-Agent Reflection Workflow** can significantly reduce hallucinations and False Positives compared to a simple zero-shot LLM prompt, especially in high-stakes environments like TEE (Trusted Execution Environments).

## 2. Technical Stack

- **Framework:** LangGraph, LangChain.
- **LLM Integration:** OpenAI GPT-4o or Claude 3.5 (via LangChain).
- **Static Analysis Tool:** `cppcheck` (integrated via Python `subprocess`).
- **Data Validation:** Pydantic (for structured outputs).

## 3. System Architecture (Graph Topology)

Please implement the following **LangGraph** structure:

### **A. Graph State Definition**

Define a `GraphState` (TypedDict or Pydantic) to track:

- `source_code`: The C++ code to be audited.
- `static_hints`: Raw output from `cppcheck`.
- `vulnerabilities`: A list of objects containing `type`, `location`, `description`, `severity`, and `status` (Candidate/Confirmed/Rejected).
- `critic_log`: A record of feedback from the Critic node.
- `iteration_count`: To prevent infinite loops (Max 3).

### **B. Nodes Implementation**

1. **`node_static_analysis`**: Executes `cppcheck` on a local `.cpp` file. It should handle errors gracefully and return the stdout as context.
2. **`node_security_scanner`**: Acts as a "Security Researcher." It analyzes the code + static hints. It must output a structured list of potential vulnerabilities using a Pydantic model.
3. **`node_critic_auditor`**: The core "Self-Reflection" node. It must follow a **3-Step Verification Protocol**:
   - **Data Flow Validation**: Trace the input to see if it's user-controllable.
   - **False Positive Scrubbing**: Specifically check for RAII/Smart Pointers or existing bounds checks that might invalidate the bug.
   - **Severity Rating**: Assign CVSS-based scores.
4. **`node_report_generator`**: Compiles the final findings into a clean Markdown table.

### **C. Conditional Edges**

- **`route_reflection`**: After the Critic node, if `vulnerabilities` are rejected OR logic is incomplete, and `iteration_count < 3`, loop back to the Scanner with the `critic_log`. Otherwise, go to the Reporter.

## 4. Specific Node Logic (The "Brain")

- **Scanner Prompting**: "Focus on Memory Safety (Overflows, UAF), Logic Errors in TEE, and Information Leakage. Be thorough."
- **Critic Prompting**: "You are a skeptical Senior Security Lead. Your goal is to find reasons why the Scanner's findings are INCORRECT. Prove that the bug cannot be triggered or is already mitigated. Be extremely pedantic."

## 5. Coding Requirements

Please provide a complete, executable Python script including:

1. **Mock Tool Function**: A function that simulates `cppcheck` output if the binary isn't installed, plus the real implementation.
2. **Pydantic Schemas**: For structured LLM output (essential for tool-use).
3. **LangGraph Workflow**: Definition using `StateGraph`.
4. **Sample Test Case**: A C++ snippet containing a subtle memory vulnerability (e.g., a buffer overflow that only happens in a specific `if` branch) to test the agent's reflection capability.

## 6. Project "Evolution" Comments

In the code, please include comments or separate methods to demonstrate:

- **Phase 1**: How a naive single-prompt approach fails.
- **Phase 2**: How adding the Critic node corrects the hallucination.
- **Phase 3**: How the `static_hints` from `cppcheck` ground the LLM in factual analysis.

------

### **Now, please generate the complete, production-grade Python code for this system.**

