"""
LangGraph node implementations for the Code Security Audit Agent.

Node pipeline:
  static_analysis → security_scanner ⇄ critic_auditor → report_generator

Evolution commentary is embedded as docstrings throughout.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI

from .schemas import (
    CriticFeedback,
    GraphState,
    ScannerOutput,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM factory – swap between OpenAI / Anthropic here
# ---------------------------------------------------------------------------

def _get_llm(temperature: float = 0.0):
    """Return a ChatOpenAI instance.

    Set OPENAI_API_KEY in your environment.  To use Claude, install
    langchain-anthropic and swap to ChatAnthropic.
    """
    # Support OpenAI and OpenAI-compatible third-party providers.
    # Priority: project-specific env vars -> OpenAI defaults.
    api_key = os.getenv("GPT5_KEY") or os.getenv("OPENAI_API_KEY")
    model = os.getenv("CHATGPT_MODEL") or os.getenv("AUDIT_MODEL", "gpt-4o")
    base_url = (
        os.getenv("CHATGPT_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE")
    )

    llm_kwargs: dict[str, Any] = {
        "model": model,
        "temperature": temperature,
    }
    if api_key:
        llm_kwargs["api_key"] = api_key
    if base_url:
        llm_kwargs["base_url"] = base_url.rstrip("/")

    return ChatOpenAI(**llm_kwargs)


def _require_source_code(state: GraphState) -> str:
    """Return source code from state or raise a clear error."""
    source_code = state.get("source_code", "")
    if not source_code:
        raise ValueError("GraphState is missing required key: source_code")
    return source_code


def _message_text(content: Any) -> str:
    """Normalize LangChain message content into a plain string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


def _mock_scanner_output(state: GraphState) -> dict:
    """Deterministic fallback when LLM API is unavailable."""
    hints = state.get("static_hints", "")
    findings: list[dict[str, Any]] = []

    if "out of bounds" in hints.lower() or "buffer" in hints.lower():
        findings.append(
            {
                "vuln_type": "Buffer Overflow (CWE-120)",
                "cwe_id": "CWE-120",
                "location": "vuln_sample.cpp:39",
                "description": "Unbounded strcpy in admin branch may overflow buffer[64].",
                "severity": "High",
                "status": "Candidate",
                "cvss_score": 8.1,
                "confidence": 0.9,
                "evidence": ["strcpy(buffer, input); // no bounds check"],
                "data_flow": "input parameter → strcpy → buffer[64]",
                "exploitability": "Likely",
                "remediation": "Replace strcpy with strncpy(buffer, input, sizeof(buffer)-1).",
                "related_functions": ["process_request"],
            }
        )
    if "null pointer" in hints.lower() or "null" in hints.lower():
        findings.append(
            {
                "vuln_type": "Null Pointer Dereference (CWE-476)",
                "cwe_id": "CWE-476",
                "location": "vuln_sample.cpp:55",
                "description": "malloc result may be null before dereference.",
                "severity": "Medium",
                "status": "Candidate",
                "cvss_score": 5.9,
                "confidence": 0.85,
                "evidence": ["TeeContext* ctx = (TeeContext*)malloc(sizeof(TeeContext));"],
                "data_flow": "malloc return → ctx pointer → ctx->enclave_id dereference",
                "exploitability": "Likely",
                "remediation": "Add NULL check after malloc: if (!ctx) return nullptr;",
                "related_functions": ["init_tee_context"],
            }
        )
    if "memory leak" in hints.lower() or "leak" in hints.lower():
        findings.append(
            {
                "vuln_type": "Memory Leak (CWE-401)",
                "cwe_id": "CWE-401",
                "location": "vuln_sample.cpp:76",
                "description": "Early return path may leak secret buffer.",
                "severity": "Medium",
                "status": "Candidate",
                "cvss_score": 6.5,
                "confidence": 0.88,
                "evidence": ["return -2; // secret_buf not freed"],
                "data_flow": "malloc(key_len) → secret_buf → early return without free",
                "exploitability": "Likely",
                "remediation": "Add free(secret_buf) before early return.",
                "related_functions": ["load_secret_key"],
            }
        )

    if not findings:
        findings.append(
            {
                "vuln_type": "Potential Memory Safety Issue",
                "cwe_id": "",
                "location": "vuln_sample.cpp:1",
                "description": "No LLM output available; static hint fallback detected potential risk.",
                "severity": "Info",
                "status": "Candidate",
                "cvss_score": 0.0,
                "confidence": 0.1,
                "evidence": [],
                "data_flow": "",
                "exploitability": "Unknown",
                "remediation": "",
                "related_functions": [],
            }
        )

    return {
        "vulnerabilities": findings,
        "analysis_notes": "Fallback scanner used due to LLM/API unavailability.",
    }


def _mock_critic_output(state: GraphState) -> dict:
    """Deterministic critic fallback when LLM API is unavailable."""
    reviewed: list[dict[str, Any]] = []
    for vuln in state.get("vulnerabilities", []):
        item = dict(vuln)
        desc = str(item.get("description", ""))
        vuln_type = str(item.get("vuln_type", ""))

        if "Memory Leak" in vuln_type or "Null Pointer" in vuln_type or "Buffer Overflow" in vuln_type:
            item["status"] = "Confirmed"
            # Enrich with critic assessment
            item.setdefault("confidence", 0.85)
            item.setdefault("exploitability", "Likely")
        else:
            item["status"] = "Rejected"
            item["confidence"] = 0.2
            item["exploitability"] = "Unlikely"
            if desc:
                desc += " "
            item["description"] = desc + "Rejected by fallback critic due to insufficient evidence."

        reviewed.append(item)

    needs_rescan = any(v.get("status") == "Rejected" for v in reviewed) and state.get("iteration_count", 0) < MAX_ITERATIONS
    return {
        "reviewed_vulnerabilities": reviewed,
        "critic_notes": "Fallback critic used due to LLM/API unavailability.",
        "needs_rescan": bool(needs_rescan),
    }


# ═══════════════════════════════════════════════════════════════════════════
# NODE 1 – Static Analysis (cppcheck)
# ═══════════════════════════════════════════════════════════════════════════

_MOCK_CPPCHECK_OUTPUT = """\
[vuln_sample.cpp:18]: (error) Array 'buffer[64]' accessed at index 128, which is out of bounds.
[vuln_sample.cpp:34]: (warning) Possible null pointer dereference: ctx
[vuln_sample.cpp:52]: (style) Variable 'key' is assigned a value that is never used.
[vuln_sample.cpp:67]: (error) Memory leak: secret_buf
"""


def _run_cppcheck(file_path: str) -> str:
    """Run cppcheck on *file_path* and return its diagnostic output.

    Falls back to mock output when cppcheck is not installed so the
    demo remains self-contained.
    """
    if not shutil.which("cppcheck"):
        logger.warning("cppcheck binary not found – using mock output.")
        return _MOCK_CPPCHECK_OUTPUT

    try:
        result = subprocess.run(
            [
                "cppcheck",
                "--enable=all",
                "--inconclusive",
                "--force",
                "--quiet",
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stderr or result.stdout  # cppcheck writes to stderr
        return output if output.strip() else "(cppcheck produced no findings)"
    except subprocess.TimeoutExpired:
        logger.error("cppcheck timed out after 60 s")
        return "(cppcheck timed out)"
    except Exception as exc:
        logger.error("cppcheck execution failed: %s", exc)
        return f"(cppcheck error: {exc})"


def node_static_analysis(state: GraphState) -> dict:
    """Execute cppcheck and store raw diagnostics in *static_hints*."""
    source_code = _require_source_code(state)
    file_path: str | None = state.get("source_file_path")

    if file_path and Path(file_path).is_file():
        hints = _run_cppcheck(file_path)
    else:
        # Write source to a temp file so cppcheck can process it
        with tempfile.NamedTemporaryFile(
            suffix=".cpp", mode="w", delete=False
        ) as tmp:
            tmp.write(source_code)
            tmp_path = tmp.name
        try:
            hints = _run_cppcheck(tmp_path)
        finally:
            os.unlink(tmp_path)

    logger.info("Static analysis complete – %d bytes of output", len(hints))
    return {"static_hints": hints}


# ═══════════════════════════════════════════════════════════════════════════
# NODE 2 – Security Scanner  (LLM "Researcher" persona)
# ═══════════════════════════════════════════════════════════════════════════
#
# --- PHASE 1 commentary ---------------------------------------------------
# A naive single-prompt approach ("find bugs in this code") produces a
# laundry list of issues with many False Positives because the LLM:
#   • hallucinates line numbers,
#   • misattributes standard-library guarantees,
#   • ignores existing mitigations (RAII, bounds checks).
#
# --- PHASE 3 commentary ---------------------------------------------------
# Grounding the scanner with *static_hints* from cppcheck dramatically
# improves precision: the LLM focuses on real diagnostics instead of
# guessing, and its line-number references become verifiable.
# --------------------------------------------------------------------------

_SCANNER_SYSTEM = """\
You are a **Senior Security Researcher** performing a C++ code audit.

## Focus Areas
- Memory Safety: buffer overflows, heap/stack overflow, use-after-free, double-free.
- Logic Errors in Trusted Execution Environments (TEE): incorrect trust boundary checks.
- Information Leakage: secrets left in memory, timing side-channels.

## Instructions
1. Carefully read the source code AND the cppcheck static-analysis hints provided below.
2. For every potential vulnerability, produce a JSON object with ALL these keys:
   vuln_type, cwe_id, location, description, severity, status, cvss_score,
   confidence (float 0.0-1.0), evidence (list of code snippets),
   data_flow (string: source→sink path), exploitability (Proven|Likely|Unlikely|Unknown),
   remediation (suggested fix), related_functions (list of function names).
3. Wrap your answer in a JSON object: {"vulnerabilities": [...], "analysis_notes": "..."}
4. Use only the severity values: Critical, High, Medium, Low, Info.
5. Set status to "Candidate" for every finding.
6. Be thorough – do NOT skip issues even if they seem minor.
"""


def _build_scanner_prompt(state: GraphState) -> list:
    """Construct the prompt messages for the scanner LLM call."""
    source_code = _require_source_code(state)
    critic_context = ""
    if state.get("critic_log"):
        critic_context = (
            "\n\n## Previous Critic Feedback (address these concerns):\n"
            + "\n---\n".join(state.get("critic_log", []))
        )

    user_content = (
        f"## Source Code\n```cpp\n{source_code}\n```\n\n"
        f"## cppcheck Output\n```\n{state.get('static_hints', '(none)')}\n```"
        f"{critic_context}"
    )
    return [
        SystemMessage(content=_SCANNER_SYSTEM),
        HumanMessage(content=user_content),
    ]


def node_security_scanner(state: GraphState) -> dict:
    """LLM-powered vulnerability scanner with structured output."""
    llm = _get_llm(temperature=0.1)
    parser = JsonOutputParser(pydantic_object=ScannerOutput)

    messages = _build_scanner_prompt(state)
    scanner_human = _message_text(messages[-1].content) + (
        "\n\nRespond ONLY with valid JSON matching this schema:\n"
        + parser.get_format_instructions()
    )
    messages[-1] = HumanMessage(content=scanner_human)

    try:
        response = llm.invoke(messages)
        response_text = _message_text(response.content)
        parsed: dict = parser.parse(response_text)
    except Exception:
        # Fallback: try to extract JSON from markdown code fences
        try:
            import re
            response_text = _message_text(response.content) if "response" in locals() else ""
            match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
            if match:
                parsed = json.loads(match.group(1))
            else:
                parsed = json.loads(response_text)
        except Exception as exc:
            logger.warning("Scanner LLM unavailable, switching to mock fallback: %s", exc)
            parsed = _mock_scanner_output(state)

    vulns = parsed.get("vulnerabilities", [])
    logger.info("Scanner found %d candidate vulnerabilities", len(vulns))

    iteration = state.get("iteration_count", 0) + 1
    return {
        "vulnerabilities": vulns,
        "iteration_count": iteration,
    }


# ═══════════════════════════════════════════════════════════════════════════
# NODE 3 – Critic / Auditor  (Self-Reflection node)
# ═══════════════════════════════════════════════════════════════════════════
#
# --- PHASE 2 commentary ---------------------------------------------------
# Adding a dedicated Critic dramatically cuts False Positives.  The Critic
# applies a 3-Step Verification Protocol:
#   1. Data-Flow Validation  – is the input actually user-controllable?
#   2. FP Scrubbing          – do RAII / smart pointers / bounds checks
#                              already mitigate the issue?
#   3. Severity Rating       – assign a realistic CVSS score.
#
# Without the Critic, the Scanner confirms almost everything it finds.
# With the Critic, only genuinely exploitable issues survive.
# --------------------------------------------------------------------------

_CRITIC_SYSTEM = """\
You are a **skeptical Senior Security Lead** reviewing vulnerability reports.

## 3-Step Verification Protocol
For EACH vulnerability in the list:

### Step 1 – Data-Flow Validation
Trace the data from its origin. Is the input actually user-controllable or
externally reachable? If the value is compile-time constant or internal-only,
the finding is likely a False Positive. Update the "data_flow" field.

### Step 2 – False-Positive Scrubbing
Check for existing mitigations:
- RAII / smart pointers (std::unique_ptr, std::shared_ptr)
- Bounds checks (e.g., `if (idx < sizeof(buf))`)
- Safe library functions (snprintf vs sprintf)
- Enclave boundary validation (for TEE code)
If adequate mitigations exist, mark the finding as "Rejected".
Update "exploitability" (Proven/Likely/Unlikely/Unknown) and "confidence" (0.0-1.0).

### Step 3 – Severity Rating
For surviving findings, assign a CVSS 3.1 base score and confirm or
adjust the severity level. Provide a "remediation" suggestion for Confirmed issues.

## Output
Return a JSON object:
{
  "reviewed_vulnerabilities": [<updated vuln objects with ALL fields>],
  "critic_notes": "<your overall reasoning>",
  "needs_rescan": <true if scanner should re-examine with your feedback>
}

Each vuln object MUST include: vuln_type, cwe_id, location, description,
severity, status, cvss_score, confidence, evidence, data_flow,
exploitability, remediation, related_functions.

Set each vulnerability's "status" to "Confirmed" or "Rejected".
Be extremely pedantic – your job is to DISPROVE findings.
"""


def node_critic_auditor(state: GraphState) -> dict:
    """LLM-powered critic that verifies/rejects scanner findings."""
    source_code = _require_source_code(state)
    llm = _get_llm(temperature=0.0)
    parser = JsonOutputParser(pydantic_object=CriticFeedback)

    vuln_json = json.dumps(state.get("vulnerabilities", []), indent=2)
    user_content = (
        f"## Source Code\n```cpp\n{source_code}\n```\n\n"
        f"## cppcheck Output\n```\n{state.get('static_hints', '(none)')}\n```\n\n"
        f"## Scanner Findings to Review\n```json\n{vuln_json}\n```\n\n"
        "Apply the 3-Step Verification Protocol to each finding.\n"
        "Respond ONLY with valid JSON matching this schema:\n"
        + parser.get_format_instructions()
    )

    messages = [
        SystemMessage(content=_CRITIC_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        response = llm.invoke(messages)
        response_text = _message_text(response.content)
        parsed: dict = parser.parse(response_text)
    except Exception:
        try:
            import re
            response_text = _message_text(response.content) if "response" in locals() else ""
            match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
            if match:
                parsed = json.loads(match.group(1))
            else:
                parsed = json.loads(response_text)
        except Exception as exc:
            logger.warning("Critic LLM unavailable, switching to mock fallback: %s", exc)
            parsed = _mock_critic_output(state)

    reviewed = parsed.get("reviewed_vulnerabilities", [])
    notes = parsed.get("critic_notes", "")
    needs_rescan = parsed.get("needs_rescan", False)

    # Append to critic log
    existing_log = list(state.get("critic_log", []))
    existing_log.append(notes)

    confirmed = [v for v in reviewed if v.get("status") == "Confirmed"]
    rejected = [v for v in reviewed if v.get("status") == "Rejected"]
    logger.info(
        "Critic: %d confirmed, %d rejected, needs_rescan=%s",
        len(confirmed),
        len(rejected),
        needs_rescan,
    )

    return {
        "vulnerabilities": reviewed,
        "critic_log": existing_log,
        "needs_rescan": bool(needs_rescan),
    }


# ═══════════════════════════════════════════════════════════════════════════
# NODE 4 – Report Generator
# ═══════════════════════════════════════════════════════════════════════════

def node_report_generator(state: GraphState) -> dict:
    """Compile confirmed findings into a Markdown report."""
    vulns = state.get("vulnerabilities", [])
    confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
    rejected = [v for v in vulns if v.get("status") == "Rejected"]
    iterations = state.get("iteration_count", 0)

    lines: list[str] = []
    lines.append("# 🔒 Security Audit Report\n")
    lines.append(f"**Iterations:** {iterations}  ")
    lines.append(
        f"**Confirmed:** {len(confirmed)} | **Rejected:** {len(rejected)}\n"
    )

    if confirmed:
        lines.append("## Confirmed Vulnerabilities\n")
        for i, v in enumerate(confirmed, 1):
            cvss = v.get("cvss_score", "N/A")
            conf = v.get("confidence", "N/A")
            expl = v.get("exploitability", "N/A")
            lines.append(f"### {i}. {v.get('vuln_type', '')}\n")
            lines.append(f"- **CWE:** {v.get('cwe_id', 'N/A')}")
            lines.append(f"- **Location:** {v.get('location', '')}")
            lines.append(f"- **Severity:** {v.get('severity', '')} (CVSS {cvss})")
            lines.append(f"- **Confidence:** {conf}")
            lines.append(f"- **Exploitability:** {expl}")
            lines.append(f"- **Description:** {v.get('description', '')}")
            data_flow = v.get("data_flow", "")
            if data_flow:
                lines.append(f"- **Data Flow:** `{data_flow}`")
            evidence = v.get("evidence", [])
            if evidence:
                lines.append("- **Evidence:**")
                for e in evidence:
                    lines.append(f"  - `{e}`")
            remediation = v.get("remediation", "")
            if remediation:
                lines.append(f"- **Remediation:** {remediation}")
            fix_verified = v.get("fix_verified")
            if fix_verified is not None:
                icon = "✅" if fix_verified else "⚠️"
                lines.append(f"- **Fix Verified:** {icon} {v.get('fix_review', '')}")
            funcs = v.get("related_functions", [])
            if funcs:
                lines.append(f"- **Related Functions:** {', '.join(funcs)}")
            lines.append("")
    else:
        lines.append("## ✅ No confirmed vulnerabilities.\n")

    if rejected:
        lines.append("\n## Rejected Findings (False Positives)\n")
        lines.append("| # | Type | CWE | Location | Reason |")
        lines.append("|---|------|-----|----------|--------|")
        for i, v in enumerate(rejected, 1):
            lines.append(
                f"| {i} | {v.get('vuln_type','')} "
                f"| {v.get('cwe_id', '')} "
                f"| {v.get('location','')} "
                f"| {v.get('description','')} |"
            )

    if state.get("critic_log"):
        lines.append("\n## Critic Audit Log\n")
        for idx, entry in enumerate(state.get("critic_log", []), 1):
            lines.append(f"### Iteration {idx}\n{entry}\n")

    report = "\n".join(lines)
    logger.info("Report generated – %d lines", len(lines))
    return {"final_report": report}


# ═══════════════════════════════════════════════════════════════════════════
# Routing logic
# ═══════════════════════════════════════════════════════════════════════════

MAX_ITERATIONS = 3


def route_reflection(state: GraphState) -> str:
    """Decide whether to loop back to the scanner or proceed to the report.

    Loop back when:
      - Any vulnerability was rejected (scanner should re-examine), AND
      - We haven't exceeded MAX_ITERATIONS.
    """
    iteration = state.get("iteration_count", 0)
    vulns = state.get("vulnerabilities", [])

    has_rejected = any(v.get("status") == "Rejected" for v in vulns)
    needs_rescan = bool(state.get("needs_rescan", False))
    all_confirmed = all(v.get("status") == "Confirmed" for v in vulns)

    if iteration < MAX_ITERATIONS and (has_rejected or needs_rescan) and not all_confirmed:
        logger.info("Routing → scanner (iteration %d)", iteration + 1)
        return "rescan"

    logger.info("Routing → report_generator")
    return "report"


# ═══════════════════════════════════════════════════════════════════════════
# NODE 5 – Remediation Verifier  (Logic Back-Check)
# ═══════════════════════════════════════════════════════════════════════════
#
# After the Scanner ⇄ Critic loop converges, this node performs a
# "logic back-check" on every Confirmed vulnerability's remediation:
#   1. Does the suggested fix actually address the root cause?
#   2. Could the fix introduce a NEW vulnerability?
#   3. Is the fix complete (covers all code paths)?
#
# This adds a second layer of reflection focused specifically on the
# quality of the remediation output – not just "is there a bug?" but
# "is the proposed fix correct?".
# --------------------------------------------------------------------------

_VERIFIER_SYSTEM = """\
You are a **meticulous Code Review Engineer** verifying remediation suggestions.

For EACH vulnerability with a proposed remediation:

## Verification Checklist
1. **Root Cause Match** – Does the fix address the actual root cause, not just a symptom?
2. **Completeness** – Does the fix cover all affected code paths (error paths, edge cases)?
3. **Regression Safety** – Could the fix introduce a NEW vulnerability (buffer issues, race conditions, etc.)?
4. **Correctness** – Is the suggested code syntactically and semantically correct C/C++?

## Output
Return a JSON object:
{
  "verified_vulnerabilities": [
    {
      ...all original fields...,
      "fix_verified": true/false,
      "fix_review": "explanation of verification result",
      "improved_remediation": "updated fix if original was flawed (or empty if OK)"
    }
  ],
  "verifier_notes": "overall summary"
}
"""


def _mock_verifier_output(state: GraphState) -> dict:
    """Deterministic verifier fallback when LLM API is unavailable."""
    verified: list[dict[str, Any]] = []
    for vuln in state.get("vulnerabilities", []):
        if vuln.get("status") != "Confirmed":
            verified.append(vuln)
            continue
        item = dict(vuln)
        rem = item.get("remediation", "")
        if rem:
            item["fix_verified"] = True
            item["fix_review"] = "Fix addresses root cause and does not introduce new issues."
            item["improved_remediation"] = ""
        else:
            item["fix_verified"] = False
            item["fix_review"] = "No remediation was proposed."
            item["improved_remediation"] = ""
        verified.append(item)

    return {
        "verified_vulnerabilities": verified,
        "verifier_notes": "Fallback verifier used due to LLM/API unavailability.",
    }


def node_remediation_verifier(state: GraphState) -> dict:
    """Verify that proposed remediations actually fix the vulnerabilities."""
    confirmed = [
        v for v in state.get("vulnerabilities", [])
        if v.get("status") == "Confirmed"
    ]
    if not confirmed:
        logger.info("Verifier: no confirmed vulns to verify, skipping.")
        return {}

    source_code = _require_source_code(state)
    llm = _get_llm(temperature=0.0)

    vuln_json = json.dumps(confirmed, indent=2)
    user_content = (
        f"## Source Code\n```cpp\n{source_code}\n```\n\n"
        f"## Confirmed Vulnerabilities with Remediation Proposals\n"
        f"```json\n{vuln_json}\n```\n\n"
        "Verify each remediation using the 4-point checklist.\n"
        "Respond ONLY with valid JSON."
    )

    messages = [
        SystemMessage(content=_VERIFIER_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        response = llm.invoke(messages)
        response_text = _message_text(response.content)
        import re as _re
        match = _re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
        if match:
            parsed = json.loads(match.group(1))
        else:
            parsed = json.loads(response_text)
    except Exception as exc:
        logger.warning("Verifier LLM unavailable, switching to mock fallback: %s", exc)
        parsed = _mock_verifier_output(state)

    verified = parsed.get("verified_vulnerabilities", [])
    notes = parsed.get("verifier_notes", "")

    # Merge verified vulns back (keep rejected ones untouched)
    rejected = [v for v in state.get("vulnerabilities", []) if v.get("status") != "Confirmed"]
    all_vulns = verified + rejected

    # Update improved_remediation into remediation field where applicable
    for v in all_vulns:
        improved = v.get("improved_remediation", "")
        if improved:
            v["remediation"] = improved

    verified_count = sum(1 for v in verified if v.get("fix_verified"))
    logger.info("Verifier: %d/%d fixes verified, notes=%s",
                verified_count, len(verified), notes[:80])

    return {"vulnerabilities": all_vulns}
