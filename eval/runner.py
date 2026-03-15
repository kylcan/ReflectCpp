"""
eval/runner.py – Execute three evaluation configurations and collect results.

Configurations
--------------
1. **Baseline**   – Single zero-shot LLM prompt (no reflection, no static hints).
2. **Reflection** – Scanner → Critic loop (no static hints).
3. **Grounded**   – Scanner → Critic loop WITH cppcheck static hints.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from eval.dataset import TestCase, load_dataset
from eval.metrics import EvalMetrics, FileResult, aggregate, score_file
from eval.report import print_comparison_table, save_eval_report

logger = logging.getLogger(__name__)


# ── helpers ───────────────────────────────────────────────────────────────

def _get_llm(temperature: float = 0.0):
    """Centralised LLM constructor (mirrors src/nodes._get_llm)."""
    from langchain_openai import ChatOpenAI

    api_key = os.getenv("GPT5_KEY") or os.getenv("OPENAI_API_KEY")
    model = os.getenv("CHATGPT_MODEL") or os.getenv("AUDIT_MODEL", "gpt-4o")
    base_url = (
        os.getenv("CHATGPT_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or os.getenv("OPENAI_API_BASE")
    )
    kwargs: dict[str, Any] = {"model": model, "temperature": temperature}
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url.rstrip("/")
    return ChatOpenAI(**kwargs)


def _parse_json_response(text: str) -> dict:
    """Best-effort JSON extraction from LLM response text."""
    import re
    # Try markdown fenced block first
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        return json.loads(match.group(1))
    return json.loads(text)


def _safe_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item if isinstance(item, str) else item.get("text", "")
            for item in content
        )
    return str(content)


# ── Baseline: single zero-shot prompt ─────────────────────────────────────

_BASELINE_PROMPT = """\
You are a security auditor. Analyse the following C++ code and list all vulnerabilities.
For each vulnerability return a JSON object with keys: vuln_type, cwe_id, location, \
description, severity (Critical/High/Medium/Low/Info), status (set to "Confirmed"), cvss_score.
Return a JSON object: {{"vulnerabilities": [...]}}
Respond ONLY with valid JSON.

```cpp
{source_code}
```"""


def run_baseline(case: TestCase) -> tuple[list[dict], float]:
    """Run a single-prompt baseline audit. Returns (vulns, latency)."""
    from langchain_core.messages import HumanMessage

    llm = _get_llm(temperature=0.0)
    t0 = time.time()
    try:
        resp = llm.invoke([HumanMessage(content=_BASELINE_PROMPT.format(source_code=case.source_code))])
        text = _safe_content(resp.content)
        parsed = _parse_json_response(text)
        vulns = parsed.get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("Baseline failed for %s: %s", case.filename, exc)
        vulns = []
    latency = time.time() - t0
    return vulns, latency


# ── Reflection: scanner + critic, no static hints ─────────────────────────

def run_reflection(case: TestCase) -> tuple[list[dict], float]:
    """Run scanner→critic loop WITHOUT static hints."""
    from src.graph import build_audit_graph
    from src.schemas import GraphState

    state: GraphState = {
        "source_code": case.source_code,
        "source_file_path": "",
        "static_hints": "(static analysis disabled for this evaluation group)",
        "vulnerabilities": [],
        "critic_log": [],
        "needs_rescan": False,
        "iteration_count": 0,
        "final_report": "",
        "run_metadata": {},
    }

    graph = build_audit_graph()
    t0 = time.time()
    try:
        result = graph.invoke(state)
        vulns = result.get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("Reflection failed for %s: %s", case.filename, exc)
        vulns = []
    latency = time.time() - t0
    return vulns, latency


# ── Grounded: scanner + critic + cppcheck ─────────────────────────────────

def run_grounded(case: TestCase) -> tuple[list[dict], float]:
    """Run the full pipeline with cppcheck grounding."""
    from src.graph import run_audit

    t0 = time.time()
    try:
        result = run_audit(case.source_code, source_file_path=case.file_path)
        vulns = result.get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("Grounded failed for %s: %s", case.filename, exc)
        vulns = []
    latency = time.time() - t0
    return vulns, latency


# ── Orchestrator ──────────────────────────────────────────────────────────

RunnerFunc = Callable[["TestCase"], tuple[list[dict[str, Any]], float]]

CONFIGURATIONS: dict[str, RunnerFunc] = {
    "Baseline (Phase 1)": run_baseline,
    "Reflection (Phase 2)": run_reflection,
    "Grounded (Phase 2+3)": run_grounded,
}


def evaluate_all(
    configs: dict[str, RunnerFunc] | None = None,
    testcases_dir: str | Path | None = None,
) -> dict[str, EvalMetrics]:
    """Run all configured experiments and return metrics keyed by config name."""
    if configs is None:
        configs = CONFIGURATIONS

    dataset = load_dataset(testcases_dir)
    logger.info("Loaded %d test cases", len(dataset))

    all_metrics: dict[str, EvalMetrics] = {}

    for config_name, runner_fn in configs.items():
        logger.info("═══ Running config: %s ═══", config_name)
        file_results: list[FileResult] = []

        for case in dataset:
            logger.info("  → %s", case.filename)
            vulns, latency = runner_fn(case)
            expected_cwes = [v.cwe_id for v in case.expected_vulns]

            fr = score_file(
                filename=case.filename,
                expected_cwe_ids=expected_cwes,
                predicted_vulns=vulns,
                latency_s=latency,
            )
            file_results.append(fr)
            logger.info(
                "    TP=%d FP=%d FN=%d TN=%d (%.1fs)",
                fr.true_positives, fr.false_positives,
                fr.false_negatives, fr.true_negatives, fr.latency_s,
            )

        metrics = aggregate(file_results)
        all_metrics[config_name] = metrics
        logger.info(
            "  → P=%.2f  R=%.2f  F1=%.2f  FPR=%.2f",
            metrics.precision, metrics.recall, metrics.f1,
            metrics.false_positive_rate,
        )

    return all_metrics


# ── CLI entry point ───────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    results = evaluate_all()
    print_comparison_table(results)
    save_eval_report(results)


if __name__ == "__main__":
    main()
