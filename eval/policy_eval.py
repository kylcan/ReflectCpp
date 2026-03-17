from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from sentinel_agent.tools import TOOL_REGISTRY
from sentinel_agent.tools.tool_policy import ToolSelectionPolicy, build_default_capabilities


DatasetItem = dict[str, Any]


def _load_dataset(path: Path) -> list[DatasetItem]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Dataset must be a JSON list")
    out: list[DatasetItem] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Item {i} must be an object")
        task = str(item.get("task", "") or "").strip()
        correct = str(item.get("correct_tool", "") or "").strip()
        if not task or not correct:
            raise ValueError(f"Item {i} missing task/correct_tool")
        out.append({"task": task, "correct_tool": correct})
    return out


def _mock_llm_preference(task_text: str, tool_name: str, tool_description: str) -> float:
    """Deterministic mock for "LLM preference".

    This is a stand-in scorer that mimics the behavior of a competent tool-chooser.
    It is intentionally simple and dependency-free so it can run in CI.
    """
    t = (task_text or "").lower()
    name = (tool_name or "").lower()

    # Strong intents
    if any(k in t for k in ["map repo", "repository structure", "file tree", "inventory", "list all files"]):
        return 1.0 if name == "repo_mapper" else 0.2

    if any(k in t for k in ["dependency", "dependencies", "manifest", "requirements.txt", "package.json", "cmakelists"]):
        return 1.0 if name == "dependency_scanner" else 0.2

    if any(k in t for k in ["open the file", "read the file", "show lines", "around the", "readme", "build instructions"]):
        return 1.0 if name == "file_reader" else 0.2

    if any(k in t for k in ["ast", "parse", "syntax tree", "call sites", "function boundaries"]):
        return 1.0 if name == "ast_parser" else 0.2

    # Security scanning: prefer cppcheck for "run static analysis"; prefer grep for "search/grep"
    if any(k in t for k in ["run static analysis", "static analysis", "cppcheck"]):
        return 1.0 if name == "cppcheck" else 0.3

    if any(k in t for k in ["search", "grep", "occurrences", "find uses", "across the repo"]):
        return 1.0 if name == "grep_scanner" else 0.3

    # Default mild preference to grep_scanner for broad discovery
    return 0.6 if name == "grep_scanner" else 0.4


def evaluate_policy(policy: ToolSelectionPolicy, dataset: list[DatasetItem], *, k: int = 3) -> dict[str, float]:
    """Evaluate a policy on a dataset.

    Dataset format:
      [{"task": str, "correct_tool": str}, ...]

    Metrics:
      - Top-1 accuracy
      - Top-K recall
    """
    k = max(int(k), 1)

    top1 = 0
    topk = 0

    for item in dataset:
        task = str(item["task"])
        correct = str(item["correct_tool"])

        selected = policy.select(task_text=task, tool_hint="", k=k, epsilon=0.0)
        selected_names = [s.tool_name for s in selected]

        if selected_names and selected_names[0] == correct:
            top1 += 1
        if correct in selected_names[:k]:
            topk += 1

    n = len(dataset)
    return {
        "top1_accuracy": (top1 / n) if n else 0.0,
        "topk_recall": (topk / n) if n else 0.0,
        "n": float(n),
    }


def _evaluate_selector(
    *,
    tool_names: list[str],
    dataset: list[DatasetItem],
    selector: Callable[[str, int], list[str]],
    k: int,
) -> dict[str, float]:
    k = max(int(k), 1)
    top1 = 0
    topk = 0

    for item in dataset:
        task = str(item["task"])
        correct = str(item["correct_tool"])

        chosen = selector(task, k)
        if chosen and chosen[0] == correct:
            top1 += 1
        if correct in chosen[:k]:
            topk += 1

    n = len(dataset)
    return {
        "top1_accuracy": (top1 / n) if n else 0.0,
        "topk_recall": (topk / n) if n else 0.0,
        "n": float(n),
    }


def _print_table(rows: list[tuple[str, dict[str, float]]]) -> None:
    headers = ["mode", "top1_accuracy", "topk_recall", "n"]

    # Prepare strings
    table: list[list[str]] = []
    for name, m in rows:
        table.append(
            [
                name,
                f"{m['top1_accuracy']:.3f}",
                f"{m['topk_recall']:.3f}",
                str(int(m["n"])),
            ]
        )

    # Column widths
    widths = [len(h) for h in headers]
    for r in table:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in widths))
    for r in table:
        print(fmt_row(r))


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate tool selection policy against a labeled dataset")
    p.add_argument(
        "--dataset",
        type=str,
        default="eval/policy_eval_dataset.json",
        help="Path to JSON dataset",
    )
    p.add_argument("--k", type=int, default=3, help="K for Top-K recall")
    args = p.parse_args()

    root = Path(__file__).resolve().parents[1]
    dataset_path = (root / args.dataset).resolve() if not Path(args.dataset).is_absolute() else Path(args.dataset)
    dataset = _load_dataset(dataset_path)

    tool_caps = build_default_capabilities(TOOL_REGISTRY)
    tool_names = sorted(tool_caps)

    # Mode 1: LLM-only (mock)
    def llm_only(task: str, k: int) -> list[str]:
        scored = []
        for tn in tool_names:
            scored.append((tn, _mock_llm_preference(task, tn, tool_caps.get(tn, ""))))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [t for t, _ in scored[:k]]

    # Mode 2: policy-only (no LLM preference)
    os.environ.pop("SENTINEL_TOOL_LLM_PREF", None)
    policy_only = ToolSelectionPolicy(tool_capabilities=tool_caps)

    def policy_only_sel(task: str, k: int) -> list[str]:
        selected = policy_only.select(task_text=task, k=k, epsilon=0.0)
        return [s.tool_name for s in selected]

    # Mode 3: hybrid (policy + LLM preference mock)
    # We monkeypatch the module-level function so we don't require real LLM calls.
    import sentinel_agent.tools.tool_policy as tp

    original_llm_pref = tp.get_llm_preference

    def hybrid_sel(task: str, k: int) -> list[str]:
        tp.get_llm_preference = _mock_llm_preference  # type: ignore
        try:
            hybrid_policy = ToolSelectionPolicy(tool_capabilities=tool_caps, llm_alpha=0.3)
            selected = hybrid_policy.select(task_text=task, k=k, epsilon=0.0)
            return [s.tool_name for s in selected]
        finally:
            tp.get_llm_preference = original_llm_pref  # type: ignore

    results = [
        ("llm_only_mock", _evaluate_selector(tool_names=tool_names, dataset=dataset, selector=llm_only, k=args.k)),
        ("policy_only", _evaluate_selector(tool_names=tool_names, dataset=dataset, selector=policy_only_sel, k=args.k)),
        ("hybrid_policy_plus_llm_mock", _evaluate_selector(tool_names=tool_names, dataset=dataset, selector=hybrid_sel, k=args.k)),
    ]

    _print_table(results)


if __name__ == "__main__":
    main()
