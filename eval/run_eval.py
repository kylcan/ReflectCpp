from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from eval.generate_dataset import build_cases, write_dataset
from eval.metrics import Metrics
from sentinel_agent.graph import run_agent


def _load_cases(index_path: Path) -> list[dict]:
    cases: list[dict] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cases.append(json.loads(line))
    return cases


def _predicted_cwes(result: dict) -> set[str]:
    vulns = result.get("vulnerabilities", [])
    confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
    cwes: set[str] = set()
    for v in confirmed:
        cwe = (v.get("cwe_id") or "").strip()
        if cwe:
            cwes.add(cwe)
    return cwes


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SentinelAgent eval on a fixed synthetic dataset")
    parser.add_argument("--regen", action="store_true", help="Regenerate the dataset files")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of cases (0 = all)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    dataset_dir = root / "eval" / "dataset"
    index_path = dataset_dir / "cases.jsonl"

    if args.regen or not index_path.exists():
        cases = build_cases(n_each=10)  # 60 total
        index_path = write_dataset(dataset_dir, cases)

    # Force deterministic offline mode unless user explicitly disables
    os.environ.setdefault("SENTINEL_OFFLINE", "1")

    cases = _load_cases(index_path)
    if args.limit and args.limit > 0:
        cases = cases[: args.limit]

    metrics = Metrics()
    reflection_stats = {
        "analyzer_candidates": 0,
        "critic_confirmed": 0,
        "critic_rejected": 0,
    }

    for case in cases:
        rel_target = case.get("repo_path") or case.get("path")
        if not rel_target:
            raise ValueError(f"Case {case.get('id')} missing repo_path/path")
        target = str(root / rel_target)
        expected = set(case.get("expected_cwes", []))

        result = run_agent(target, max_iterations=2)
        predicted = _predicted_cwes(result)

        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)

        metrics.tp += tp
        metrics.fp += fp
        metrics.fn += fn

        md = result.get("run_metadata", {})
        reflection_stats["analyzer_candidates"] += int(md.get("analyzer_candidate_count", 0) or 0)
        reflection_stats["critic_confirmed"] += int(md.get("critic_confirmed_count", 0) or 0)
        reflection_stats["critic_rejected"] += int(md.get("critic_rejected_count", 0) or 0)

    summary = {
        "cases": len(cases),
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "fp_rate": metrics.fp_rate,
        "reflection": reflection_stats,
    }

    out_json = root / "eval" / "results.json"
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"Wrote: {out_json}")


if __name__ == "__main__":
    main()
