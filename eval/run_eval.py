from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable

from eval.generate_dataset import build_cases, write_dataset
from eval.metrics import Metrics, RunSummary, per_case_prf1, summarize_runs
from sentinel_agent.graph import run_agent
from sentinel_agent.tools.cppcheck import CppcheckTool
from sentinel_agent.tools.grep_scanner import GrepScannerTool


EVAL_CWE_ALLOWLIST: set[str] = {"CWE-78", "CWE-120", "CWE-338", "CWE-476"}


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


def _baseline_predicted_cwes(target_path: str) -> set[str]:
    """Deterministic baseline using existing offline tools.

    We intentionally restrict to a small allowlist of CWEs that appear in the
    synthetic dataset to avoid noise from generic patterns.
    """
    predicted: set[str] = set()

    try:
        grep_json = GrepScannerTool().execute(path=target_path)
        grep_payload = json.loads(grep_json) if grep_json else {}
        for m in grep_payload.get("matches", []) or []:
            cwe = (m.get("cwe") or "").strip()
            if cwe in EVAL_CWE_ALLOWLIST:
                predicted.add(cwe)
    except Exception:
        pass

    try:
        cpp_json = CppcheckTool().execute(file_path=target_path)
        cpp_payload = json.loads(cpp_json) if cpp_json else {}
        for f in cpp_payload.get("findings", []) or []:
            msg = (f.get("message") or "").lower()
            if "system()" in msg or "command" in msg:
                predicted.add("CWE-78")
            if "strcpy" in msg or "memcpy" in msg or "buffer overflow" in msg:
                predicted.add("CWE-120")
            if "rand()" in msg or "weak prng" in msg:
                predicted.add("CWE-338")
            if "null pointer" in msg or "malloc" in msg:
                predicted.add("CWE-476")
    except Exception:
        pass

    return predicted & EVAL_CWE_ALLOWLIST


def _score_cases(
    *,
    cases: list[dict],
    root: Path,
    predictor: Callable[[str], tuple[set[str], dict]],
    reflection_stats: dict[str, int] | None = None,
) -> RunSummary:
    metrics = Metrics()
    macro_ps: list[float] = []
    macro_rs: list[float] = []
    macro_f1s: list[float] = []

    for case in cases:
        rel_target = case.get("repo_path") or case.get("path")
        if not rel_target:
            raise ValueError(f"Case {case.get('id')} missing repo_path/path")
        target = str(root / rel_target)

        expected = set(case.get("expected_cwes", [])) & EVAL_CWE_ALLOWLIST
        predicted, md = predictor(target)
        predicted = set(predicted) & EVAL_CWE_ALLOWLIST

        if reflection_stats is not None:
            reflection_stats["analyzer_candidates"] += int(md.get("analyzer_candidate_count", 0) or 0)
            reflection_stats["critic_confirmed"] += int(md.get("critic_confirmed_count", 0) or 0)
            reflection_stats["critic_rejected"] += int(md.get("critic_rejected_count", 0) or 0)

        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        metrics.tp += tp
        metrics.fp += fp
        metrics.fn += fn
        metrics.cases += 1

        p, r, f1, exact = per_case_prf1(predicted, expected)
        macro_ps.append(p)
        macro_rs.append(r)
        macro_f1s.append(f1)
        if exact:
            metrics.exact_matches += 1

    macro_precision = sum(macro_ps) / len(macro_ps) if macro_ps else 0.0
    macro_recall = sum(macro_rs) / len(macro_rs) if macro_rs else 0.0
    macro_f1 = sum(macro_f1s) / len(macro_f1s) if macro_f1s else 0.0

    return RunSummary(
        micro=metrics,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SentinelAgent eval on a fixed synthetic dataset")
    parser.add_argument("--regen", action="store_true", help="Regenerate the dataset files")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of cases (0 = all)")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat the whole eval N times (useful for LLM variance)")
    parser.add_argument("--no-baseline", action="store_true", help="Skip deterministic baseline scoring")
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

    repeat = max(int(args.repeat or 1), 1)

    def agent_predictor(target: str) -> tuple[set[str], dict]:
        result = run_agent(target, max_iterations=2)
        return _predicted_cwes(result), (result.get("run_metadata", {}) or {})

    def baseline_predictor(target: str) -> tuple[set[str], dict]:
        return _baseline_predicted_cwes(target), {}

    agent_runs: list[RunSummary] = []
    baseline_runs: list[RunSummary] = []
    reflection_stats = {
        "analyzer_candidates": 0,
        "critic_confirmed": 0,
        "critic_rejected": 0,
    }

    for _ in range(repeat):
        # Score agent
        agent_summary = _score_cases(
            cases=cases,
            root=root,
            predictor=agent_predictor,
            reflection_stats=reflection_stats,
        )
        agent_runs.append(agent_summary)

        if not args.no_baseline:
            baseline_runs.append(_score_cases(cases=cases, root=root, predictor=baseline_predictor))

    agent_repeated = summarize_runs(agent_runs)
    baseline_repeated = summarize_runs(baseline_runs) if baseline_runs else None

    agent_micro = agent_runs[-1].micro
    baseline_micro = baseline_runs[-1].micro if baseline_runs else None

    summary = {
        "cases": len(cases),
        "repeat": repeat,
        "cwe_allowlist": sorted(EVAL_CWE_ALLOWLIST),
        "agent": {
            "micro": {
                "tp": agent_micro.tp,
                "fp": agent_micro.fp,
                "fn": agent_micro.fn,
                "precision": agent_micro.precision,
                "recall": agent_micro.recall,
                "f1": agent_micro.f1,
                "fp_rate": agent_micro.fp_rate,
                "exact_match_rate": agent_micro.exact_match_rate,
            },
            "macro": {
                "precision": agent_runs[-1].macro_precision,
                "recall": agent_runs[-1].macro_recall,
                "f1": agent_runs[-1].macro_f1,
            },
            "repeated": {
                "mean_micro_f1": agent_repeated.mean_micro_f1,
                "std_micro_f1": agent_repeated.std_micro_f1,
                "mean_macro_f1": agent_repeated.mean_macro_f1,
                "std_macro_f1": agent_repeated.std_macro_f1,
            },
            "reflection": reflection_stats,
        },
    }

    if baseline_micro is not None and baseline_runs:
        summary["baseline"] = {
            "micro": {
                "tp": baseline_micro.tp,
                "fp": baseline_micro.fp,
                "fn": baseline_micro.fn,
                "precision": baseline_micro.precision,
                "recall": baseline_micro.recall,
                "f1": baseline_micro.f1,
                "fp_rate": baseline_micro.fp_rate,
                "exact_match_rate": baseline_micro.exact_match_rate,
            },
            "macro": {
                "precision": baseline_runs[-1].macro_precision,
                "recall": baseline_runs[-1].macro_recall,
                "f1": baseline_runs[-1].macro_f1,
            },
            "repeated": {
                "mean_micro_f1": baseline_repeated.mean_micro_f1 if baseline_repeated else 0.0,
                "std_micro_f1": baseline_repeated.std_micro_f1 if baseline_repeated else 0.0,
                "mean_macro_f1": baseline_repeated.mean_macro_f1 if baseline_repeated else 0.0,
                "std_macro_f1": baseline_repeated.std_macro_f1 if baseline_repeated else 0.0,
            },
        }
        summary["delta_agent_minus_baseline"] = {
            "micro_f1": agent_micro.f1 - baseline_micro.f1,
            "macro_f1": agent_runs[-1].macro_f1 - baseline_runs[-1].macro_f1,
            "exact_match_rate": agent_micro.exact_match_rate - baseline_micro.exact_match_rate,
        }

    out_json = root / "eval" / "results.json"
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"Wrote: {out_json}")


if __name__ == "__main__":
    main()
