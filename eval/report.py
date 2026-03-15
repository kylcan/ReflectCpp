"""
eval/report.py – Format evaluation results into comparison tables.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from eval.metrics import EvalMetrics


def comparison_table_md(results: dict[str, EvalMetrics]) -> str:
    """Render a Markdown comparison table from evaluation results."""
    lines: list[str] = []
    lines.append("# Evaluation Results — Multi-Agent Reflection Comparison\n")
    lines.append(
        "| Configuration | Precision | Recall | F1 | FPR | TP | FP | FN | TN | Avg Latency (s) |"
    )
    lines.append(
        "|---------------|-----------|--------|----|-----|----|----|----|----|------------------|"
    )

    for name, m in results.items():
        lines.append(
            f"| {name} "
            f"| {m.precision:.2f} "
            f"| {m.recall:.2f} "
            f"| {m.f1:.2f} "
            f"| {m.false_positive_rate:.2f} "
            f"| {m.total_tp} "
            f"| {m.total_fp} "
            f"| {m.total_fn} "
            f"| {m.total_tn} "
            f"| {m.avg_latency_s:.1f} |"
        )

    lines.append("")
    lines.append("## Per-File Breakdown\n")

    for name, m in results.items():
        lines.append(f"### {name}\n")
        lines.append("| File | Expected | Predicted | TP | FP | FN | Latency |")
        lines.append("|------|----------|-----------|----|----|----|---------| ")
        for fr in m.file_results:
            lines.append(
                f"| {fr.filename} "
                f"| {', '.join(fr.expected_cwe_ids) or '—'} "
                f"| {', '.join(fr.predicted_cwe_ids) or '—'} "
                f"| {fr.true_positives} "
                f"| {fr.false_positives} "
                f"| {fr.false_negatives} "
                f"| {fr.latency_s:.1f}s |"
            )
        lines.append("")

    return "\n".join(lines)


def print_comparison_table(results: dict[str, EvalMetrics]) -> None:
    """Print the comparison table to stdout."""
    print(comparison_table_md(results))


def save_eval_report(
    results: dict[str, EvalMetrics],
    output_dir: str | Path | None = None,
) -> Path:
    """Save Markdown + JSON evaluation report.

    Returns the path to the saved Markdown file.
    """
    if output_dir is None:
        output_dir = Path(__file__).resolve().parent.parent / "docs"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Markdown
    md_path = output_dir / "eval_results.md"
    md_path.write_text(comparison_table_md(results), encoding="utf-8")

    # JSON (machine-readable)
    json_data: dict[str, Any] = {}
    for name, m in results.items():
        json_data[name] = {
            "precision": m.precision,
            "recall": m.recall,
            "f1": m.f1,
            "fpr": m.false_positive_rate,
            "tp": m.total_tp,
            "fp": m.total_fp,
            "fn": m.total_fn,
            "tn": m.total_tn,
            "avg_latency_s": m.avg_latency_s,
            "file_results": [
                {
                    "filename": fr.filename,
                    "expected": fr.expected_cwe_ids,
                    "predicted": fr.predicted_cwe_ids,
                    "tp": fr.true_positives,
                    "fp": fr.false_positives,
                    "fn": fr.false_negatives,
                    "tn": fr.true_negatives,
                    "latency_s": fr.latency_s,
                }
                for fr in m.file_results
            ],
        }

    json_path = output_dir / "eval_results.json"
    json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"📊 Eval report saved to: {md_path}")
    print(f"📊 Eval data saved to:   {json_path}")
    return md_path
