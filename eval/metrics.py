"""
eval/metrics.py – Precision, Recall, FPR and per-file scoring utilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FileResult:
    """Audit outcome for a single test-case file."""
    filename: str
    expected_cwe_ids: list[str]      # from ground truth
    predicted_cwe_ids: list[str]     # from audit (Confirmed only)
    all_predicted_cwe_ids: list[str] # including Rejected
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    latency_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class EvalMetrics:
    """Aggregated metrics across all test cases."""
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    total_tp: int = 0
    total_fp: int = 0
    total_fn: int = 0
    total_tn: int = 0
    avg_latency_s: float = 0.0
    avg_prompt_tokens: float = 0.0
    avg_completion_tokens: float = 0.0
    file_results: list[FileResult] = field(default_factory=list)


def _normalize_cwe(cwe_str: str) -> str:
    """Extract a canonical CWE-NNN form from varied input strings."""
    import re
    match = re.search(r"CWE-?\d+", cwe_str, re.IGNORECASE)
    if match:
        raw = match.group(0).upper().replace("CWE", "CWE-")
        # Normalize double dashes
        return raw.replace("CWE--", "CWE-")
    return cwe_str.upper()


def score_file(
    filename: str,
    expected_cwe_ids: list[str],
    predicted_vulns: list[dict[str, Any]],
    latency_s: float = 0.0,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
) -> FileResult:
    """Score a single file's predictions against ground truth.

    Matching strategy: CWE-id level (not line-level) to be lenient with
    LLM location hallucinations while still measuring real detection ability.
    """
    confirmed = [
        v for v in predicted_vulns
        if v.get("status") == "Confirmed"
    ]

    pred_cwes = set()
    for v in confirmed:
        cwe = v.get("cwe_id") or ""
        if not cwe:
            # Try to extract from vuln_type
            cwe = v.get("vuln_type", "")
        pred_cwes.add(_normalize_cwe(cwe))

    all_pred_cwes = set()
    for v in predicted_vulns:
        cwe = v.get("cwe_id") or v.get("vuln_type", "")
        all_pred_cwes.add(_normalize_cwe(cwe))

    expected_set = {_normalize_cwe(c) for c in expected_cwe_ids}

    tp = len(pred_cwes & expected_set)
    fp = len(pred_cwes - expected_set)
    fn = len(expected_set - pred_cwes)
    # TN: file expected no vulns AND none were confirmed
    tn = 1 if (not expected_set and not pred_cwes) else 0

    return FileResult(
        filename=filename,
        expected_cwe_ids=sorted(expected_set),
        predicted_cwe_ids=sorted(pred_cwes),
        all_predicted_cwe_ids=sorted(all_pred_cwes),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        latency_s=latency_s,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def aggregate(file_results: list[FileResult]) -> EvalMetrics:
    """Compute aggregate metrics from per-file results."""
    total_tp = sum(r.true_positives for r in file_results)
    total_fp = sum(r.false_positives for r in file_results)
    total_fn = sum(r.false_negatives for r in file_results)
    total_tn = sum(r.true_negatives for r in file_results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) else 0.0

    n = len(file_results) or 1
    avg_lat = sum(r.latency_s for r in file_results) / n
    avg_pt = sum(r.prompt_tokens for r in file_results) / n
    avg_ct = sum(r.completion_tokens for r in file_results) / n

    return EvalMetrics(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        total_tp=total_tp,
        total_fp=total_fp,
        total_fn=total_fn,
        total_tn=total_tn,
        avg_latency_s=round(avg_lat, 3),
        avg_prompt_tokens=round(avg_pt, 1),
        avg_completion_tokens=round(avg_ct, 1),
        file_results=file_results,
    )
