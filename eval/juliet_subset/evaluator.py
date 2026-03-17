from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel_agent.graph import run_agent
from sentinel_agent.tools.cppcheck import CppcheckTool


SUPPORTED_CWES: set[str] = {"CWE-121", "CWE-78", "CWE-416"}

# Normalize near-equivalents that show up in tool outputs.
_CWE_NORMALIZATION = {
    "CWE-120": "CWE-121",  # classic buffer overflow -> stack-based buffer overflow bucket
}


def _normalize_cwe(cwe_id: str) -> str:
    cwe = (cwe_id or "").strip().upper()
    if not cwe:
        return ""
    if not cwe.startswith("CWE-") and cwe.startswith("CWE") and cwe[3:].isdigit():
        cwe = f"CWE-{cwe[3:]}"
    return _CWE_NORMALIZATION.get(cwe, cwe)


def _load_metadata(sample_dir: Path) -> dict[str, Any]:
    meta_path = sample_dir / "metadata.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"Missing metadata.json in {sample_dir}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def run_agent_on_sample(sample_dir: Path, *, max_iterations: int = 2) -> dict[str, Any]:
    return run_agent(str(sample_dir), max_iterations=max_iterations)


def extract_detected_vulnerabilities(agent_result: dict[str, Any]) -> set[str]:
    vulns = agent_result.get("vulnerabilities", []) or []
    confirmed = [v for v in vulns if (v.get("status") or "").strip() == "Confirmed"]

    out: set[str] = set()
    for v in confirmed:
        cwe = _normalize_cwe((v.get("cwe_id") or "").strip())
        if cwe:
            out.add(cwe)
    return out


def _cppcheck_findings_to_cwes(payload: dict[str, Any]) -> set[str]:
    cwes: set[str] = set()
    for f in payload.get("findings", []) or []:
        msg = (f.get("message") or "").lower()
        if not msg:
            continue

        # CWE-78
        if "system()" in msg or "command execution" in msg or "command" in msg and "system" in msg:
            cwes.add("CWE-78")

        # CWE-121 (buffer overflow-ish)
        if "buffer overflow" in msg or "strcpy" in msg or "memcpy" in msg:
            cwes.add("CWE-121")

        # CWE-416
        if "use after free" in msg or "use-after-free" in msg or "use-after" in msg and "free" in msg:
            cwes.add("CWE-416")

    return {_normalize_cwe(c) for c in cwes if c}


def baseline_cppcheck_only(sample_dir: Path) -> set[str]:
    raw = CppcheckTool().execute(file_path=str(sample_dir))
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        payload = {}
    return _cppcheck_findings_to_cwes(payload)


@dataclass
class BinaryMetrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return float(self.tp) / float(denom) if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return float(self.fp) / float(denom) if denom else 0.0


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    m = BinaryMetrics()

    for r in rows:
        expected = bool(r["expected_vulnerable"])
        predicted = bool(r["predicted_vulnerable"])

        if expected and predicted:
            m.tp += 1
        elif expected and not predicted:
            m.fn += 1
        elif not expected and predicted:
            m.fp += 1
        else:
            m.tn += 1

    return {
        "tp": m.tp,
        "fp": m.fp,
        "tn": m.tn,
        "fn": m.fn,
        "recall": m.recall,
        "fpr": m.fpr,
    }


def _iter_samples(samples_dir: Path) -> list[Path]:
    if not samples_dir.exists():
        return []
    samples = [p for p in samples_dir.iterdir() if p.is_dir() and (p / "metadata.json").exists()]
    return sorted(samples)


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate SentinelAgent on a locally-built Juliet subset")
    p.add_argument("--samples-dir", type=str, default="eval/juliet_subset/samples", help="Directory containing sample subfolders")
    p.add_argument("--limit", type=int, default=0, help="Limit number of samples (0 = all)")
    p.add_argument("--max-iterations", type=int, default=2, help="Agent max iterations")
    p.add_argument("--no-baseline", action="store_true", help="Skip cppcheck-only baseline")
    p.add_argument("--offline", action="store_true", help="Force offline deterministic mode (sets SENTINEL_OFFLINE=1)")
    args = p.parse_args()

    if args.offline:
        os.environ["SENTINEL_OFFLINE"] = "1"

    samples_dir = Path(args.samples_dir).expanduser().resolve()
    sample_dirs = _iter_samples(samples_dir)
    if args.limit and args.limit > 0:
        sample_dirs = sample_dirs[: args.limit]

    if not sample_dirs:
        raise SystemExit(
            "No samples found. Build them first via: python -m eval.juliet_subset.builder --juliet-root /path/to/Juliet"
        )

    agent_rows: list[dict[str, Any]] = []
    baseline_rows: list[dict[str, Any]] = []

    for sd in sample_dirs:
        meta = _load_metadata(sd)
        sample_id = meta.get("id") or sd.name
        cwe_id = _normalize_cwe(str(meta.get("cwe_id") or ""))
        expected_vuln = bool(meta.get("expected_vulnerable"))

        if cwe_id not in SUPPORTED_CWES:
            # Keep the evaluator strict so metrics remain interpretable.
            continue

        agent_result = run_agent_on_sample(sd, max_iterations=int(args.max_iterations))
        agent_cwes = extract_detected_vulnerabilities(agent_result)
        agent_pred = cwe_id in agent_cwes

        agent_rows.append(
            {
                "id": sample_id,
                "cwe_id": cwe_id,
                "expected_vulnerable": expected_vuln,
                "predicted_vulnerable": agent_pred,
                "predicted_cwes": sorted(agent_cwes),
            }
        )

        if not args.no_baseline:
            base_cwes = baseline_cppcheck_only(sd)
            base_pred = cwe_id in base_cwes
            baseline_rows.append(
                {
                    "id": sample_id,
                    "cwe_id": cwe_id,
                    "expected_vulnerable": expected_vuln,
                    "predicted_vulnerable": base_pred,
                    "predicted_cwes": sorted(base_cwes),
                }
            )

    summary: dict[str, Any] = {
        "samples": len(agent_rows),
        "cwes": sorted(SUPPORTED_CWES),
        "agent": compute_metrics(agent_rows),
    }

    if baseline_rows:
        summary["baseline_cppcheck_only"] = compute_metrics(baseline_rows)
        summary["delta_agent_minus_baseline"] = {
            "recall": summary["agent"]["recall"] - summary["baseline_cppcheck_only"]["recall"],
            "fpr": summary["agent"]["fpr"] - summary["baseline_cppcheck_only"]["fpr"],
        }

    out_path = samples_dir.parent / "juliet_subset_results.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
