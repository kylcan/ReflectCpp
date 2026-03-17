from __future__ import annotations

import argparse
import json
import random
import shutil
from dataclasses import dataclass
from pathlib import Path


_C_EXTS = {".c", ".cc", ".cpp", ".cxx"}
SUPPORTED_CWES: tuple[str, ...] = ("CWE-121", "CWE-78", "CWE-416")


@dataclass(frozen=True)
class Candidate:
    cwe_id: str
    path: Path
    expected_vulnerable: bool


def _cwe_dir_prefix(cwe_id: str) -> str:
    # "CWE-121" -> "CWE121_"
    return f"CWE{cwe_id.split('-')[-1]}_"


def _label_expected_from_name(file_path: Path) -> bool | None:
    name = file_path.stem.lower()
    has_good = "good" in name
    has_bad = "bad" in name

    # Prefer unambiguous cases
    if has_good and not has_bad:
        return False
    if has_bad and not has_good:
        return True

    # Common Juliet patterns like *_goodG2B* or *_badSink*
    if name.startswith("good") and not has_bad:
        return False
    if name.startswith("bad") and not has_good:
        return True

    return None


def find_candidates(juliet_root: Path, cwe_id: str) -> list[Candidate]:
    prefix = _cwe_dir_prefix(cwe_id)

    candidates: list[Candidate] = []
    # Search for any testcase directory matching the CWE prefix.
    for d in sorted([p for p in juliet_root.rglob(f"{prefix}*") if p.is_dir()]):
        for fp in sorted(d.rglob("*")):
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in _C_EXTS:
                continue
            expected = _label_expected_from_name(fp)
            if expected is None:
                continue
            candidates.append(Candidate(cwe_id=cwe_id, path=fp, expected_vulnerable=expected))

    return candidates


def _write_metadata(
    sample_dir: Path,
    *,
    sample_id: str,
    cwe_id: str,
    expected_vulnerable: bool,
    source_files: list[str],
    juliet_source: str,
) -> None:
    meta = {
        "id": sample_id,
        "cwe_id": cwe_id,
        "expected_vulnerable": expected_vulnerable,
        "source_files": source_files,
        "juliet_source": juliet_source,
    }
    (sample_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def build_subset(
    *,
    juliet_root: Path,
    out_dir: Path,
    per_cwe: int = 20,
    seed: int = 7,
    overwrite: bool = False,
) -> dict:
    if not juliet_root.exists():
        raise FileNotFoundError(f"juliet_root not found: {juliet_root}")

    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)

    created: list[dict] = []
    for cwe_id in SUPPORTED_CWES:
        candidates = find_candidates(juliet_root, cwe_id)
        good = [c for c in candidates if not c.expected_vulnerable]
        bad = [c for c in candidates if c.expected_vulnerable]

        # Aim for a 50/50 split when possible.
        want_bad = per_cwe // 2
        want_good = per_cwe - want_bad

        rng.shuffle(good)
        rng.shuffle(bad)

        selected = bad[:want_bad] + good[:want_good]
        # If one side is short, fill from the other.
        if len(selected) < per_cwe:
            remaining = [c for c in (bad + good) if c not in selected]
            rng.shuffle(remaining)
            selected.extend(remaining[: (per_cwe - len(selected))])

        for idx, cand in enumerate(selected, start=1):
            tag = "bad" if cand.expected_vulnerable else "good"
            sample_id = f"{cwe_id}_{tag}_{idx:03d}"
            sample_dir = out_dir / sample_id

            if sample_dir.exists():
                if overwrite:
                    shutil.rmtree(sample_dir)
                else:
                    continue

            sample_dir.mkdir(parents=True, exist_ok=True)
            dest_name = cand.path.name
            shutil.copy2(cand.path, sample_dir / dest_name)

            _write_metadata(
                sample_dir,
                sample_id=sample_id,
                cwe_id=cand.cwe_id,
                expected_vulnerable=cand.expected_vulnerable,
                source_files=[dest_name],
                juliet_source=str(cand.path),
            )

            created.append(
                {
                    "id": sample_id,
                    "cwe_id": cand.cwe_id,
                    "expected_vulnerable": cand.expected_vulnerable,
                    "source": str(cand.path),
                }
            )

    manifest = {
        "juliet_root": str(juliet_root),
        "out_dir": str(out_dir),
        "seed": seed,
        "per_cwe": per_cwe,
        "total_created": len(created),
        "samples": created,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description="Build a local Juliet subset (no vendoring)")
    p.add_argument("--juliet-root", type=str, required=True, help="Path to Juliet C/C++ test suite root")
    p.add_argument("--out-dir", type=str, default="eval/juliet_subset/samples", help="Output directory")
    p.add_argument("--per-cwe", type=int, default=20, help="Number of samples per CWE (default 20 => ~60 total)")
    p.add_argument("--seed", type=int, default=7, help="Random seed")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing samples")
    args = p.parse_args()

    manifest = build_subset(
        juliet_root=Path(args.juliet_root).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        per_cwe=max(int(args.per_cwe), 1),
        seed=int(args.seed),
        overwrite=bool(args.overwrite),
    )

    print(json.dumps({k: v for k, v in manifest.items() if k != "samples"}, indent=2))
    print(f"Wrote: {Path(manifest['out_dir']) / 'manifest.json'}")


if __name__ == "__main__":
    main()
