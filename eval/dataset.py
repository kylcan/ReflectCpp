"""
eval/dataset.py – Load test cases and their ground-truth labels.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class GroundTruthVuln:
    """A single expected vulnerability from labels.json."""
    cwe_id: str
    line: int
    function: str
    description: str = ""


@dataclass
class TestCase:
    """One evaluation sample: source file + expected vulnerabilities."""
    filename: str
    source_code: str
    file_path: str
    expected_vulns: list[GroundTruthVuln] = field(default_factory=list)

    @property
    def has_vulns(self) -> bool:
        return len(self.expected_vulns) > 0


def load_dataset(testcases_dir: str | Path | None = None) -> list[TestCase]:
    """Load all test cases from *testcases_dir*.

    Parameters
    ----------
    testcases_dir : path-like, optional
        Defaults to ``eval/testcases/`` relative to this file.

    Returns
    -------
    list[TestCase]
    """
    if testcases_dir is None:
        testcases_dir = Path(__file__).parent / "testcases"
    testcases_dir = Path(testcases_dir)

    labels_path = testcases_dir / "labels.json"
    if not labels_path.exists():
        raise FileNotFoundError(f"labels.json not found at {labels_path}")

    with open(labels_path, encoding="utf-8") as f:
        labels: dict = json.load(f)

    cases: list[TestCase] = []
    for filename, meta in sorted(labels.items()):
        cpp_path = testcases_dir / filename
        if not cpp_path.exists():
            continue
        source = cpp_path.read_text(encoding="utf-8")
        expected = [
            GroundTruthVuln(
                cwe_id=v["cwe_id"],
                line=v["line"],
                function=v["function"],
                description=v.get("description", ""),
            )
            for v in meta.get("vulnerabilities", [])
        ]
        cases.append(
            TestCase(
                filename=filename,
                source_code=source,
                file_path=str(cpp_path.resolve()),
                expected_vulns=expected,
            )
        )

    return cases
