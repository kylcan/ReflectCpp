from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    cases: int = 0
    exact_matches: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def fp_rate(self) -> float:
        return self.fp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def exact_match_rate(self) -> float:
        return (self.exact_matches / self.cases) if self.cases else 0.0


def per_case_prf1(predicted: set[str], expected: set[str]) -> tuple[float, float, float, bool]:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    exact = predicted == expected
    return precision, recall, f1, exact


@dataclass(frozen=True)
class RunSummary:
    micro: Metrics
    macro_precision: float
    macro_recall: float
    macro_f1: float


@dataclass(frozen=True)
class RepeatedSummary:
    mean_micro_f1: float
    std_micro_f1: float
    mean_macro_f1: float
    std_macro_f1: float


def summarize_runs(runs: list[RunSummary]) -> RepeatedSummary:
    micro_f1s = [r.micro.f1 for r in runs]
    macro_f1s = [r.macro_f1 for r in runs]
    return RepeatedSummary(
        mean_micro_f1=mean(micro_f1s) if micro_f1s else 0.0,
        std_micro_f1=pstdev(micro_f1s) if len(micro_f1s) > 1 else 0.0,
        mean_macro_f1=mean(macro_f1s) if macro_f1s else 0.0,
        std_macro_f1=pstdev(macro_f1s) if len(macro_f1s) > 1 else 0.0,
    )
