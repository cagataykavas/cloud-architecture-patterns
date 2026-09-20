from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from math import isfinite


@dataclass(frozen=True)
class BurnRatePolicy:
    objective: float = 0.999
    fast_burn_threshold: float = 14.4
    slow_burn_threshold: float = 6.0
    min_requests_per_window: int = 100

    def __post_init__(self) -> None:
        if not 0 < self.objective < 1:
            raise ValueError("objective must be in (0, 1)")
        if self.fast_burn_threshold <= 0 or self.slow_burn_threshold <= 0:
            raise ValueError("burn-rate thresholds must be positive")
        if self.min_requests_per_window < 1:
            raise ValueError("min_requests_per_window must be positive")


@dataclass(frozen=True)
class SLIWindow:
    name: str
    requests: int
    failures: int

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("window name must not be empty")
        if self.requests < 0 or self.failures < 0 or self.failures > self.requests:
            raise ValueError("window counts must satisfy 0 <= failures <= requests")


@dataclass(frozen=True)
class WindowEvidence:
    name: str
    requests: int
    failures: int
    error_rate: float
    burn_rate: float
    sufficient_traffic: bool


@dataclass(frozen=True)
class BurnRateDecision:
    alert: bool
    reasons: tuple[str, ...]
    evidence: tuple[WindowEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "alert": self.alert,
            "reasons": list(self.reasons),
            "evidence": [asdict(item) for item in self.evidence],
        }


def evaluate_burn_rate(
    windows: Sequence[SLIWindow],
    *,
    fast_window: str,
    slow_window: str,
    policy: BurnRatePolicy | None = None,
) -> BurnRateDecision:
    """Evaluate a paired fast/slow SLO burn-rate alert.

    Both windows must exceed their threshold. This reduces alerts caused by a short
    isolated spike while still detecting sustained error-budget consumption.
    """
    active_policy = policy or BurnRatePolicy()
    if not windows:
        raise ValueError("at least one SLI window is required")
    by_name = {window.name: window for window in windows}
    if len(by_name) != len(windows):
        raise ValueError("window names must be unique")
    if fast_window == slow_window or fast_window not in by_name or slow_window not in by_name:
        raise ValueError("fast and slow windows must be distinct and present")

    budget = 1 - active_policy.objective
    evidence: list[WindowEvidence] = []
    for window in sorted(windows, key=lambda item: item.name):
        error_rate = window.failures / window.requests if window.requests else 0.0
        burn_rate = error_rate / budget
        if not isfinite(burn_rate):
            raise ValueError("calculated burn rate must be finite")
        evidence.append(
            WindowEvidence(
                name=window.name,
                requests=window.requests,
                failures=window.failures,
                error_rate=error_rate,
                burn_rate=burn_rate,
                sufficient_traffic=window.requests >= active_policy.min_requests_per_window,
            )
        )

    indexed = {item.name: item for item in evidence}
    fast = indexed[fast_window]
    slow = indexed[slow_window]
    reasons: list[str] = []
    if not fast.sufficient_traffic:
        reasons.append(f"insufficient_traffic:{fast_window}")
    if not slow.sufficient_traffic:
        reasons.append(f"insufficient_traffic:{slow_window}")

    paired_breach = (
        fast.sufficient_traffic
        and slow.sufficient_traffic
        and fast.burn_rate >= active_policy.fast_burn_threshold
        and slow.burn_rate >= active_policy.slow_burn_threshold
    )
    if paired_breach:
        reasons.append("paired_burn_rate_exceeded")
    return BurnRateDecision(alert=bool(reasons), reasons=tuple(reasons), evidence=tuple(evidence))
