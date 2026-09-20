import pytest

from cloud_patterns.slo_burn_rate import BurnRatePolicy, SLIWindow, evaluate_burn_rate

POLICY = BurnRatePolicy(
    objective=0.99,
    fast_burn_threshold=10.0,
    slow_burn_threshold=5.0,
    min_requests_per_window=100,
)


def test_sustained_fast_and_slow_burn_alerts():
    decision = evaluate_burn_rate(
        [SLIWindow("5m", 1000, 120), SLIWindow("1h", 10000, 600)],
        fast_window="5m",
        slow_window="1h",
        policy=POLICY,
    )

    assert decision.alert
    assert decision.reasons == ("paired_burn_rate_exceeded",)
    assert decision.to_dict()["evidence"][0]["name"] == "1h"


def test_short_spike_without_slow_burn_does_not_alert():
    decision = evaluate_burn_rate(
        [SLIWindow("5m", 1000, 120), SLIWindow("1h", 10000, 100)],
        fast_window="5m",
        slow_window="1h",
        policy=POLICY,
    )

    assert not decision.alert
    assert decision.reasons == ()


def test_low_traffic_is_explicit_and_fail_closed():
    decision = evaluate_burn_rate(
        [SLIWindow("5m", 20, 0), SLIWindow("1h", 80, 0)],
        fast_window="5m",
        slow_window="1h",
        policy=POLICY,
    )

    assert decision.alert
    assert decision.reasons == ("insufficient_traffic:5m", "insufficient_traffic:1h")


def test_zero_request_window_is_safe_and_insufficient():
    decision = evaluate_burn_rate(
        [SLIWindow("5m", 0, 0), SLIWindow("1h", 1000, 0)],
        fast_window="5m",
        slow_window="1h",
        policy=POLICY,
    )
    assert decision.alert
    assert decision.evidence[1].burn_rate == 0.0


@pytest.mark.parametrize(("requests", "failures"), [(-1, 0), (1, -1), (1, 2)])
def test_invalid_window_counts_are_rejected(requests, failures):
    with pytest.raises(ValueError, match="0 <= failures <= requests"):
        SLIWindow("bad", requests, failures)


def test_duplicate_or_missing_window_names_are_rejected():
    duplicate = [SLIWindow("5m", 100, 1), SLIWindow("5m", 100, 1)]
    with pytest.raises(ValueError, match="unique"):
        evaluate_burn_rate(duplicate, fast_window="5m", slow_window="1h", policy=POLICY)

    with pytest.raises(ValueError, match="distinct and present"):
        evaluate_burn_rate(
            [SLIWindow("5m", 100, 1), SLIWindow("1h", 100, 1)],
            fast_window="5m",
            slow_window="missing",
            policy=POLICY,
        )
