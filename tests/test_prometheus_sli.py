from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from cloud_patterns.prometheus_sli import PrometheusAdapterError, windows_from_prometheus
from cloud_patterns.slo_burn_rate import BurnRatePolicy, evaluate_burn_rate

NOW = datetime(2026, 10, 22, 3, 30, tzinfo=UTC)
WINDOWS = ("5m", "1h")


def _payload(values, *, timestamp=None):
    sample_time = NOW.timestamp() - 10 if timestamp is None else timestamp
    return json.dumps(
        {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"window": window, "service": "checkout"},
                        "value": [sample_time, str(value)],
                    }
                    for window, value in values
                ],
            },
        }
    )


def test_adapts_prometheus_vectors_into_existing_burn_rate_gate():
    windows = windows_from_prometheus(
        _payload([("5m", 1_000), ("1h", 10_000)]),
        _payload([("5m", 120), ("1h", 600)]),
        expected_windows=WINDOWS,
        observed_at=NOW,
    )
    decision = evaluate_burn_rate(
        windows,
        fast_window="5m",
        slow_window="1h",
        policy=BurnRatePolicy(
            objective=0.99,
            fast_burn_threshold=10,
            slow_burn_threshold=5,
            min_requests_per_window=100,
        ),
    )

    assert [(item.name, item.requests, item.failures) for item in windows] == [
        ("1h", 10_000, 600),
        ("5m", 1_000, 120),
    ]
    assert decision.alert
    assert decision.reasons == ("paired_burn_rate_exceeded",)


def test_semantically_identical_vector_order_is_deterministic():
    first = windows_from_prometheus(
        _payload([("5m", 100), ("1h", 1_000)]),
        _payload([("5m", 2), ("1h", 10)]),
        expected_windows=WINDOWS,
        observed_at=NOW,
    )
    second = windows_from_prometheus(
        _payload([("1h", 1_000), ("5m", 100)]),
        _payload([("1h", 10), ("5m", 2)]),
        expected_windows=tuple(reversed(WINDOWS)),
        observed_at=NOW,
    )

    assert first == second


@pytest.mark.parametrize(
    ("requests", "failures", "match"),
    [
        (["5m", "5m"], ["5m", "1h"], "duplicate window"),
        (["5m"], ["5m", "1h"], "missing an expected window"),
        (["5m", "1h", "6h"], ["5m", "1h"], "unexpected window"),
    ],
)
def test_rejects_duplicate_missing_and_unexpected_windows(requests, failures, match):
    with pytest.raises(PrometheusAdapterError, match=match):
        windows_from_prometheus(
            _payload([(name, 100) for name in requests]),
            _payload([(name, 1) for name in failures]),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("NaN", "finite integer"),
        ("1.5", "finite integer"),
        ("-1", "supported range"),
        ("9007199254740992", "supported range"),
        ("1e1000000000", "supported range"),
    ],
)
def test_rejects_unsafe_counter_values(value, match):
    with pytest.raises(PrometheusAdapterError, match=match):
        windows_from_prometheus(
            _payload([("5m", value), ("1h", 100)]),
            _payload([("5m", 1), ("1h", 1)]),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )


def test_rejects_stale_future_and_skewed_samples():
    with pytest.raises(PrometheusAdapterError, match="stale"):
        windows_from_prometheus(
            _payload([("5m", 100), ("1h", 100)], timestamp=NOW.timestamp() - 121),
            _payload([("5m", 1), ("1h", 1)]),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )
    with pytest.raises(PrometheusAdapterError, match="future"):
        windows_from_prometheus(
            _payload([("5m", 100), ("1h", 100)], timestamp=NOW.timestamp() + 6),
            _payload([("5m", 1), ("1h", 1)]),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )
    with pytest.raises(PrometheusAdapterError, match="skew budget"):
        windows_from_prometheus(
            _payload([("5m", 100), ("1h", 100)], timestamp=NOW.timestamp() - 10),
            _payload([("5m", 1), ("1h", 1)], timestamp=NOW.timestamp() - 20),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )


def test_rejects_failure_count_above_request_count():
    with pytest.raises(ValueError, match="failures <= requests"):
        windows_from_prometheus(
            _payload([("5m", 100), ("1h", 100)]),
            _payload([("5m", 101), ("1h", 1)]),
            expected_windows=WINDOWS,
            observed_at=NOW,
        )


def test_rejects_duplicate_json_non_vector_and_failed_query():
    duplicate = '{"status":"success","status":"success","data":{}}'
    non_vector = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": []}})
    failed = json.dumps({"status": "error", "error": "private backend detail"})
    valid = _payload([("5m", 1), ("1h", 1)])

    for payload, match in (
        (duplicate, "duplicate key"),
        (non_vector, "instant vector"),
        (failed, "did not succeed"),
    ):
        with pytest.raises(PrometheusAdapterError, match=match):
            windows_from_prometheus(
                payload,
                valid,
                expected_windows=WINDOWS,
                observed_at=NOW,
            )


def test_rejects_oversized_payload_and_invalid_configuration():
    valid = _payload([("5m", 1), ("1h", 1)])
    with pytest.raises(PrometheusAdapterError, match="byte budget"):
        windows_from_prometheus(
            valid + " ",
            valid,
            expected_windows=WINDOWS,
            observed_at=NOW,
            max_payload_bytes=len(valid),
        )
    with pytest.raises(PrometheusAdapterError, match="timezone-aware"):
        windows_from_prometheus(
            valid,
            valid,
            expected_windows=WINDOWS,
            observed_at=datetime(2026, 10, 22),
        )
    with pytest.raises(PrometheusAdapterError, match="must be unique"):
        windows_from_prometheus(
            valid,
            valid,
            expected_windows=("5m", "5m"),
            observed_at=NOW,
        )
    with pytest.raises(PrometheusAdapterError, match="window budget"):
        windows_from_prometheus(
            valid,
            valid,
            expected_windows="5m",
            observed_at=NOW,
        )


def test_rejects_non_utf8_json_instead_of_autodetecting_it():
    utf16 = _payload([("5m", 1), ("1h", 1)]).encode("utf-16")

    with pytest.raises(PrometheusAdapterError, match="UTF-8"):
        windows_from_prometheus(
            utf16,
            utf16,
            expected_windows=WINDOWS,
            observed_at=NOW,
        )
