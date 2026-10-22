from __future__ import annotations

import json
import math
from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .slo_burn_rate import SLIWindow

MAX_WINDOWS = 32
MAX_LABELS = 16
MAX_LABEL_BYTES = 128
MAX_COUNT = 9_007_199_254_740_991


class PrometheusAdapterError(ValueError):
    """Prometheus evidence is malformed, stale, incomplete, or inconsistent."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise PrometheusAdapterError("Prometheus JSON contains a duplicate key")
        output[key] = value
    return output


def _reject_constant(value: str) -> None:
    raise PrometheusAdapterError(f"Prometheus JSON contains invalid constant {value}")


def _decode(payload: bytes | str, maximum_bytes: int) -> dict[str, Any]:
    try:
        if isinstance(payload, str):
            encoded = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            encoded = payload
        else:
            raise PrometheusAdapterError("Prometheus payload must be UTF-8 JSON")
        text = encoded.decode("utf-8")
    except UnicodeError as exc:
        raise PrometheusAdapterError("Prometheus payload is not valid UTF-8 JSON") from exc
    if not encoded or len(encoded) > maximum_bytes:
        raise PrometheusAdapterError("Prometheus payload violates the byte budget")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrometheusAdapterError("Prometheus payload is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise PrometheusAdapterError("Prometheus response must be an object")
    return document


def _count(value: object) -> int:
    if not isinstance(value, str):
        raise PrometheusAdapterError("Prometheus sample value must be a string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise PrometheusAdapterError("Prometheus counter must be numeric") from exc
    if not parsed.is_finite() or parsed != parsed.to_integral_value():
        raise PrometheusAdapterError("Prometheus counter must be a finite integer")
    if not 0 <= parsed <= MAX_COUNT:
        raise PrometheusAdapterError("Prometheus counter is outside the supported range")
    return int(parsed)


def _timestamp(value: object, *, now: float, max_age: float, max_future_skew: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrometheusAdapterError("Prometheus sample timestamp must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise PrometheusAdapterError("Prometheus sample timestamp must be finite")
    if result > now + max_future_skew:
        raise PrometheusAdapterError("Prometheus sample is too far in the future")
    if result < now - max_age:
        raise PrometheusAdapterError("Prometheus sample is stale")
    return result


def _vector(
    payload: bytes | str,
    *,
    expected_windows: frozenset[str],
    now: float,
    max_age: float,
    max_future_skew: float,
    maximum_bytes: int,
) -> dict[str, tuple[int, float]]:
    document = _decode(payload, maximum_bytes)
    if document.get("status") != "success":
        raise PrometheusAdapterError("Prometheus query did not succeed")
    data = document.get("data")
    if not isinstance(data, dict) or data.get("resultType") != "vector":
        raise PrometheusAdapterError("Prometheus query must return an instant vector")
    result = data.get("result")
    if not isinstance(result, list) or len(result) > MAX_WINDOWS:
        raise PrometheusAdapterError("Prometheus result violates the window budget")

    samples: dict[str, tuple[int, float]] = {}
    for item in result:
        if not isinstance(item, dict):
            raise PrometheusAdapterError("Prometheus vector sample must be an object")
        metric = item.get("metric")
        value = item.get("value")
        if not isinstance(metric, dict) or not 1 <= len(metric) <= MAX_LABELS:
            raise PrometheusAdapterError("Prometheus metric labels violate the label budget")
        for label_name, label_value in metric.items():
            if (
                not isinstance(label_name, str)
                or not isinstance(label_value, str)
                or not label_name
                or len(label_name.encode("utf-8")) > MAX_LABEL_BYTES
                or len(label_value.encode("utf-8")) > MAX_LABEL_BYTES
            ):
                raise PrometheusAdapterError("Prometheus metric labels must be bounded strings")
        window = metric.get("window")
        if window not in expected_windows:
            raise PrometheusAdapterError("Prometheus result contains an unexpected window")
        if window in samples:
            raise PrometheusAdapterError("Prometheus result contains a duplicate window")
        if not isinstance(value, list) or len(value) != 2:
            raise PrometheusAdapterError("Prometheus sample must contain timestamp and value")
        samples[window] = (
            _count(value[1]),
            _timestamp(
                value[0],
                now=now,
                max_age=max_age,
                max_future_skew=max_future_skew,
            ),
        )
    if samples.keys() != expected_windows:
        raise PrometheusAdapterError("Prometheus result is missing an expected window")
    return samples


def windows_from_prometheus(
    requests_payload: bytes | str,
    failures_payload: bytes | str,
    *,
    expected_windows: Sequence[str],
    observed_at: datetime,
    max_age_seconds: float = 120.0,
    max_future_skew_seconds: float = 5.0,
    max_pair_skew_seconds: float = 5.0,
    max_payload_bytes: int = 256 * 1024,
) -> tuple[SLIWindow, ...]:
    """Convert paired Prometheus instant vectors into validated SLI windows."""

    if (
        not isinstance(observed_at, datetime)
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise PrometheusAdapterError("observed_at must be timezone-aware")
    if isinstance(expected_windows, (str, bytes)):
        raise PrometheusAdapterError("expected windows violate the window budget")
    windows = tuple(expected_windows)
    if not 1 <= len(windows) <= MAX_WINDOWS or any(
        not isinstance(name, str) or not name.strip() or len(name.encode("utf-8")) > MAX_LABEL_BYTES
        for name in windows
    ):
        raise PrometheusAdapterError("expected windows violate the window budget")
    expected = frozenset(windows)
    if len(expected) != len(windows):
        raise PrometheusAdapterError("expected window names must be unique")
    for name, value, allow_zero in (
        ("max_age_seconds", max_age_seconds, False),
        ("max_future_skew_seconds", max_future_skew_seconds, True),
        ("max_pair_skew_seconds", max_pair_skew_seconds, True),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or (not allow_zero and value == 0)
        ):
            raise PrometheusAdapterError(f"{name} has an invalid value")
    if type(max_payload_bytes) is not int or not 1 <= max_payload_bytes <= 4 * 1024 * 1024:
        raise PrometheusAdapterError("max_payload_bytes has an invalid value")

    now = observed_at.timestamp()
    request_samples = _vector(
        requests_payload,
        expected_windows=expected,
        now=now,
        max_age=float(max_age_seconds),
        max_future_skew=float(max_future_skew_seconds),
        maximum_bytes=max_payload_bytes,
    )
    failure_samples = _vector(
        failures_payload,
        expected_windows=expected,
        now=now,
        max_age=float(max_age_seconds),
        max_future_skew=float(max_future_skew_seconds),
        maximum_bytes=max_payload_bytes,
    )

    output: list[SLIWindow] = []
    for window in sorted(expected):
        requests, request_time = request_samples[window]
        failures, failure_time = failure_samples[window]
        if abs(request_time - failure_time) > max_pair_skew_seconds:
            raise PrometheusAdapterError("paired Prometheus samples exceed the skew budget")
        output.append(SLIWindow(window, requests, failures))
    return tuple(output)
