"""Fail-closed cross-region failover readiness audit.

The evaluator deliberately consumes a compact evidence manifest rather than cloud
credentials. Collection is provider-specific; policy and evidence semantics are not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 256 * 1024
MAX_COMPONENTS = 512
MAX_DEPENDENCIES_PER_COMPONENT = 64
MAX_TOTAL_DEPENDENCIES = 4096
MAX_IDENTIFIER_LENGTH = 128
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
RECOVERY_MODES = frozenset(
    {"active_active", "hot_standby", "warm_standby", "backup_restore", "unavailable"}
)
TIERS = frozenset({"critical", "important", "supporting"})


class EvidenceError(ValueError):
    """The evidence artifact is malformed or exceeds a resource budget."""


@dataclass(frozen=True)
class Policy:
    minimum_capacity_ratio: float = 0.8
    max_rehearsal_age_days: int = 30
    max_future_skew_seconds: int = 300
    require_important_dependency_closure: bool = True

    def __post_init__(self) -> None:
        if not 0 < self.minimum_capacity_ratio <= 1:
            raise EvidenceError("minimum_capacity_ratio must be in (0, 1]")
        if not 1 <= self.max_rehearsal_age_days <= 365:
            raise EvidenceError("max_rehearsal_age_days must be in [1, 365]")
        if not 0 <= self.max_future_skew_seconds <= 3600:
            raise EvidenceError("max_future_skew_seconds must be in [0, 3600]")


@dataclass(frozen=True)
class Component:
    name: str
    tier: str
    recovery_mode: str
    dependencies: tuple[str, ...]
    recovery_order: int
    target_rto_seconds: float
    measured_rto_seconds: float
    target_rpo_seconds: float
    measured_rpo_seconds: float
    required_capacity: float
    recovery_capacity: float
    validation_passed: bool


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceError("unable to read evidence") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise EvidenceError("evidence exceeds byte budget")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvidenceError(f"non-finite number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError("evidence root must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing or extra:
        raise EvidenceError(f"{field} keys do not match the schema")


def _identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_IDENTIFIER_LENGTH
        or not IDENTIFIER.fullmatch(value)
    ):
        raise EvidenceError(f"{field} is not a valid identifier")
    return value


def _number(value: Any, field: str, *, positive: bool = False) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise EvidenceError(f"{field} must be finite numeric evidence")
    result = float(value)
    if result < 0 or (positive and result <= 0) or result > 1_000_000_000:
        raise EvidenceError(f"{field} is outside its allowed range")
    return result


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > 1_000_000
    ):
        raise EvidenceError(f"{field} must be an integer in range")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise EvidenceError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _parse_component(raw: Any, index: int) -> Component:
    if not isinstance(raw, dict):
        raise EvidenceError(f"components[{index}] must be an object")
    expected = {
        "name",
        "tier",
        "recovery_mode",
        "dependencies",
        "recovery_order",
        "target_rto_seconds",
        "measured_rto_seconds",
        "target_rpo_seconds",
        "measured_rpo_seconds",
        "required_capacity",
        "recovery_capacity",
        "validation_passed",
    }
    _require_exact_keys(raw, expected, f"components[{index}]")
    name = _identifier(raw["name"], f"components[{index}].name")
    tier = raw["tier"]
    mode = raw["recovery_mode"]
    if tier not in TIERS:
        raise EvidenceError(f"components[{index}].tier is unsupported")
    if mode not in RECOVERY_MODES:
        raise EvidenceError(f"components[{index}].recovery_mode is unsupported")
    dependencies = raw["dependencies"]
    if (
        not isinstance(dependencies, list)
        or len(dependencies) > MAX_DEPENDENCIES_PER_COMPONENT
    ):
        raise EvidenceError(f"components[{index}].dependencies exceeds its budget")
    parsed_dependencies = tuple(
        _identifier(item, f"components[{index}].dependencies") for item in dependencies
    )
    if (
        len(parsed_dependencies) != len(set(parsed_dependencies))
        or name in parsed_dependencies
    ):
        raise EvidenceError(
            f"components[{index}].dependencies contains a duplicate or self-reference"
        )
    validation = raw["validation_passed"]
    if not isinstance(validation, bool):
        raise EvidenceError(f"components[{index}].validation_passed must be boolean")
    return Component(
        name=name,
        tier=tier,
        recovery_mode=mode,
        dependencies=parsed_dependencies,
        recovery_order=_integer(
            raw["recovery_order"], f"components[{index}].recovery_order", minimum=1
        ),
        target_rto_seconds=_number(
            raw["target_rto_seconds"],
            f"components[{index}].target_rto_seconds",
            positive=True,
        ),
        measured_rto_seconds=_number(
            raw["measured_rto_seconds"], f"components[{index}].measured_rto_seconds"
        ),
        target_rpo_seconds=_number(
            raw["target_rpo_seconds"], f"components[{index}].target_rpo_seconds"
        ),
        measured_rpo_seconds=_number(
            raw["measured_rpo_seconds"], f"components[{index}].measured_rpo_seconds"
        ),
        required_capacity=_number(
            raw["required_capacity"],
            f"components[{index}].required_capacity",
            positive=True,
        ),
        recovery_capacity=_number(
            raw["recovery_capacity"], f"components[{index}].recovery_capacity"
        ),
        validation_passed=validation,
    )


def _component_ref(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:16]


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _has_cycle(components: dict[str, Component]) -> bool:
    state: dict[str, int] = {}

    def visit(name: str) -> bool:
        if state.get(name) == 1:
            return True
        if state.get(name) == 2:
            return False
        state[name] = 1
        if any(visit(dep) for dep in components[name].dependencies):
            return True
        state[name] = 2
        return False

    return any(visit(name) for name in sorted(components))


def audit(
    manifest: dict[str, Any], policy: Policy, *, now: datetime | None = None
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "rehearsal_id",
        "primary_region",
        "recovery_region",
        "started_at",
        "completed_at",
        "traffic_switch_budget_seconds",
        "measured_traffic_switch_seconds",
        "components",
    }
    _require_exact_keys(manifest, expected, "manifest")
    if manifest["schema_version"] != 1:
        raise EvidenceError("schema_version must equal 1")
    _identifier(manifest["rehearsal_id"], "rehearsal_id")
    primary = _identifier(manifest["primary_region"], "primary_region")
    recovery = _identifier(manifest["recovery_region"], "recovery_region")
    started = _timestamp(manifest["started_at"], "started_at")
    completed = _timestamp(manifest["completed_at"], "completed_at")
    if completed < started:
        raise EvidenceError("completed_at precedes started_at")
    current_input = now or datetime.now(UTC)
    if current_input.tzinfo is None or current_input.utcoffset() is None:
        raise EvidenceError("now must be timezone-aware")
    current = current_input.astimezone(UTC)
    if completed.timestamp() > current.timestamp() + policy.max_future_skew_seconds:
        raise EvidenceError("completed_at is too far in the future")
    raw_components = manifest["components"]
    if (
        not isinstance(raw_components, list)
        or not 1 <= len(raw_components) <= MAX_COMPONENTS
    ):
        raise EvidenceError("components count is outside its budget")
    parsed = [
        _parse_component(item, index) for index, item in enumerate(raw_components)
    ]
    components = {component.name: component for component in parsed}
    if len(components) != len(parsed):
        raise EvidenceError("component names must be unique")
    if (
        sum(len(component.dependencies) for component in parsed)
        > MAX_TOTAL_DEPENDENCIES
    ):
        raise EvidenceError("total dependency count exceeds its budget")
    unknown = sorted(
        {
            dep
            for component in parsed
            for dep in component.dependencies
            if dep not in components
        }
    )
    if unknown:
        raise EvidenceError("dependency references an unknown component")

    findings: list[dict[str, str]] = []

    def add(code: str, component: Component | None = None) -> None:
        finding = {"code": code}
        if component is not None:
            finding["component_ref"] = _component_ref(component.name)
        findings.append(finding)

    if primary == recovery:
        add("RECOVERY_REGION_NOT_DISTINCT")
    age_seconds = max(0.0, (current - completed).total_seconds())
    if age_seconds > policy.max_rehearsal_age_days * 86400:
        add("REHEARSAL_STALE")
    traffic_budget = _number(
        manifest["traffic_switch_budget_seconds"],
        "traffic_switch_budget_seconds",
        positive=True,
    )
    measured_switch = _number(
        manifest["measured_traffic_switch_seconds"], "measured_traffic_switch_seconds"
    )
    if measured_switch > traffic_budget:
        add("TRAFFIC_SWITCH_BUDGET_EXCEEDED")
    if _has_cycle(components):
        add("DEPENDENCY_CYCLE")

    evaluated_tiers = (
        {"critical", "important"}
        if policy.require_important_dependency_closure
        else {"critical"}
    )
    required_names = {item.name for item in parsed if item.tier in evaluated_tiers}
    pending = list(required_names)
    while pending:
        for dependency_name in components[pending.pop()].dependencies:
            if dependency_name not in required_names:
                required_names.add(dependency_name)
                pending.append(dependency_name)
    for component in sorted(parsed, key=lambda item: item.name):
        required = component.name in required_names
        if component.tier == "critical" and component.recovery_mode == "backup_restore":
            add("CRITICAL_COMPONENT_COLD_RECOVERY", component)
        if required and component.recovery_mode == "unavailable":
            add("COMPONENT_UNAVAILABLE", component)
        if required and not component.validation_passed:
            add("VALIDATION_FAILED", component)
        if required and component.measured_rto_seconds > component.target_rto_seconds:
            add("RTO_EXCEEDED", component)
        if required and component.measured_rpo_seconds > component.target_rpo_seconds:
            add("RPO_EXCEEDED", component)
        ratio = component.recovery_capacity / component.required_capacity
        if required and ratio < policy.minimum_capacity_ratio:
            add("RECOVERY_CAPACITY_INSUFFICIENT", component)
        if required:
            for dependency_name in sorted(component.dependencies):
                dependency = components[dependency_name]
                if (
                    dependency.recovery_mode == "unavailable"
                    or not dependency.validation_passed
                ):
                    add("DEPENDENCY_NOT_RECOVERABLE", component)
                if dependency.recovery_order >= component.recovery_order:
                    add("DEPENDENCY_RECOVERY_ORDER_INVALID", component)
                if dependency.target_rto_seconds > component.target_rto_seconds:
                    add("DEPENDENCY_RTO_MISALIGNED", component)

    findings.sort(key=lambda item: (item["code"], item.get("component_ref", "")))
    capacity_ratios = [
        item.recovery_capacity / item.required_capacity for item in parsed
    ]
    report: dict[str, Any] = {
        "schema_version": 1,
        "accepted": not findings,
        "component_count": len(parsed),
        "critical_component_count": sum(item.tier == "critical" for item in parsed),
        "dependency_count": sum(len(item.dependencies) for item in parsed),
        "rehearsal_age_seconds": round(age_seconds, 6),
        "traffic_switch_ratio": round(measured_switch / traffic_budget, 9),
        "minimum_observed_capacity_ratio": round(min(capacity_ratios), 9),
        "findings": findings,
        "manifest_digest": _canonical_digest(manifest),
        "policy_digest": _canonical_digest(
            {
                "minimum_capacity_ratio": policy.minimum_capacity_ratio,
                "max_rehearsal_age_days": policy.max_rehearsal_age_days,
                "max_future_skew_seconds": policy.max_future_skew_seconds,
                "require_important_dependency_closure": policy.require_important_dependency_closure,
            }
        ),
    }
    report["evidence_digest"] = _canonical_digest(report)
    return report


def _atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--minimum-capacity-ratio", type=float, default=0.8)
    parser.add_argument("--max-rehearsal-age-days", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        policy = Policy(
            minimum_capacity_ratio=args.minimum_capacity_ratio,
            max_rehearsal_age_days=args.max_rehearsal_age_days,
        )
        report = audit(manifest, policy)
    except EvidenceError as exc:
        error = {"accepted": False, "error": "malformed_evidence", "detail": str(exc)}
        if args.output:
            _atomic_write(args.output, error)
        else:
            print(json.dumps(error, sort_keys=True))
        return 3
    if args.output:
        _atomic_write(args.output, report)
    else:
        print(json.dumps(report, sort_keys=True))
    return 0 if report["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
