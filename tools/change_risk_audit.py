from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_RESOURCES = 1_024
MAX_DEPENDENCIES = 8_192
MAX_FINDINGS = 2_048
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {
    "compute",
    "database",
    "dns",
    "iam",
    "network",
    "object_store",
    "queue",
    "secret",
    "other",
}
CRITICALITIES = {"critical", "important", "standard"}
DATA_CLASSES = {"none", "ephemeral", "persistent"}
ACTIONS = {"no_op", "create", "update", "delete", "replace"}
PRIVILEGE_SCOPES = {
    "none": 0,
    "scoped": 1,
    "project": 2,
    "account": 3,
    "organization": 4,
}


class ChangeRiskError(ValueError):
    """Raised when change-plan evidence or policy is malformed."""


@dataclass(frozen=True)
class ResourceState:
    region: str
    failure_domain: str
    public_access: bool
    encrypted: bool
    multi_zone: bool
    deletion_protection: bool
    privilege_scope: str


@dataclass(frozen=True)
class ResourceChange:
    resource_id: str
    kind: str
    criticality: str
    data_class: str
    action: str
    depends_on: tuple[str, ...]
    before: ResourceState | None
    after: ResourceState | None
    change_ticket: str | None
    approval_digest: str | None
    backup_verified_at: datetime | None
    replacement_ready: bool


@dataclass(frozen=True)
class ChangePlan:
    generated_at: datetime
    plan_id: str
    source_revision: str
    state_snapshot_digest: str
    resources: tuple[ResourceChange, ...]


@dataclass(frozen=True)
class ChangeRiskPolicy:
    max_age_seconds: int = 86_400
    max_future_skew_seconds: int = 60
    max_backup_age_seconds: int = 7 * 86_400
    max_changed_resources: int = 64
    max_critical_impacted: int = 3
    max_changes_per_failure_domain: int = 2

    def __post_init__(self) -> None:
        for name in (
            "max_age_seconds",
            "max_future_skew_seconds",
            "max_backup_age_seconds",
            "max_changed_resources",
            "max_critical_impacted",
            "max_changes_per_failure_domain",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ChangeRiskError(f"{name} must be a non-negative integer")
        for name in (
            "max_backup_age_seconds",
            "max_changed_resources",
            "max_critical_impacted",
            "max_changes_per_failure_domain",
        ):
            if getattr(self, name) == 0:
                raise ChangeRiskError(f"{name} must be greater than zero")


@dataclass(frozen=True)
class Finding:
    code: str
    resource_ref: str | None


@dataclass(frozen=True)
class ChangeRiskReport:
    schema_version: str
    accepted: bool
    reasons: tuple[str, ...]
    evidence_digest: str
    plan_ref: str
    source_revision: str
    state_snapshot_digest: str
    generated_at: str
    resource_count: int
    changed_resource_count: int
    critical_changed_count: int
    critical_impacted_count: int
    maximum_resource_blast_radius: int
    destructive_persistent_count: int
    security_regression_count: int
    finding_count: int
    findings_truncated: bool
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "reasons": list(self.reasons),
            "findings": [asdict(finding) for finding in self.findings],
        }


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ChangeRiskError("evidence contains a non-canonical value") from error
    return rendered.encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ChangeRiskError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _timestamp(value: object, path: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ChangeRiskError(f"{path} must be a bounded ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ChangeRiskError(f"{path} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ChangeRiskError(f"{path} must include a timezone")
    return parsed.astimezone(UTC)


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ChangeRiskError(f"{path} must be an object")
    return value


def _keys(value: dict[str, object], expected: set[str], path: str) -> None:
    if set(value) != expected:
        raise ChangeRiskError(f"{path} has missing or unexpected fields")


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ChangeRiskError(f"{path} must be a bounded identifier")
    return value


def _choice(value: object, choices: set[str] | dict[str, int], path: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ChangeRiskError(f"{path} has an unsupported value")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ChangeRiskError(f"{path} must be boolean")
    return value


def _optional_identifier(value: object, path: str) -> str | None:
    return None if value is None else _identifier(value, path)


def _optional_digest(value: object, path: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ChangeRiskError(f"{path} must be a lowercase SHA-256 digest or null")
    return value


def _required_digest(value: object, path: str) -> str:
    result = _optional_digest(value, path)
    if result is None:
        raise ChangeRiskError(f"{path} must be a lowercase SHA-256 digest")
    return result


def _parse_state(value: object, path: str) -> ResourceState:
    raw = _object(value, path)
    _keys(
        raw,
        {
            "region",
            "failure_domain",
            "public_access",
            "encrypted",
            "multi_zone",
            "deletion_protection",
            "privilege_scope",
        },
        path,
    )
    return ResourceState(
        region=_identifier(raw["region"], f"{path}.region"),
        failure_domain=_identifier(raw["failure_domain"], f"{path}.failure_domain"),
        public_access=_boolean(raw["public_access"], f"{path}.public_access"),
        encrypted=_boolean(raw["encrypted"], f"{path}.encrypted"),
        multi_zone=_boolean(raw["multi_zone"], f"{path}.multi_zone"),
        deletion_protection=_boolean(
            raw["deletion_protection"], f"{path}.deletion_protection"
        ),
        privilege_scope=_choice(
            raw["privilege_scope"], PRIVILEGE_SCOPES, f"{path}.privilege_scope"
        ),
    )


def _optional_state(value: object, path: str) -> ResourceState | None:
    return None if value is None else _parse_state(value, path)


def parse_plan(value: object) -> ChangePlan:
    root = _object(value, "plan")
    _keys(
        root,
        {
            "generated_at",
            "plan_id",
            "source_revision",
            "state_snapshot_digest",
            "resources",
        },
        "plan",
    )
    raw_resources = root["resources"]
    if (
        not isinstance(raw_resources, list)
        or not 1 <= len(raw_resources) <= MAX_RESOURCES
    ):
        raise ChangeRiskError("resources must contain between 1 and 1024 entries")
    resources: list[ResourceChange] = []
    seen: set[str] = set()
    dependency_count = 0
    for index, item in enumerate(raw_resources):
        path = f"resources[{index}]"
        raw = _object(item, path)
        _keys(
            raw,
            {
                "id",
                "kind",
                "criticality",
                "data_class",
                "action",
                "depends_on",
                "before",
                "after",
                "change_ticket",
                "approval_digest",
                "backup_verified_at",
                "replacement_ready",
            },
            path,
        )
        resource_id = _identifier(raw["id"], f"{path}.id")
        if resource_id in seen:
            raise ChangeRiskError("resource IDs must be unique")
        seen.add(resource_id)
        raw_dependencies = raw["depends_on"]
        if not isinstance(raw_dependencies, list):
            raise ChangeRiskError(f"{path}.depends_on must be an array")
        dependencies = tuple(
            _identifier(item, f"{path}.depends_on[{dep_index}]")
            for dep_index, item in enumerate(raw_dependencies)
        )
        if len(set(dependencies)) != len(dependencies):
            raise ChangeRiskError(f"{path}.depends_on must not contain duplicates")
        dependency_count += len(dependencies)
        if dependency_count > MAX_DEPENDENCIES:
            raise ChangeRiskError("dependency edge budget exceeded")
        action = _choice(raw["action"], ACTIONS, f"{path}.action")
        before = _optional_state(raw["before"], f"{path}.before")
        after = _optional_state(raw["after"], f"{path}.after")
        if action == "create" and (before is not None or after is None):
            raise ChangeRiskError(
                "create requires null before and non-null after state"
            )
        if action == "delete" and (before is None or after is not None):
            raise ChangeRiskError(
                "delete requires non-null before and null after state"
            )
        if action in {"no_op", "update", "replace"} and (
            before is None or after is None
        ):
            raise ChangeRiskError(f"{action} requires before and after state")
        if action == "no_op" and before != after:
            raise ChangeRiskError("no_op before and after states must match")
        backup = raw["backup_verified_at"]
        resources.append(
            ResourceChange(
                resource_id=resource_id,
                kind=_choice(raw["kind"], KINDS, f"{path}.kind"),
                criticality=_choice(
                    raw["criticality"], CRITICALITIES, f"{path}.criticality"
                ),
                data_class=_choice(
                    raw["data_class"], DATA_CLASSES, f"{path}.data_class"
                ),
                action=action,
                depends_on=dependencies,
                before=before,
                after=after,
                change_ticket=_optional_identifier(
                    raw["change_ticket"], f"{path}.change_ticket"
                ),
                approval_digest=_optional_digest(
                    raw["approval_digest"], f"{path}.approval_digest"
                ),
                backup_verified_at=(
                    None
                    if backup is None
                    else _timestamp(backup, f"{path}.backup_verified_at")
                ),
                replacement_ready=_boolean(
                    raw["replacement_ready"], f"{path}.replacement_ready"
                ),
            )
        )

    ids = {resource.resource_id for resource in resources}
    for resource in resources:
        for dependency in resource.depends_on:
            if dependency == resource.resource_id:
                raise ChangeRiskError("resources cannot depend on themselves")
            if dependency not in ids:
                raise ChangeRiskError("dependencies must reference declared resources")
    if not any(resource.action != "no_op" for resource in resources):
        raise ChangeRiskError("plan must contain at least one change")
    _validate_acyclic(resources)
    return ChangePlan(
        generated_at=_timestamp(root["generated_at"], "generated_at"),
        plan_id=_identifier(root["plan_id"], "plan_id"),
        source_revision=_required_digest(root["source_revision"], "source_revision"),
        state_snapshot_digest=_required_digest(
            root["state_snapshot_digest"], "state_snapshot_digest"
        ),
        resources=tuple(resources),
    )


def _validate_acyclic(resources: list[ResourceChange]) -> None:
    indegree = {
        resource.resource_id: len(resource.depends_on) for resource in resources
    }
    dependents: dict[str, list[str]] = {
        resource.resource_id: [] for resource in resources
    }
    for resource in resources:
        for dependency in resource.depends_on:
            dependents[dependency].append(resource.resource_id)
    ready = deque(sorted(key for key, value in indegree.items() if value == 0))
    visited = 0
    while ready:
        current = ready.popleft()
        visited += 1
        for dependent in dependents[current]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
    if visited != len(resources):
        raise ChangeRiskError("resource dependency graph must be acyclic")


def _state_dict(state: ResourceState | None) -> dict[str, Any] | None:
    return None if state is None else asdict(state)


def _canonical_plan(plan: ChangePlan) -> dict[str, Any]:
    return {
        "generated_at": _format_timestamp(plan.generated_at),
        "plan_id": plan.plan_id,
        "source_revision": plan.source_revision,
        "state_snapshot_digest": plan.state_snapshot_digest,
        "resources": [
            {
                "id": resource.resource_id,
                "kind": resource.kind,
                "criticality": resource.criticality,
                "data_class": resource.data_class,
                "action": resource.action,
                "depends_on": sorted(resource.depends_on),
                "before": _state_dict(resource.before),
                "after": _state_dict(resource.after),
                "change_ticket": resource.change_ticket,
                "approval_digest": resource.approval_digest,
                "backup_verified_at": (
                    None
                    if resource.backup_verified_at is None
                    else _format_timestamp(resource.backup_verified_at)
                ),
                "replacement_ready": resource.replacement_ready,
            }
            for resource in sorted(plan.resources, key=lambda item: item.resource_id)
        ],
    }


def _requires_approval(resource: ResourceChange) -> bool:
    before = resource.before
    after = resource.after
    if resource.data_class == "persistent" and resource.action in {"delete", "replace"}:
        return True
    if (
        after is not None
        and after.public_access
        and (before is None or not before.public_access)
    ):
        return True
    if (
        after is not None
        and PRIVILEGE_SCOPES[after.privilege_scope] >= PRIVILEGE_SCOPES["account"]
        and (
            before is None
            or PRIVILEGE_SCOPES[after.privilege_scope]
            > PRIVILEGE_SCOPES[before.privilege_scope]
        )
    ):
        return True
    return before is not None and after is not None and before.region != after.region


def _security_regressions(resource: ResourceChange) -> tuple[str, ...]:
    before = resource.before
    after = resource.after
    if before is None or after is None:
        return ()
    findings: list[str] = []
    if resource.data_class != "none" and before.encrypted and not after.encrypted:
        findings.append("encryption_removed")
    if (
        resource.data_class == "persistent"
        and before.deletion_protection
        and not after.deletion_protection
    ):
        findings.append("deletion_protection_removed")
    if (
        resource.criticality in {"critical", "important"}
        and before.multi_zone
        and not after.multi_zone
    ):
        findings.append("multi_zone_resilience_removed")
    return tuple(findings)


def audit_change_plan(
    plan: ChangePlan | object,
    *,
    now: datetime,
    policy: ChangeRiskPolicy | None = None,
) -> ChangeRiskReport:
    parsed = plan if isinstance(plan, ChangePlan) else parse_plan(plan)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ChangeRiskError("now must be timezone-aware")
    now_utc = now.astimezone(UTC)
    effective_policy = policy or ChangeRiskPolicy()
    resources = {resource.resource_id: resource for resource in parsed.resources}
    changed = tuple(
        resource for resource in parsed.resources if resource.action != "no_op"
    )
    dependents: dict[str, list[str]] = {resource_id: [] for resource_id in resources}
    for resource in parsed.resources:
        for dependency in resource.depends_on:
            dependents[dependency].append(resource.resource_id)

    reasons: set[str] = set()
    findings: list[Finding] = []
    total_finding_count = 0

    def record(code: str, resource: ResourceChange | None = None) -> None:
        nonlocal total_finding_count
        reasons.add(code)
        total_finding_count += 1
        if len(findings) < MAX_FINDINGS:
            findings.append(
                Finding(
                    code=code,
                    resource_ref=None
                    if resource is None
                    else _ref(resource.resource_id),
                )
            )

    age_seconds = (now_utc - parsed.generated_at).total_seconds()
    if age_seconds > effective_policy.max_age_seconds:
        record("stale_plan_evidence")
    if age_seconds < -effective_policy.max_future_skew_seconds:
        record("future_plan_evidence")
    if len(changed) > effective_policy.max_changed_resources:
        record("change_batch_limit_exceeded")

    changed_domains: Counter[str] = Counter()
    impacted_union: set[str] = set()
    maximum_blast_radius = 0
    destructive_persistent_count = 0
    security_regression_count = 0
    for resource in changed:
        state = resource.after or resource.before
        assert state is not None
        changed_domains[state.failure_domain] += 1
        impacted = {resource.resource_id}
        queue = deque([resource.resource_id])
        while queue:
            current = queue.popleft()
            for dependent in dependents[current]:
                if dependent not in impacted:
                    impacted.add(dependent)
                    queue.append(dependent)
        maximum_blast_radius = max(maximum_blast_radius, len(impacted))
        impacted_union.update(
            resource_id
            for resource_id in impacted
            if resources[resource_id].criticality == "critical"
        )

        if _requires_approval(resource) and (
            resource.change_ticket is None or resource.approval_digest is None
        ):
            record("missing_change_approval", resource)
        regressions = _security_regressions(resource)
        security_regression_count += len(regressions)
        for regression in regressions:
            record(regression, resource)
        if resource.data_class == "persistent" and resource.action in {
            "delete",
            "replace",
        }:
            destructive_persistent_count += 1
            if resource.backup_verified_at is None:
                record("missing_verified_backup", resource)
            else:
                backup_age = (now_utc - resource.backup_verified_at).total_seconds()
                if backup_age > effective_policy.max_backup_age_seconds:
                    record("stale_verified_backup", resource)
                if backup_age < -effective_policy.max_future_skew_seconds:
                    record("future_backup_evidence", resource)
            if resource.action == "replace" and not resource.replacement_ready:
                record("replacement_not_ready", resource)

    if len(impacted_union) > effective_policy.max_critical_impacted:
        record("critical_blast_radius_exceeded")
    for count in changed_domains.values():
        if count > effective_policy.max_changes_per_failure_domain:
            record("failure_domain_change_concentration")
            break

    ordered_findings = tuple(
        sorted(findings, key=lambda finding: (finding.code, finding.resource_ref or ""))
    )
    ordered_reasons = tuple(sorted(reasons))
    return ChangeRiskReport(
        schema_version="1.0",
        accepted=not ordered_reasons,
        reasons=ordered_reasons,
        evidence_digest=_digest(_canonical_plan(parsed)),
        plan_ref=_ref(parsed.plan_id),
        source_revision=parsed.source_revision,
        state_snapshot_digest=parsed.state_snapshot_digest,
        generated_at=_format_timestamp(parsed.generated_at),
        resource_count=len(parsed.resources),
        changed_resource_count=len(changed),
        critical_changed_count=sum(
            resource.criticality == "critical" for resource in changed
        ),
        critical_impacted_count=len(impacted_union),
        maximum_resource_blast_radius=maximum_blast_radius,
        destructive_persistent_count=destructive_persistent_count,
        security_regression_count=security_regression_count,
        finding_count=total_finding_count,
        findings_truncated=total_finding_count > len(ordered_findings),
        findings=ordered_findings,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ChangeRiskError("JSON objects must not contain duplicate fields")
        result[key] = value
    return result


def load_plan(path: Path) -> ChangePlan:
    try:
        if path.is_symlink():
            raise ChangeRiskError("input must not be a symbolic link")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ChangeRiskError("input exceeds the JSON byte limit")
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ChangeRiskError("JSON must not contain non-finite numbers")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ChangeRiskError("input is not valid UTF-8 JSON") from error
    return parse_plan(payload)


def _write_json(payload: dict[str, Any], output: Path | None) -> None:
    rendered = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    )
    if output is None:
        print(rendered, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit infrastructure change blast radius"
    )
    parser.add_argument("plan", type=Path, help="normalized infrastructure plan JSON")
    parser.add_argument("--now", required=True, help="UTC-aware audit timestamp")
    parser.add_argument("--output", type=Path, help="atomically write the audit report")
    parser.add_argument("--max-changed-resources", type=int, default=64)
    parser.add_argument("--max-critical-impacted", type=int, default=3)
    parser.add_argument("--max-changes-per-failure-domain", type=int, default=2)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        report = audit_change_plan(
            load_plan(arguments.plan),
            now=_timestamp(arguments.now, "now"),
            policy=ChangeRiskPolicy(
                max_changed_resources=arguments.max_changed_resources,
                max_critical_impacted=arguments.max_critical_impacted,
                max_changes_per_failure_domain=arguments.max_changes_per_failure_domain,
            ),
        )
        _write_json(report.to_dict(), arguments.output)
    except (ChangeRiskError, OSError) as error:
        _write_json(
            {"accepted": False, "error": "malformed_evidence", "detail": str(error)},
            arguments.output,
        )
        return 3
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
