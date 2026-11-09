from __future__ import annotations

import argparse
import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools.change_risk_audit import parse_plan
from tools.terraform_plan_adapter import (
    ADAPTER_SCHEMA_VERSION,
    FORMAT_VERSION_RE,
    INVENTORY_FIELDS,
    MAX_INVENTORY_BYTES,
    MAX_PLAN_BYTES,
    MAX_RESOURCES,
    TerraformPlanAdapterError,
    _digest,
    _exact_fields,
    _load_json,
    _normalized_state,
    _object,
    _write_json,
)

RECONCILIATION_SCHEMA_VERSION = "terraform-apply-reconciliation/v1"
MAX_MODULE_DEPTH = 32
MAX_FINDINGS = 2 * MAX_RESOURCES


class TerraformApplyReconciliationError(ValueError):
    """Plan, inventory, or applied-state evidence cannot be reconciled safely."""


@dataclass(frozen=True)
class ReconciliationFinding:
    code: str
    resource_ref: str


@dataclass(frozen=True)
class TerraformApplyReport:
    schema_version: str
    accepted: bool
    reasons: tuple[str, ...]
    evidence_digest: str
    plan_ref: str
    source_revision: str
    inventory_digest: str
    applied_state_digest: str
    expected_resource_count: int
    observed_resource_count: int
    matched_resource_count: int
    missing_resource_count: int
    unexpected_resource_count: int
    posture_drift_count: int
    finding_count: int
    findings_truncated: bool
    findings: tuple[ReconciliationFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "reasons": list(self.reasons),
            "findings": [asdict(finding) for finding in self.findings],
        }


def _resource_ref(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:16]


def _managed_state_resources(state: dict[str, object]) -> dict[str, dict[str, object]]:
    version = state.get("format_version")
    if not isinstance(version, str) or FORMAT_VERSION_RE.fullmatch(version) is None:
        raise TerraformApplyReconciliationError(
            "unsupported Terraform state JSON format version"
        )
    terraform_version = state.get("terraform_version")
    if not isinstance(terraform_version, str) or not 1 <= len(terraform_version) <= 64:
        raise TerraformApplyReconciliationError("state terraform_version is invalid")
    values = _object(state.get("values"), "state.values")
    root = _object(values.get("root_module"), "state.values.root_module")
    resources: dict[str, dict[str, object]] = {}
    stack: list[tuple[dict[str, object], int]] = [(root, 0)]
    visited_modules = 0
    while stack:
        module, depth = stack.pop()
        if depth > MAX_MODULE_DEPTH:
            raise TerraformApplyReconciliationError("module depth budget exceeded")
        visited_modules += 1
        if visited_modules > MAX_RESOURCES:
            raise TerraformApplyReconciliationError("module count budget exceeded")
        raw_resources = module.get("resources", [])
        if not isinstance(raw_resources, list):
            raise TerraformApplyReconciliationError("module.resources must be an array")
        for item in raw_resources:
            resource = _object(item, "state resource")
            mode = resource.get("mode")
            if mode == "data":
                continue
            if mode != "managed":
                raise TerraformApplyReconciliationError(
                    "state resource mode is unsupported"
                )
            address = resource.get("address")
            if not isinstance(address, str) or not 1 <= len(address) <= 192:
                raise TerraformApplyReconciliationError(
                    "state resource address is invalid"
                )
            provider_name = resource.get("provider_name")
            if not isinstance(provider_name, str) or not 1 <= len(provider_name) <= 256:
                raise TerraformApplyReconciliationError(
                    "state resource provider_name is invalid"
                )
            if address in resources:
                raise TerraformApplyReconciliationError(
                    "managed state resource addresses must be unique"
                )
            _object(resource.get("values"), "state resource values")
            _object(
                resource.get("sensitive_values", {}),
                "state resource sensitive_values",
            )
            resources[address] = resource
            if len(resources) > MAX_RESOURCES:
                raise TerraformApplyReconciliationError(
                    "managed state resource budget exceeded"
                )
        children = module.get("child_modules", [])
        if not isinstance(children, list):
            raise TerraformApplyReconciliationError(
                "module.child_modules must be an array"
            )
        for child in reversed(children):
            stack.append((_object(child, "child module"), depth + 1))
    return resources


def _canonical_applied_state(
    state: dict[str, object], resources: dict[str, dict[str, object]]
) -> dict[str, object]:
    return {
        "format_version": state["format_version"],
        "terraform_version": state.get("terraform_version"),
        "managed_resources": [
            {
                "address": address,
                "provider_name": resource.get("provider_name"),
                "schema_version": resource.get("schema_version"),
                "values": resource["values"],
                "sensitive_values": resource.get("sensitive_values", {}),
            }
            for address, resource in sorted(resources.items())
        ],
    }


def _reconcile_terraform_apply(
    normalized_plan: object,
    inventory: object,
    applied_state: object,
) -> TerraformApplyReport:
    try:
        plan = parse_plan(normalized_plan)
    except ValueError as exc:
        raise TerraformApplyReconciliationError(
            "normalized plan violates the change-risk contract"
        ) from exc
    raw_plan = _object(normalized_plan, "plan")
    catalog = _object(inventory, "inventory")
    _exact_fields(catalog, {"schema_version", "resources"}, "inventory")
    if catalog["schema_version"] != ADAPTER_SCHEMA_VERSION:
        raise TerraformApplyReconciliationError("unsupported inventory schema")
    entries = _object(catalog["resources"], "inventory.resources")
    if _digest(catalog) != plan.inventory_digest:
        raise TerraformApplyReconciliationError(
            "inventory digest does not match the reviewed plan"
        )
    expected_by_id = {resource.resource_id: resource for resource in plan.resources}
    if set(entries) != set(expected_by_id):
        raise TerraformApplyReconciliationError(
            "inventory must exactly cover normalized plan resources"
        )
    for address, metadata in entries.items():
        _exact_fields(
            _object(metadata, f"inventory.resources[{address!r}]"),
            INVENTORY_FIELDS,
            f"inventory.resources[{address!r}]",
        )

    raw_state = _object(applied_state, "state")
    observed = _managed_state_resources(raw_state)
    expected_present = {
        address
        for address, resource in expected_by_id.items()
        if resource.action != "delete"
    }
    expected_deleted = set(expected_by_id) - expected_present

    findings: list[ReconciliationFinding] = []
    total_findings = 0
    reasons: set[str] = set()

    def record(code: str, address: str) -> None:
        nonlocal total_findings
        reasons.add(code)
        total_findings += 1
        if len(findings) < MAX_FINDINGS:
            findings.append(
                ReconciliationFinding(code=code, resource_ref=_resource_ref(address))
            )

    missing = expected_present - set(observed)
    unexpected = set(observed) - expected_present
    for address in sorted(missing):
        record("expected_resource_missing", address)
    for address in sorted(unexpected):
        code = (
            "deleted_resource_still_present"
            if address in expected_deleted
            else "unreviewed_resource_present"
        )
        record(code, address)

    posture_drift = 0
    matched = 0
    for address in sorted(expected_present & set(observed)):
        expected = expected_by_id[address]
        metadata = _object(entries[address], f"inventory.resources[{address!r}]")
        state_resource = observed[address]
        try:
            actual = _normalized_state(
                state_resource["values"],
                metadata["posture"],
                unknown={},
                sensitive=state_resource.get("sensitive_values", {}),
                path=f"applied[{address!r}]",
            )
        except TerraformPlanAdapterError as exc:
            raise TerraformApplyReconciliationError(
                "applied posture cannot be resolved safely"
            ) from exc
        expected_after = expected.after
        if expected_after is None:  # pragma: no cover - parse_plan action invariant
            raise TerraformApplyReconciliationError(
                "present resource has no expected after state"
            )
        expected_state = {
            "region": expected_after.region,
            "failure_domain": expected_after.failure_domain,
            "public_access": expected_after.public_access,
            "encrypted": expected_after.encrypted,
            "multi_zone": expected_after.multi_zone,
            "deletion_protection": expected_after.deletion_protection,
            "privilege_scope": expected_after.privilege_scope,
        }
        if actual != expected_state:
            posture_drift += 1
            record("governed_posture_drift", address)
        else:
            matched += 1

    canonical_state = _canonical_applied_state(raw_state, observed)
    ordered_findings = tuple(
        sorted(findings, key=lambda finding: (finding.code, finding.resource_ref))
    )
    return TerraformApplyReport(
        schema_version=RECONCILIATION_SCHEMA_VERSION,
        accepted=not reasons,
        reasons=tuple(sorted(reasons)),
        evidence_digest=_digest(
            {
                "normalized_plan": raw_plan,
                "inventory": catalog,
                "applied_state": canonical_state,
            }
        ),
        plan_ref=_resource_ref(plan.plan_id),
        source_revision=plan.source_revision,
        inventory_digest=plan.inventory_digest,
        applied_state_digest=_digest(canonical_state),
        expected_resource_count=len(expected_by_id),
        observed_resource_count=len(observed),
        matched_resource_count=matched + len(expected_deleted - set(observed)),
        missing_resource_count=len(missing),
        unexpected_resource_count=len(unexpected),
        posture_drift_count=posture_drift,
        finding_count=total_findings,
        findings_truncated=total_findings > len(ordered_findings),
        findings=ordered_findings,
    )


def reconcile_terraform_apply(
    normalized_plan: object,
    inventory: object,
    applied_state: object,
) -> TerraformApplyReport:
    try:
        return _reconcile_terraform_apply(normalized_plan, inventory, applied_state)
    except TerraformPlanAdapterError as exc:
        raise TerraformApplyReconciliationError(
            "plan, inventory, or state shape is invalid"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile governed Terraform posture after apply"
    )
    parser.add_argument("normalized_plan", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("applied_state", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        report = reconcile_terraform_apply(
            _load_json(arguments.normalized_plan, MAX_PLAN_BYTES),
            _load_json(arguments.inventory, MAX_INVENTORY_BYTES),
            _load_json(arguments.applied_state, MAX_PLAN_BYTES),
        )
        _write_json(report.to_dict(), arguments.output)
    except (
        OSError,
        TerraformApplyReconciliationError,
        TerraformPlanAdapterError,
    ) as exc:
        _write_json(
            {"accepted": False, "error": "malformed_evidence", "detail": str(exc)},
            arguments.output,
        )
        return 3
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
