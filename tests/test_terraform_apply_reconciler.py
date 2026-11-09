from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.terraform_apply_reconciler import (
    TerraformApplyReconciliationError,
    reconcile_terraform_apply,
)
from tools.terraform_plan_adapter import ADAPTER_SCHEMA_VERSION

REVISION = "a" * 64
STATE_DIGEST = "b" * 64


def posture() -> dict[str, object]:
    return {
        "region": {"path": "/region"},
        "failure_domain": {"path": "/availability_zone"},
        "public_access": {"path": "/publicly_accessible"},
        "encrypted": {"path": "/storage_encrypted"},
        "multi_zone": {"path": "/multi_az"},
        "deletion_protection": {"path": "/deletion_protection"},
        "privilege_scope": {"literal": "scoped"},
    }


def governed_state(*, public: bool = False) -> dict[str, object]:
    return {
        "region": "eu-west-1",
        "failure_domain": "eu-west-1a",
        "public_access": public,
        "encrypted": True,
        "multi_zone": True,
        "deletion_protection": True,
        "privilege_scope": "scoped",
    }


def provider_values(*, public: bool = False) -> dict[str, object]:
    return {
        "region": "eu-west-1",
        "availability_zone": "eu-west-1a",
        "publicly_accessible": public,
        "storage_encrypted": True,
        "multi_az": True,
        "deletion_protection": True,
        "engine": "postgres",
    }


def resource(
    address: str,
    action: str,
    *,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "id": address,
        "kind": "database",
        "criticality": "critical",
        "data_class": "persistent",
        "action": action,
        "depends_on": [],
        "before": before,
        "after": after,
        "change_ticket": "CHG-42" if action == "delete" else None,
        "approval_digest": "c" * 64 if action == "delete" else None,
        "backup_verified_at": ("2026-11-09T06:00:00Z" if action == "delete" else None),
        "replacement_ready": False,
    }


def catalog_digest(catalog: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            catalog,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def plan() -> dict[str, object]:
    state = governed_state()
    return {
        "generated_at": "2026-11-09T07:00:00Z",
        "plan_id": "tfplan-0123456789abcdef",
        "source_revision": REVISION,
        "state_snapshot_digest": STATE_DIGEST,
        "inventory_digest": catalog_digest(inventory()),
        "resources": [
            resource("aws_db_instance.orders", "update", before=state, after=state),
            resource("aws_db_instance.audit", "no_op", before=state, after=state),
            resource("aws_db_instance.legacy", "delete", before=state, after=None),
        ],
    }


def metadata() -> dict[str, object]:
    return {
        "kind": "database",
        "criticality": "critical",
        "data_class": "persistent",
        "depends_on": [],
        "change_ticket": None,
        "approval_digest": None,
        "backup_verified_at": None,
        "replacement_ready": False,
        "posture": posture(),
    }


def inventory() -> dict[str, object]:
    return {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "resources": {
            "aws_db_instance.orders": metadata(),
            "aws_db_instance.audit": metadata(),
            "aws_db_instance.legacy": metadata(),
        },
    }


def state_resource(address: str, *, public: bool = False) -> dict[str, object]:
    return {
        "address": address,
        "mode": "managed",
        "type": "aws_db_instance",
        "name": address.rsplit(".", 1)[-1],
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "schema_version": 2,
        "values": provider_values(public=public),
        "sensitive_values": {},
    }


def applied_state() -> dict[str, object]:
    return {
        "format_version": "1.0",
        "terraform_version": "1.14.0",
        "values": {
            "root_module": {
                "resources": [
                    state_resource("aws_db_instance.orders"),
                    state_resource("aws_db_instance.audit"),
                    {
                        "address": "data.aws_caller_identity.current",
                        "mode": "data",
                        "values": {"account_id": "123456789012"},
                    },
                ]
            }
        },
    }


def reconcile(raw_plan=None, catalog=None, raw_state=None):
    return reconcile_terraform_apply(
        plan() if raw_plan is None else raw_plan,
        inventory() if catalog is None else catalog,
        applied_state() if raw_state is None else raw_state,
    )


def test_matching_apply_state_is_accepted_without_exposing_addresses() -> None:
    report = reconcile()

    assert report.accepted is True
    assert report.expected_resource_count == 3
    assert report.observed_resource_count == 2
    assert report.matched_resource_count == 3
    assert report.inventory_digest == catalog_digest(inventory())
    assert report.findings == ()
    assert "aws_db_instance" not in json.dumps(report.to_dict())


def test_governed_posture_drift_is_rejected_with_hashed_reference() -> None:
    raw_state = applied_state()
    raw_state["values"]["root_module"]["resources"][0] = state_resource(
        "aws_db_instance.orders", public=True
    )

    report = reconcile(raw_state=raw_state)

    assert report.accepted is False
    assert report.reasons == ("governed_posture_drift",)
    assert report.posture_drift_count == 1
    assert report.matched_resource_count == 2
    assert len(report.findings[0].resource_ref) == 16
    assert "orders" not in json.dumps(report.to_dict())


def test_missing_unreviewed_and_failed_delete_are_distinguished() -> None:
    raw_state = applied_state()
    resources = raw_state["values"]["root_module"]["resources"]
    resources.pop(0)
    resources.extend(
        [
            state_resource("aws_db_instance.legacy"),
            state_resource("aws_db_instance.shadow"),
        ]
    )

    report = reconcile(raw_state=raw_state)

    assert report.reasons == (
        "deleted_resource_still_present",
        "expected_resource_missing",
        "unreviewed_resource_present",
    )
    assert report.missing_resource_count == 1
    assert report.unexpected_resource_count == 2
    assert report.finding_count == 3


def test_create_and_replace_compare_their_expected_after_posture() -> None:
    raw_plan = plan()
    raw_plan["resources"][0]["action"] = "replace"
    raw_plan["resources"][0]["replacement_ready"] = True
    raw_plan["resources"][1]["action"] = "create"
    raw_plan["resources"][1]["before"] = None

    assert reconcile(raw_plan=raw_plan).accepted


def test_nested_child_modules_are_flattened() -> None:
    raw_state = applied_state()
    resources = raw_state["values"]["root_module"]["resources"]
    audit = resources.pop(1)
    raw_state["values"]["root_module"]["child_modules"] = [
        {"address": "module.audit", "resources": [audit]}
    ]

    report = reconcile(raw_state=raw_state)

    assert report.accepted
    assert report.observed_resource_count == 2


def test_resource_order_does_not_change_evidence() -> None:
    raw_state = applied_state()
    raw_state["values"]["root_module"]["resources"].reverse()

    assert reconcile(raw_state=raw_state) == reconcile()


def test_duplicate_managed_address_fails_closed() -> None:
    raw_state = applied_state()
    raw_state["values"]["root_module"]["resources"].append(
        state_resource("aws_db_instance.orders")
    )

    with pytest.raises(TerraformApplyReconciliationError, match="unique"):
        reconcile(raw_state=raw_state)


def test_missing_provider_identity_fails_closed() -> None:
    raw_state = applied_state()
    del raw_state["values"]["root_module"]["resources"][0]["provider_name"]

    with pytest.raises(TerraformApplyReconciliationError, match="provider_name"):
        reconcile(raw_state=raw_state)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(format_version="2.0"), "format version"),
        (lambda value: value.pop("terraform_version"), "terraform_version"),
        (lambda value: value.pop("values"), "shape is invalid"),
        (
            lambda value: value["values"]["root_module"].update(resources={}),
            "resources must be an array",
        ),
    ],
)
def test_malformed_state_fails_closed(mutation, message: str) -> None:
    raw_state = applied_state()
    mutation(raw_state)

    with pytest.raises(TerraformApplyReconciliationError, match=message):
        reconcile(raw_state=raw_state)


def test_sensitive_governed_value_fails_closed() -> None:
    raw_state = applied_state()
    raw_state["values"]["root_module"]["resources"][0]["sensitive_values"] = {
        "storage_encrypted": True
    }

    with pytest.raises(
        TerraformApplyReconciliationError, match="cannot be resolved safely"
    ):
        reconcile(raw_state=raw_state)


def test_inventory_must_exactly_cover_plan() -> None:
    catalog = inventory()
    del catalog["resources"]["aws_db_instance.audit"]
    raw_plan = plan()
    raw_plan["inventory_digest"] = catalog_digest(catalog)

    with pytest.raises(TerraformApplyReconciliationError, match="exactly cover"):
        reconcile(raw_plan=raw_plan, catalog=catalog)


def test_modified_inventory_cannot_remap_applied_posture() -> None:
    catalog = inventory()
    catalog["resources"]["aws_db_instance.orders"]["posture"]["public_access"] = {
        "literal": False
    }

    with pytest.raises(TerraformApplyReconciliationError, match="inventory digest"):
        reconcile(catalog=catalog)


def run_cli(tmp_path: Path, raw_state: dict[str, object]):
    plan_path = tmp_path / "normalized.json"
    inventory_path = tmp_path / "inventory.json"
    state_path = tmp_path / "state.json"
    output = tmp_path / "reconciliation.json"
    plan_path.write_text(json.dumps(plan()), encoding="utf-8")
    inventory_path.write_text(json.dumps(inventory()), encoding="utf-8")
    state_path.write_text(json.dumps(raw_state), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.terraform_apply_reconciler",
            str(plan_path),
            str(inventory_path),
            str(state_path),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return result, json.loads(output.read_text(encoding="utf-8"))


def test_cli_has_distinct_accept_reject_and_malformed_exits(tmp_path: Path) -> None:
    accepted, accepted_report = run_cli(tmp_path, applied_state())
    assert accepted.returncode == 0
    assert accepted_report["accepted"] is True

    drifted = applied_state()
    drifted["values"]["root_module"]["resources"][0] = state_resource(
        "aws_db_instance.orders", public=True
    )
    rejected, rejected_report = run_cli(tmp_path, drifted)
    assert rejected.returncode == 2
    assert rejected_report["reasons"] == ["governed_posture_drift"]

    malformed = applied_state()
    malformed["format_version"] = "2.0"
    invalid, invalid_report = run_cli(tmp_path, malformed)
    assert invalid.returncode == 3
    assert invalid_report["error"] == "malformed_evidence"


def test_cli_rejects_symlinked_state(tmp_path: Path) -> None:
    plan_path = tmp_path / "normalized.json"
    inventory_path = tmp_path / "inventory.json"
    target = tmp_path / "real-state.json"
    link = tmp_path / "linked-state.json"
    plan_path.write_text(json.dumps(plan()), encoding="utf-8")
    inventory_path.write_text(json.dumps(inventory()), encoding="utf-8")
    target.write_text(json.dumps(applied_state()), encoding="utf-8")
    link.symlink_to(target)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.terraform_apply_reconciler",
            str(plan_path),
            str(inventory_path),
            str(link),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 3
    assert json.loads(result.stdout)["error"] == "malformed_evidence"


def test_ungoverned_state_drift_changes_digest_without_policy_rejection() -> None:
    raw_state = applied_state()
    cloned = copy.deepcopy(raw_state)
    cloned["values"]["root_module"]["resources"][0]["values"]["engine"] = "mysql"

    baseline = reconcile(raw_state=raw_state)
    changed = reconcile(raw_state=cloned)

    assert changed.accepted
    assert changed.applied_state_digest != baseline.applied_state_digest
    assert changed.evidence_digest != baseline.evidence_digest
