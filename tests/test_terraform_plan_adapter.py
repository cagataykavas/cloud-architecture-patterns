from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tools.change_risk_audit import audit_change_plan
from tools.terraform_plan_adapter import (
    ADAPTER_SCHEMA_VERSION,
    TerraformPlanAdapterError,
    adapt_terraform_plan,
)

NOW = datetime(2026, 11, 8, 17, 30, tzinfo=UTC)
REVISION = "a" * 64


def state(*, encrypted: bool = True, public: bool = False) -> dict[str, object]:
    return {
        "region": "eu-west-1",
        "az": "eu-west-1a",
        "public": public,
        "encrypted": encrypted,
        "multi_az": True,
        "delete_protection": True,
        "scope": "scoped",
    }


def change(
    address: str,
    *,
    actions: list[str],
    before: dict[str, object] | None,
    after: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "address": address,
        "mode": "managed",
        "type": address.split(".", 1)[0],
        "name": address.split(".", 1)[1],
        "change": {
            "actions": actions,
            "before": before,
            "after": after,
            "after_unknown": {},
            "before_sensitive": {},
            "after_sensitive": {},
        },
    }


def plan() -> dict[str, object]:
    database_before = state()
    database_after = copy.deepcopy(database_before)
    api_state = state()
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.0",
        "applyable": True,
        "complete": True,
        "errored": False,
        "prior_state": {"values": {"root_module": {"resources": []}}},
        "resource_changes": [
            change(
                "aws_db_instance.orders",
                actions=["update"],
                before=database_before,
                after=database_after,
            ),
            change(
                "aws_instance.api",
                actions=["no-op"],
                before=api_state,
                after=copy.deepcopy(api_state),
            ),
            {
                "address": "data.aws_caller_identity.current",
                "mode": "data",
                "change": {"actions": ["read"], "before": None, "after": {}},
            },
        ],
    }


def posture(*, literal_region: bool = False) -> dict[str, object]:
    return {
        "region": ({"literal": "eu-west-1"} if literal_region else {"path": "/region"}),
        "failure_domain": {"path": "/az"},
        "public_access": {"path": "/public"},
        "encrypted": {"path": "/encrypted"},
        "multi_zone": {"path": "/multi_az"},
        "deletion_protection": {"path": "/delete_protection"},
        "privilege_scope": {"path": "/scope"},
    }


def metadata(
    *,
    kind: str,
    criticality: str,
    data_class: str,
    depends_on: list[str],
) -> dict[str, object]:
    return {
        "kind": kind,
        "criticality": criticality,
        "data_class": data_class,
        "depends_on": depends_on,
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
            "aws_db_instance.orders": metadata(
                kind="database",
                criticality="critical",
                data_class="persistent",
                depends_on=[],
            ),
            "aws_instance.api": metadata(
                kind="compute",
                criticality="critical",
                data_class="none",
                depends_on=["aws_db_instance.orders"],
            ),
        },
    }


def adapt(raw_plan=None, catalog=None):
    return adapt_terraform_plan(
        plan() if raw_plan is None else raw_plan,
        inventory() if catalog is None else catalog,
        source_revision=REVISION,
        generated_at=NOW,
    )


def test_adapter_produces_gate_compatible_dependency_evidence() -> None:
    normalized = adapt()
    report = audit_change_plan(normalized, now=NOW)

    assert report.accepted is True
    assert report.changed_resource_count == 1
    assert report.critical_changed_count == 1
    assert report.critical_impacted_count == 2
    assert report.maximum_resource_blast_radius == 2
    assert normalized["plan_id"].startswith("tfplan-")
    assert normalized["state_snapshot_digest"]
    assert normalized["inventory_digest"]
    assert all(
        "data.aws_caller_identity" not in row["id"] for row in normalized["resources"]
    )


def test_resource_and_catalog_order_do_not_change_normalized_evidence() -> None:
    raw_plan = plan()
    catalog = inventory()
    raw_plan["resource_changes"].reverse()
    catalog["resources"] = dict(reversed(list(catalog["resources"].items())))

    assert adapt(raw_plan, catalog) == adapt()


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"]])
def test_both_replacement_orders_map_to_replace(actions: list[str]) -> None:
    raw_plan = plan()
    raw_plan["resource_changes"][0]["change"]["actions"] = actions

    normalized = adapt(raw_plan)

    assert normalized["resources"][0]["action"] == "replace"


@pytest.mark.parametrize(
    ("tree", "message"),
    [("after_unknown", "unknown"), ("after_sensitive", "sensitive")],
)
def test_unknown_or_sensitive_governed_posture_fails_closed(
    tree: str, message: str
) -> None:
    raw_plan = plan()
    raw_plan["resource_changes"][0]["change"][tree] = {"encrypted": True}

    with pytest.raises(TerraformPlanAdapterError, match=message):
        adapt(raw_plan)


def test_literal_selector_is_explicit_and_supported() -> None:
    catalog = inventory()
    catalog["resources"]["aws_db_instance.orders"]["posture"] = posture(
        literal_region=True
    )

    normalized = adapt(catalog=catalog)

    assert normalized["resources"][0]["before"]["region"] == "eu-west-1"


@pytest.mark.parametrize("extra", [False, True])
def test_inventory_must_exactly_cover_managed_resources(extra: bool) -> None:
    catalog = inventory()
    if extra:
        catalog["resources"]["aws_s3_bucket.extra"] = copy.deepcopy(
            catalog["resources"]["aws_instance.api"]
        )
    else:
        del catalog["resources"]["aws_instance.api"]

    with pytest.raises(TerraformPlanAdapterError, match="exactly cover"):
        adapt(catalog=catalog)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(format_version="2.0"), "format version"),
        (lambda value: value.update(errored=True), "errored"),
        (lambda value: value.update(applyable=False), "not applyable"),
        (lambda value: value.update(complete=False), "incomplete"),
        (
            lambda value: value["resource_changes"][0]["change"].update(
                actions=["read"]
            ),
            "actions is unsupported",
        ),
    ],
)
def test_unsupported_or_unusable_plans_fail_closed(mutate, message: str) -> None:
    raw_plan = plan()
    mutate(raw_plan)

    with pytest.raises(TerraformPlanAdapterError, match=message):
        adapt(raw_plan)


def test_invalid_sidecar_value_is_rejected_by_downstream_contract() -> None:
    catalog = inventory()
    catalog["resources"]["aws_db_instance.orders"]["criticality"] = "urgent"

    with pytest.raises(TerraformPlanAdapterError, match="audit contract"):
        adapt(catalog=catalog)


def run_cli(tmp_path: Path, plan_text: str, inventory_text: str):
    plan_path = tmp_path / "tfplan.json"
    inventory_path = tmp_path / "inventory.json"
    output = tmp_path / "normalized.json"
    plan_path.write_text(plan_text, encoding="utf-8")
    inventory_path.write_text(inventory_text, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.terraform_plan_adapter",
            str(plan_path),
            str(inventory_path),
            "--source-revision",
            REVISION,
            "--generated-at",
            "2026-11-08T17:30:00Z",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return result, output


def test_cli_atomically_writes_normalized_plan(tmp_path: Path) -> None:
    result, output = run_cli(tmp_path, json.dumps(plan()), json.dumps(inventory()))

    assert result.returncode == 0
    assert result.stdout == ""
    assert audit_change_plan(json.loads(output.read_text()), now=NOW).accepted


def test_cli_rejects_duplicate_fields_and_symlinks(tmp_path: Path) -> None:
    duplicate = json.dumps(plan()).replace(
        '"format_version": "1.2"',
        '"format_version": "1.2", "format_version": "1.2"',
        1,
    )
    result, output = run_cli(tmp_path, duplicate, json.dumps(inventory()))
    assert result.returncode == 3
    assert json.loads(output.read_text())["error"] == "malformed_evidence"

    plan_path = tmp_path / "real.json"
    plan_path.write_text(json.dumps(plan()), encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(plan_path)
    inventory_path = tmp_path / "inventory-linked.json"
    inventory_path.write_text(json.dumps(inventory()), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.terraform_plan_adapter",
            str(linked),
            str(inventory_path),
            "--source-revision",
            REVISION,
            "--generated-at",
            "2026-11-08T17:30:00Z",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 3
    assert json.loads(completed.stdout)["error"] == "malformed_evidence"
