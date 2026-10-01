from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tools.change_risk_audit import (
    ChangeRiskError,
    ChangeRiskPolicy,
    audit_change_plan,
    load_plan,
    parse_plan,
)

NOW = datetime(2026, 10, 1, 13, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def state(
    *,
    region: str = "eu-west",
    failure_domain: str = "eu-west-a",
    public_access: bool = False,
    encrypted: bool = True,
    multi_zone: bool = True,
    deletion_protection: bool = True,
    privilege_scope: str = "scoped",
) -> dict:
    return {
        "region": region,
        "failure_domain": failure_domain,
        "public_access": public_access,
        "encrypted": encrypted,
        "multi_zone": multi_zone,
        "deletion_protection": deletion_protection,
        "privilege_scope": privilege_scope,
    }


def resource(
    resource_id: str,
    *,
    kind: str = "compute",
    criticality: str = "standard",
    data_class: str = "none",
    action: str = "no_op",
    depends_on: list[str] | None = None,
    before: dict | None = None,
    after: dict | None = None,
    change_ticket: str | None = None,
    approval_digest: str | None = None,
    backup_verified_at: str | None = None,
    replacement_ready: bool = False,
) -> dict:
    before = state() if before is None and action != "create" else before
    after = copy.deepcopy(before) if after is None and action != "delete" else after
    return {
        "id": resource_id,
        "kind": kind,
        "criticality": criticality,
        "data_class": data_class,
        "action": action,
        "depends_on": depends_on or [],
        "before": before,
        "after": after,
        "change_ticket": change_ticket,
        "approval_digest": approval_digest,
        "backup_verified_at": backup_verified_at,
        "replacement_ready": replacement_ready,
    }


def valid_plan() -> dict:
    database_before = state(failure_domain="data-a")
    database_after = state(failure_domain="data-a")
    return {
        "generated_at": "2026-10-01T13:00:00Z",
        "plan_id": "plan-prod-42",
        "source_revision": DIGEST_A,
        "state_snapshot_digest": DIGEST_B,
        "resources": [
            resource("network", kind="network"),
            resource(
                "database",
                kind="database",
                criticality="critical",
                data_class="persistent",
                action="update",
                depends_on=["network"],
                before=database_before,
                after=database_after,
            ),
            resource(
                "api",
                criticality="critical",
                depends_on=["database", "network"],
                before=state(failure_domain="app-a"),
            ),
            resource(
                "worker",
                criticality="important",
                depends_on=["database"],
                before=state(failure_domain="app-b"),
            ),
        ],
    }


def permissive_policy(**overrides) -> ChangeRiskPolicy:
    values = {
        "max_changed_resources": 1_024,
        "max_critical_impacted": 1_024,
        "max_changes_per_failure_domain": 1_024,
    }
    values.update(overrides)
    return ChangeRiskPolicy(**values)


def test_safe_update_is_accepted_with_transitive_blast_radius() -> None:
    report = audit_change_plan(valid_plan(), now=NOW)

    assert report.accepted
    assert report.changed_resource_count == 1
    assert report.critical_changed_count == 1
    assert report.critical_impacted_count == 2
    assert report.maximum_resource_blast_radius == 3
    assert report.findings == ()


def test_resource_order_and_dependency_order_are_canonical() -> None:
    original = valid_plan()
    permuted = copy.deepcopy(original)
    permuted["resources"].reverse()
    for item in permuted["resources"]:
        item["depends_on"].reverse()

    original_report = audit_change_plan(original, now=NOW)
    permuted_report = audit_change_plan(permuted, now=NOW)

    assert original_report.to_dict() == permuted_report.to_dict()


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("encrypted", "encryption_removed"),
        ("deletion_protection", "deletion_protection_removed"),
        ("multi_zone", "multi_zone_resilience_removed"),
    ],
)
def test_security_regressions_fail_closed(field: str, code: str) -> None:
    payload = valid_plan()
    database = payload["resources"][1]
    database["after"][field] = False

    report = audit_change_plan(payload, now=NOW)

    assert not report.accepted
    assert code in report.reasons
    assert report.security_regression_count == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item["after"].update(public_access=True),
        lambda item: item["after"].update(privilege_scope="account"),
        lambda item: item["after"].update(region="eu-central"),
    ],
)
def test_high_risk_changes_require_ticket_and_approval_digest(mutate) -> None:
    payload = valid_plan()
    changed = payload["resources"][1]
    mutate(changed)

    rejected = audit_change_plan(payload, now=NOW)
    changed["change_ticket"] = "CHG-1234"
    changed["approval_digest"] = DIGEST_C
    accepted = audit_change_plan(payload, now=NOW)

    assert "missing_change_approval" in rejected.reasons
    assert accepted.accepted


def test_persistent_replace_requires_backup_replacement_and_approval() -> None:
    payload = valid_plan()
    database = payload["resources"][1]
    database.update(action="replace")

    report = audit_change_plan(payload, now=NOW)

    assert set(report.reasons) == {
        "missing_change_approval",
        "missing_verified_backup",
        "replacement_not_ready",
    }
    assert report.destructive_persistent_count == 1


def test_persistent_replace_with_fresh_evidence_is_accepted() -> None:
    payload = valid_plan()
    database = payload["resources"][1]
    database.update(
        action="replace",
        change_ticket="CHG-1234",
        approval_digest=DIGEST_C,
        backup_verified_at="2026-09-30T13:00:00Z",
        replacement_ready=True,
    )

    report = audit_change_plan(payload, now=NOW)

    assert report.accepted
    assert report.destructive_persistent_count == 1


def test_stale_and_future_backup_evidence_are_rejected() -> None:
    stale = valid_plan()
    future = valid_plan()
    for payload, timestamp in (
        (stale, "2026-09-20T13:00:00Z"),
        (future, "2026-10-01T13:01:01Z"),
    ):
        payload["resources"][1].update(
            action="replace",
            change_ticket="CHG-1234",
            approval_digest=DIGEST_C,
            backup_verified_at=timestamp,
            replacement_ready=True,
        )

    stale_report = audit_change_plan(stale, now=NOW)
    future_report = audit_change_plan(future, now=NOW)

    assert "stale_verified_backup" in stale_report.reasons
    assert "future_backup_evidence" in future_report.reasons


def test_change_batch_and_failure_domain_budgets_are_independent() -> None:
    payload = valid_plan()
    payload["resources"][0]["action"] = "update"
    report = audit_change_plan(
        payload,
        now=NOW,
        policy=ChangeRiskPolicy(
            max_changed_resources=1,
            max_changes_per_failure_domain=1,
        ),
    )

    assert "change_batch_limit_exceeded" in report.reasons
    assert "failure_domain_change_concentration" not in report.reasons

    payload["resources"][0]["before"]["failure_domain"] = "data-a"
    payload["resources"][0]["after"]["failure_domain"] = "data-a"
    concentrated = audit_change_plan(
        payload,
        now=NOW,
        policy=permissive_policy(max_changes_per_failure_domain=1),
    )
    assert "failure_domain_change_concentration" in concentrated.reasons


def test_critical_transitive_blast_radius_is_gated() -> None:
    report = audit_change_plan(
        valid_plan(),
        now=NOW,
        policy=permissive_policy(max_critical_impacted=1),
    )

    assert report.reasons == ("critical_blast_radius_exceeded",)
    assert report.critical_impacted_count == 2


def test_stale_and_future_plan_evidence_are_rejected() -> None:
    stale = audit_change_plan(
        valid_plan(),
        now=NOW + timedelta(seconds=101),
        policy=ChangeRiskPolicy(max_age_seconds=100),
    )
    future = audit_change_plan(
        valid_plan(),
        now=NOW - timedelta(seconds=61),
        policy=ChangeRiskPolicy(max_future_skew_seconds=60),
    )

    assert stale.reasons == ("stale_plan_evidence",)
    assert future.reasons == ("future_plan_evidence",)


def test_report_does_not_expose_resource_or_plan_identifiers() -> None:
    report = audit_change_plan(valid_plan(), now=NOW)
    rendered = json.dumps(report.to_dict())

    assert "plan-prod-42" not in rendered
    assert "database" not in rendered
    assert "api" not in rendered
    assert "worker" not in rendered


def test_finding_report_is_bounded_without_losing_total_count() -> None:
    payload = valid_plan()
    payload["resources"] = []
    for index in range(1_024):
        before = state(failure_domain=f"zone-{index:04d}")
        after = state(
            failure_domain=f"zone-{index:04d}",
            encrypted=False,
            multi_zone=False,
            deletion_protection=False,
        )
        payload["resources"].append(
            resource(
                f"database-{index:04d}",
                kind="database",
                criticality="critical",
                data_class="persistent",
                action="update",
                before=before,
                after=after,
            )
        )

    report = audit_change_plan(payload, now=NOW, policy=permissive_policy())

    assert report.finding_count == 3_072
    assert len(report.findings) == 2_048
    assert report.findings_truncated


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra=True), "missing or unexpected"),
        (lambda value: value["resources"].append(value["resources"][0]), "unique"),
        (
            lambda value: value["resources"][0]["depends_on"].append("missing"),
            "declared",
        ),
        (
            lambda value: value["resources"][0].update(action="create"),
            "create requires",
        ),
        (lambda value: value["resources"][0]["before"].update(encrypted=1), "boolean"),
        (lambda value: value.update(source_revision="A" * 64), "lowercase SHA-256"),
        (lambda value: value.update(generated_at="2026-10-01"), "timezone"),
    ],
)
def test_malformed_evidence_fails_closed(mutate, message: str) -> None:
    payload = valid_plan()
    mutate(payload)

    with pytest.raises(ChangeRiskError, match=message):
        parse_plan(payload)


def test_dependency_cycle_fails_closed() -> None:
    payload = valid_plan()
    payload["resources"][0]["depends_on"] = ["api"]

    with pytest.raises(ChangeRiskError, match="acyclic"):
        parse_plan(payload)


def test_all_no_op_plan_fails_closed() -> None:
    payload = valid_plan()
    payload["resources"][1]["action"] = "no_op"

    with pytest.raises(ChangeRiskError, match="at least one change"):
        parse_plan(payload)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_age_seconds": -1},
        {"max_changed_resources": 0},
        {"max_critical_impacted": True},
        {"max_changes_per_failure_domain": 0},
    ],
)
def test_invalid_policies_fail_closed(kwargs: dict) -> None:
    with pytest.raises(ChangeRiskError):
        ChangeRiskPolicy(**kwargs)


def test_load_rejects_duplicate_json_and_non_finite_values(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    non_finite = tmp_path / "nan.json"
    duplicate.write_text('{"generated_at":"x","generated_at":"y"}', encoding="utf-8")
    non_finite.write_text('{"generated_at":NaN}', encoding="utf-8")

    with pytest.raises(ChangeRiskError, match="duplicate"):
        load_plan(duplicate)
    with pytest.raises(ChangeRiskError, match="non-finite"):
        load_plan(non_finite)


def test_load_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "plan.json"
    target.write_text(json.dumps(valid_plan()), encoding="utf-8")
    link = tmp_path / "linked.json"
    link.symlink_to(target)

    with pytest.raises(ChangeRiskError, match="symbolic link"):
        load_plan(link)


def run_cli(
    tmp_path: Path, raw: str, *arguments: str
) -> subprocess.CompletedProcess[str]:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(raw, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.change_risk_audit",
            str(plan_path),
            "--now",
            "2026-10-01T13:00:05Z",
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_accepts_and_atomically_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "reports" / "change-risk.json"
    completed = run_cli(tmp_path, json.dumps(valid_plan()), "--output", str(output))

    assert completed.returncode == 0
    assert completed.stdout == ""
    assert json.loads(output.read_text(encoding="utf-8"))["accepted"] is True


def test_cli_separates_policy_rejection_from_malformed_evidence(tmp_path: Path) -> None:
    rejected = valid_plan()
    rejected["resources"][1]["after"]["encrypted"] = False

    policy_result = run_cli(tmp_path, json.dumps(rejected))
    malformed_result = run_cli(tmp_path, "not-json")

    assert policy_result.returncode == 2
    assert json.loads(policy_result.stdout)["accepted"] is False
    assert malformed_result.returncode == 3
    assert json.loads(malformed_result.stdout)["error"] == "malformed_evidence"
