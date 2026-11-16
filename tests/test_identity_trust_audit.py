from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest

from tools.identity_trust_audit import (
    IdentityBinding,
    TrustPolicy,
    audit_identity_trust,
    load_bindings,
    main,
)

AS_OF = datetime(2026, 11, 16, 8, tzinfo=UTC)


def binding(**overrides):
    value = {
        "binding_id": "deploy-main",
        "provider": "aws",
        "principal": "arn:aws:iam::123456789012:role/deploy-main",
        "principal_type": "workload",
        "role": "deployment-reader",
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::release-bucket/main/model.tar"],
        "credential_mode": "federated",
        "federation_issuer": "https://token.actions.githubusercontent.com",
        "federation_subjects": ["repo:example/service:ref:refs/heads/main"],
    }
    value.update(overrides)
    return value


def parsed(*values):
    policy = TrustPolicy()
    return [IdentityBinding.from_dict(value, policy) for value in values]


def test_bounded_federated_workload_passes_deterministically():
    human = binding(
        binding_id="human-reviewer",
        principal="user:reviewer@example.com",
        principal_type="human",
        role="audit-viewer",
        actions=["logs:Read"],
        resources=["project:fraud-prod"],
        credential_mode="interactive",
        federation_issuer=None,
        federation_subjects=[],
    )
    first = audit_identity_trust(parsed(binding(), human), as_of=AS_OF)
    second = audit_identity_trust(parsed(human, binding()), as_of=AS_OF)

    assert first.passed
    assert first.findings == ()
    assert first.evidence_sha256 == second.evidence_sha256
    assert first.to_dict()["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
    }


def test_public_privileged_static_binding_fails_with_stable_codes():
    risky = binding(
        principal="*",
        role="AdministratorAccess",
        actions=["s3:*"],
        resources=["*"],
        credential_mode="static_key",
    )
    report = audit_identity_trust(parsed(risky), as_of=AS_OF)

    assert not report.passed
    assert [finding.code for finding in report.findings] == [
        "PRIVILEGED_WORKLOAD_ROLE",
        "PUBLIC_OR_WILDCARD_PRINCIPAL",
        "STATIC_CREDENTIAL",
        "WILDCARD_ACTION",
        "WILDCARD_RESOURCE",
    ]
    serialized = json.dumps(report.to_dict())
    assert "arn:aws:iam" not in serialized
    assert len(report.evidence_sha256) == 64


def test_federation_constraints_and_break_glass_lifecycle_are_audited():
    broad = binding(
        binding_id="broad-federation",
        federation_issuer=None,
        federation_subjects=["repo:example/*"],
    )
    emergency = binding(
        binding_id="break-glass",
        principal="user:on-call@example.com",
        principal_type="break_glass",
        role="incident-operator",
        actions=["compute:Restart"],
        resources=["service:payments"],
        credential_mode="short_lived_token",
        federation_issuer=None,
        federation_subjects=[],
        expires_at="2026-11-16T07:59:59Z",
        approval_ref=None,
    )
    codes = {
        finding.code
        for finding in audit_identity_trust(
            parsed(broad, emergency), as_of=AS_OF
        ).findings
    }

    assert codes == {
        "BROAD_FEDERATION_SUBJECT",
        "MISSING_FEDERATION_ISSUER",
        "BREAK_GLASS_WITHOUT_APPROVAL",
        "EXPIRED_BREAK_GLASS_BINDING",
    }


def test_input_contract_rejects_duplicates_unknown_fields_and_budget_overrun(tmp_path):
    duplicate_key = tmp_path / "duplicate.json"
    duplicate_key.write_text('{"bindings": [], "bindings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON field"):
        load_bindings(duplicate_key)

    with pytest.raises(ValueError, match="unknown fields"):
        IdentityBinding.from_dict({**binding(), "surprise": True}, TrustPolicy())

    duplicates = parsed(binding(), binding())
    with pytest.raises(ValueError, match="binding IDs must be unique"):
        audit_identity_trust(duplicates, as_of=AS_OF)

    with pytest.raises(ValueError, match="at least one"):
        audit_identity_trust([], as_of=AS_OF)

    too_many = parsed(binding(), binding(binding_id="second"))
    with pytest.raises(ValueError, match="audit budget"):
        audit_identity_trust(
            too_many,
            as_of=AS_OF,
            policy=TrustPolicy(max_bindings=1),
        )


def test_interactive_workload_credentials_fail_closed():
    report = audit_identity_trust(
        parsed(binding(credential_mode="interactive")), as_of=AS_OF
    )

    assert [finding.code for finding in report.findings] == [
        "INTERACTIVE_WORKLOAD_CREDENTIAL"
    ]


def test_cli_writes_private_atomic_report_and_uses_distinct_exit_codes(
    tmp_path, capsys
):
    input_path = tmp_path / "bindings.json"
    output_path = tmp_path / "report.json"
    input_path.write_text(json.dumps({"bindings": [binding()]}), encoding="utf-8")

    assert (
        main(
            [
                str(input_path),
                "--as-of",
                "2026-11-16T08:00:00Z",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    assert json.loads(output_path.read_text(encoding="utf-8"))["passed"] is True
    assert os.stat(output_path).st_mode & 0o777 == 0o600

    input_path.write_text(
        json.dumps({"bindings": [binding(principal="*")]}), encoding="utf-8"
    )
    assert (
        main(
            [
                str(input_path),
                "--as-of",
                "2026-11-16T08:00:00Z",
                "--output",
                str(output_path),
            ]
        )
        == 2
    )

    input_path.write_text("not-json", encoding="utf-8")
    assert (
        main(
            [
                str(input_path),
                "--as-of",
                "2026-11-16T08:00:00Z",
                "--output",
                str(output_path),
            ]
        )
        == 3
    )
    assert "identity trust audit failed" in capsys.readouterr().err
