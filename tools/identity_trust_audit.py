"""Provider-neutral audit for workload identity and emergency access bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUPPORTED_PROVIDERS = frozenset({"aws", "gcp", "azure", "huawei"})
PRINCIPAL_TYPES = frozenset({"workload", "human", "break_glass"})
CREDENTIAL_MODES = frozenset(
    {"federated", "short_lived_token", "interactive", "static_key"}
)
PUBLIC_PRINCIPALS = frozenset(
    {"*", "anonymous", "public", "allusers", "allauthenticatedusers"}
)


@dataclass(frozen=True)
class TrustPolicy:
    max_bindings: int = 10_000
    max_input_bytes: int = 1_000_000
    max_string_chars: int = 512
    privileged_role_patterns: tuple[str, ...] = (
        "administrator",
        "cluster-admin",
        "fullaccess",
        "full_access",
        "roles/owner",
        "tenant administrator",
    )

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("max_bindings", self.max_bindings, 1_000_000),
            ("max_input_bytes", self.max_input_bytes, 100_000_000),
            ("max_string_chars", self.max_string_chars, 10_000),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in [1, {maximum}]")
        if not self.privileged_role_patterns or any(
            not isinstance(pattern, str) or not pattern
            for pattern in self.privileged_role_patterns
        ):
            raise ValueError("privileged role patterns must be non-empty strings")


@dataclass(frozen=True)
class IdentityBinding:
    binding_id: str
    provider: str
    principal: str
    principal_type: str
    role: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    credential_mode: str
    federation_issuer: str | None = None
    federation_subjects: tuple[str, ...] = ()
    expires_at: str | None = None
    approval_ref: str | None = None

    @classmethod
    def from_dict(cls, value: Any, policy: TrustPolicy) -> IdentityBinding:
        if not isinstance(value, dict):
            raise TypeError("each binding must be an object")
        required = {
            "binding_id",
            "provider",
            "principal",
            "principal_type",
            "role",
            "actions",
            "resources",
            "credential_mode",
        }
        optional = {
            "federation_issuer",
            "federation_subjects",
            "expires_at",
            "approval_ref",
        }
        missing = required - value.keys()
        unknown = value.keys() - required - optional
        if missing:
            raise ValueError(f"binding is missing required fields: {sorted(missing)}")
        if unknown:
            raise ValueError(f"binding contains unknown fields: {sorted(unknown)}")

        provider = _bounded_string(value["provider"], "provider", policy).lower()
        principal_type = _bounded_string(
            value["principal_type"], "principal_type", policy
        ).lower()
        credential_mode = _bounded_string(
            value["credential_mode"], "credential_mode", policy
        ).lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unsupported provider: {provider}")
        if principal_type not in PRINCIPAL_TYPES:
            raise ValueError(f"unsupported principal_type: {principal_type}")
        if credential_mode not in CREDENTIAL_MODES:
            raise ValueError(f"unsupported credential_mode: {credential_mode}")

        return cls(
            binding_id=_bounded_string(value["binding_id"], "binding_id", policy),
            provider=provider,
            principal=_bounded_string(value["principal"], "principal", policy),
            principal_type=principal_type,
            role=_bounded_string(value["role"], "role", policy),
            actions=_string_tuple(value["actions"], "actions", policy, required=True),
            resources=_string_tuple(
                value["resources"], "resources", policy, required=True
            ),
            credential_mode=credential_mode,
            federation_issuer=_optional_string(
                value.get("federation_issuer"), "federation_issuer", policy
            ),
            federation_subjects=_string_tuple(
                value.get("federation_subjects", []),
                "federation_subjects",
                policy,
                required=False,
            ),
            expires_at=_optional_time(value.get("expires_at"), policy),
            approval_ref=_optional_string(
                value.get("approval_ref"), "approval_ref", policy
            ),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "actions": list(self.actions),
            "resources": list(self.resources),
            "federation_subjects": list(self.federation_subjects),
        }


@dataclass(frozen=True)
class TrustFinding:
    binding_id: str
    provider: str
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class TrustAuditReport:
    passed: bool
    evaluated_at: str
    binding_count: int
    finding_count: int
    severity_counts: dict[str, int]
    findings: tuple[TrustFinding, ...]
    evidence_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "passed": self.passed,
            "evaluated_at": self.evaluated_at,
            "binding_count": self.binding_count,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence_sha256": self.evidence_sha256,
        }


def audit_identity_trust(
    bindings: list[IdentityBinding],
    *,
    as_of: datetime,
    policy: TrustPolicy | None = None,
) -> TrustAuditReport:
    active = policy or TrustPolicy()
    evaluated_at = _normalized_time(as_of, "as_of")
    if not bindings:
        raise ValueError("at least one identity binding is required")
    if len(bindings) > active.max_bindings:
        raise ValueError("binding count exceeds the configured audit budget")
    binding_ids = [binding.binding_id for binding in bindings]
    if len(binding_ids) != len(set(binding_ids)):
        raise ValueError("binding IDs must be unique")

    findings: list[TrustFinding] = []
    for binding in sorted(bindings, key=lambda item: item.binding_id):
        findings.extend(_audit_binding(binding, as_of, active))
    findings.sort(key=lambda item: (item.binding_id, item.code))

    severity_counts = {
        severity: sum(finding.severity == severity for finding in findings)
        for severity in ("critical", "high", "medium")
    }
    evidence = {
        "schema_version": 1,
        "evaluated_at": evaluated_at,
        "policy": asdict(active),
        "bindings": [
            binding.canonical_dict()
            for binding in sorted(bindings, key=lambda item: item.binding_id)
        ],
        "findings": [finding.to_dict() for finding in findings],
    }
    evidence_sha256 = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return TrustAuditReport(
        passed=not findings,
        evaluated_at=evaluated_at,
        binding_count=len(bindings),
        finding_count=len(findings),
        severity_counts=severity_counts,
        findings=tuple(findings),
        evidence_sha256=evidence_sha256,
    )


def load_bindings(
    path: Path, policy: TrustPolicy | None = None
) -> list[IdentityBinding]:
    active = policy or TrustPolicy()
    payload = path.read_bytes()
    if len(payload) > active.max_input_bytes:
        raise ValueError("input exceeds the configured byte budget")
    document = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(document, dict) or set(document) != {"bindings"}:
        raise ValueError("input must contain exactly one bindings field")
    raw_bindings = document["bindings"]
    if not isinstance(raw_bindings, list):
        raise TypeError("bindings must be an array")
    if len(raw_bindings) > active.max_bindings:
        raise ValueError("binding count exceeds the configured audit budget")
    return [IdentityBinding.from_dict(value, active) for value in raw_bindings]


def _audit_binding(
    binding: IdentityBinding,
    as_of: datetime,
    policy: TrustPolicy,
) -> list[TrustFinding]:
    findings: list[TrustFinding] = []

    def add(code: str, severity: str, message: str) -> None:
        findings.append(
            TrustFinding(binding.binding_id, binding.provider, code, severity, message)
        )

    if (
        binding.principal.strip().lower() in PUBLIC_PRINCIPALS
        or "*" in binding.principal
    ):
        add(
            "PUBLIC_OR_WILDCARD_PRINCIPAL",
            "critical",
            "principal is public or wildcarded",
        )
    if any("*" in action for action in binding.actions):
        add("WILDCARD_ACTION", "high", "one or more actions contain a wildcard")
    if any("*" in resource for resource in binding.resources):
        add("WILDCARD_RESOURCE", "high", "one or more resources contain a wildcard")
    if binding.credential_mode == "static_key":
        add("STATIC_CREDENTIAL", "high", "binding relies on a static credential")

    if binding.principal_type == "workload":
        role = binding.role.lower()
        if role in {"admin", "owner"} or any(
            pattern.lower() in role for pattern in policy.privileged_role_patterns
        ):
            add(
                "PRIVILEGED_WORKLOAD_ROLE",
                "critical",
                "workload identity receives a privileged role",
            )
        if binding.credential_mode == "interactive":
            add(
                "INTERACTIVE_WORKLOAD_CREDENTIAL",
                "high",
                "workload identity relies on an interactive credential mode",
            )
        if binding.credential_mode == "federated":
            if not binding.federation_issuer:
                add(
                    "MISSING_FEDERATION_ISSUER",
                    "high",
                    "federated workload has no bounded issuer",
                )
            if not binding.federation_subjects:
                add(
                    "MISSING_FEDERATION_SUBJECT",
                    "high",
                    "federated workload has no subject constraint",
                )
            elif any("*" in subject for subject in binding.federation_subjects):
                add(
                    "BROAD_FEDERATION_SUBJECT",
                    "high",
                    "federation subject contains a wildcard",
                )

    if binding.principal_type == "break_glass":
        if not binding.approval_ref:
            add(
                "BREAK_GLASS_WITHOUT_APPROVAL",
                "medium",
                "break-glass binding has no approval reference",
            )
        if not binding.expires_at:
            add(
                "BREAK_GLASS_WITHOUT_EXPIRY",
                "high",
                "break-glass binding has no expiry",
            )
        elif _parse_time(binding.expires_at, "expires_at") <= as_of.astimezone(UTC):
            add(
                "EXPIRED_BREAK_GLASS_BINDING",
                "high",
                "break-glass binding is expired but still present",
            )

    return findings


def _bounded_string(value: Any, name: str, policy: TrustPolicy) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > policy.max_string_chars
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _optional_string(value: Any, name: str, policy: TrustPolicy) -> str | None:
    return None if value is None else _bounded_string(value, name, policy)


def _string_tuple(
    value: Any,
    name: str,
    policy: TrustPolicy,
    *,
    required: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (required and not value):
        qualifier = "a non-empty" if required else "an"
        raise ValueError(f"{name} must be {qualifier} array")
    items = tuple(_bounded_string(item, name, policy) for item in value)
    if len(items) != len(set(items)):
        raise ValueError(f"{name} entries must be unique")
    return tuple(sorted(items))


def _optional_time(value: Any, policy: TrustPolicy) -> str | None:
    if value is None:
        return None
    raw = _bounded_string(value, "expires_at", policy)
    return _normalized_time(_parse_time(raw, "expires_at"), "expires_at")


def _parse_time(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone offset")
    return parsed.astimezone(UTC)


def _normalized_time(value: datetime, name: str) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def write_report(report: TrustAuditReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(report.to_dict(), temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit normalized cloud identity trust bindings"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--as-of", required=True, help="timezone-aware ISO-8601 evaluation time"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        as_of = _parse_time(args.as_of, "as_of")
        bindings = load_bindings(args.input)
        report = audit_identity_trust(bindings, as_of=as_of)
        write_report(report, args.output)
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        print(f"identity trust audit failed: {exc}", file=sys.stderr)
        return 3

    print(
        json.dumps(
            {
                "passed": report.passed,
                "binding_count": report.binding_count,
                "finding_count": report.finding_count,
                "evidence_sha256": report.evidence_sha256,
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
