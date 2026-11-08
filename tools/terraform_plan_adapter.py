from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from tools.change_risk_audit import ChangeRiskError, parse_plan

ADAPTER_SCHEMA_VERSION = "terraform-plan-adapter/v1"
MAX_PLAN_BYTES = 16 * 1024 * 1024
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_RESOURCES = 1_024
MAX_POINTER_BYTES = 512
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORMAT_VERSION_RE = re.compile(r"^1\.[0-9]+$")
STATE_FIELDS = {
    "region",
    "failure_domain",
    "public_access",
    "encrypted",
    "multi_zone",
    "deletion_protection",
    "privilege_scope",
}
INVENTORY_FIELDS = {
    "kind",
    "criticality",
    "data_class",
    "depends_on",
    "change_ticket",
    "approval_digest",
    "backup_verified_at",
    "replacement_ready",
    "posture",
}
ACTION_MAP = {
    ("no-op",): "no_op",
    ("create",): "create",
    ("update",): "update",
    ("delete",): "delete",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}


class TerraformPlanAdapterError(ValueError):
    """Raw plan or reviewed inventory cannot be normalized safely."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TerraformPlanAdapterError("input contains a non-canonical value") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TerraformPlanAdapterError("JSON contains duplicate fields")
        result[key] = value
    return result


def _load_json(path: Path, byte_limit: int) -> object:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TerraformPlanAdapterError("input file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TerraformPlanAdapterError("input must be a regular file")
        if not 1 <= metadata.st_size <= byte_limit:
            raise TerraformPlanAdapterError("input exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = byte_limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != metadata.st_size
            or len(payload) > byte_limit
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or metadata.st_ctime_ns != after.st_ctime_ns
        ):
            raise TerraformPlanAdapterError("input changed while being read")
    finally:
        os.close(descriptor)
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                TerraformPlanAdapterError("JSON contains a non-finite number")
            ),
        )
    except TerraformPlanAdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TerraformPlanAdapterError("input is not valid UTF-8 JSON") from exc


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TerraformPlanAdapterError(f"{path} must be an object")
    return value


def _array(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        raise TerraformPlanAdapterError(f"{path} must be an array")
    return value


def _exact_fields(value: dict[str, object], fields: set[str], path: str) -> None:
    if set(value) != fields:
        raise TerraformPlanAdapterError(f"{path} has missing or unexpected fields")


def _pointer_segments(pointer: object, path: str) -> tuple[str, ...]:
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or len(pointer.encode("utf-8")) > MAX_POINTER_BYTES
    ):
        raise TerraformPlanAdapterError(f"{path} must be a bounded JSON pointer")
    segments: list[str] = []
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise TerraformPlanAdapterError(f"{path} has invalid JSON pointer escaping")
        segment = raw.replace("~1", "/").replace("~0", "~")
        if not segment:
            raise TerraformPlanAdapterError(f"{path} contains an empty segment")
        segments.append(segment)
    if not 1 <= len(segments) <= 16:
        raise TerraformPlanAdapterError(f"{path} exceeds the pointer depth limit")
    return tuple(segments)


def _walk(value: object, segments: tuple[str, ...], path: str) -> object:
    current = value
    for segment in segments:
        if isinstance(current, dict):
            if segment not in current:
                raise TerraformPlanAdapterError(f"{path} does not resolve")
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isascii() or not segment.isdecimal():
                raise TerraformPlanAdapterError(f"{path} has an invalid array index")
            index = int(segment)
            if index >= len(current):
                raise TerraformPlanAdapterError(f"{path} does not resolve")
            current = current[index]
        else:
            raise TerraformPlanAdapterError(f"{path} does not resolve")
    return current


def _flagged(tree: object, segments: tuple[str, ...]) -> bool:
    current = tree
    if current is True:
        return True
    for segment in segments:
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, list) and segment.isascii() and segment.isdecimal():
            index = int(segment)
            current = current[index] if index < len(current) else None
        else:
            return False
        if current is True:
            return True
    return False


def _selector_value(
    selector: object,
    state: object,
    *,
    unknown: object,
    sensitive: object,
    path: str,
) -> object:
    raw = _object(selector, path)
    if set(raw) == {"literal"}:
        return raw["literal"]
    if set(raw) != {"path"}:
        raise TerraformPlanAdapterError(f"{path} must contain path or literal")
    segments = _pointer_segments(raw["path"], f"{path}.path")
    if _flagged(unknown, segments):
        raise TerraformPlanAdapterError(f"{path} resolves to an unknown value")
    if _flagged(sensitive, segments):
        raise TerraformPlanAdapterError(f"{path} resolves to a sensitive value")
    return _walk(state, segments, path)


def _normalized_state(
    state: object,
    selectors: object,
    *,
    unknown: object,
    sensitive: object,
    path: str,
) -> dict[str, object]:
    if state is None:
        raise TerraformPlanAdapterError(f"{path} state is missing")
    posture = _object(selectors, f"{path}.posture")
    _exact_fields(posture, STATE_FIELDS, f"{path}.posture")
    return {
        field: _selector_value(
            posture[field],
            state,
            unknown=unknown,
            sensitive=sensitive,
            path=f"{path}.posture.{field}",
        )
        for field in sorted(STATE_FIELDS)
    }


def _managed_changes(plan: dict[str, object]) -> dict[str, dict[str, object]]:
    raw_changes = _array(plan.get("resource_changes"), "plan.resource_changes")
    if len(raw_changes) > MAX_RESOURCES * 2:
        raise TerraformPlanAdapterError("resource change budget exceeded")
    changes: dict[str, dict[str, object]] = {}
    for index, item in enumerate(raw_changes):
        path = f"plan.resource_changes[{index}]"
        raw = _object(item, path)
        mode = raw.get("mode")
        if mode == "data":
            continue
        if mode != "managed":
            raise TerraformPlanAdapterError(f"{path}.mode is unsupported")
        address = raw.get("address")
        if not isinstance(address, str) or not address or len(address) > 192:
            raise TerraformPlanAdapterError(f"{path}.address is invalid")
        if raw.get("deposed") is not None:
            raise TerraformPlanAdapterError("deposed resource changes are unsupported")
        if address in changes:
            raise TerraformPlanAdapterError("managed resource addresses must be unique")
        changes[address] = raw
    if not 1 <= len(changes) <= MAX_RESOURCES:
        raise TerraformPlanAdapterError("plan must contain 1-1024 managed resources")
    return changes


def adapt_terraform_plan(
    plan: object,
    inventory: object,
    *,
    source_revision: str,
    generated_at: datetime,
) -> dict[str, object]:
    raw_plan = _object(plan, "plan")
    if (
        not isinstance(raw_plan.get("format_version"), str)
        or FORMAT_VERSION_RE.fullmatch(raw_plan["format_version"]) is None
    ):
        raise TerraformPlanAdapterError("unsupported Terraform JSON format version")
    if raw_plan.get("errored") is not False:
        raise TerraformPlanAdapterError("errored plans cannot be adapted")
    if raw_plan.get("applyable") is not True:
        raise TerraformPlanAdapterError("plan is not applyable")
    if raw_plan.get("complete") is not True:
        raise TerraformPlanAdapterError("incomplete plans cannot be adapted")
    if "prior_state" not in raw_plan:
        raise TerraformPlanAdapterError("plan.prior_state is required")
    if (
        not isinstance(source_revision, str)
        or SHA256_RE.fullmatch(source_revision) is None
    ):
        raise TerraformPlanAdapterError("source revision must be a lowercase SHA-256")
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise TerraformPlanAdapterError("generated_at must be timezone-aware")

    catalog = _object(inventory, "inventory")
    _exact_fields(catalog, {"schema_version", "resources"}, "inventory")
    if catalog["schema_version"] != ADAPTER_SCHEMA_VERSION:
        raise TerraformPlanAdapterError("unsupported inventory schema")
    entries = _object(catalog["resources"], "inventory.resources")
    changes = _managed_changes(raw_plan)
    if set(entries) != set(changes):
        raise TerraformPlanAdapterError(
            "inventory must exactly cover all managed resource changes"
        )

    normalized: list[dict[str, object]] = []
    for address in sorted(changes):
        change_record = changes[address]
        metadata = _object(entries[address], f"inventory.resources[{address!r}]")
        _exact_fields(metadata, INVENTORY_FIELDS, f"inventory.resources[{address!r}]")
        change = _object(change_record.get("change"), f"plan.change[{address!r}]")
        raw_actions = _array(change.get("actions"), f"plan.change[{address!r}].actions")
        if not all(isinstance(item, str) for item in raw_actions):
            raise TerraformPlanAdapterError(
                f"plan.change[{address!r}].actions is unsupported"
            )
        actions = tuple(raw_actions)
        if actions not in ACTION_MAP:
            raise TerraformPlanAdapterError(
                f"plan.change[{address!r}].actions is unsupported"
            )
        action = ACTION_MAP[actions]
        before = change.get("before")
        after = change.get("after")
        if before is not None:
            _object(before, f"plan.change[{address!r}].before")
        if after is not None:
            _object(after, f"plan.change[{address!r}].after")
        after_unknown = change.get("after_unknown", {})
        before_sensitive = change.get("before_sensitive", {})
        after_sensitive = change.get("after_sensitive", {})
        _object(after_unknown, f"plan.change[{address!r}].after_unknown")
        _object(before_sensitive, f"plan.change[{address!r}].before_sensitive")
        _object(after_sensitive, f"plan.change[{address!r}].after_sensitive")
        if action == "create" and (before is not None or after is None):
            raise TerraformPlanAdapterError("create state shape is invalid")
        if action == "delete" and (before is None or after is not None):
            raise TerraformPlanAdapterError("delete state shape is invalid")
        if action in {"no_op", "update", "replace"} and (
            before is None or after is None
        ):
            raise TerraformPlanAdapterError(f"{action} state shape is invalid")

        before_state = None
        after_state = None
        if before is not None:
            before_state = _normalized_state(
                before,
                metadata["posture"],
                unknown={},
                sensitive=before_sensitive,
                path=f"before[{address!r}]",
            )
        if after is not None:
            after_state = _normalized_state(
                after,
                metadata["posture"],
                unknown=after_unknown,
                sensitive=after_sensitive,
                path=f"after[{address!r}]",
            )
        normalized.append(
            {
                "id": address,
                "kind": metadata["kind"],
                "criticality": metadata["criticality"],
                "data_class": metadata["data_class"],
                "action": action,
                "depends_on": metadata["depends_on"],
                "before": before_state,
                "after": after_state,
                "change_ticket": metadata["change_ticket"],
                "approval_digest": metadata["approval_digest"],
                "backup_verified_at": metadata["backup_verified_at"],
                "replacement_ready": metadata["replacement_ready"],
            }
        )

    identity_plan = dict(raw_plan)
    identity_plan["resource_changes"] = sorted(
        _array(raw_plan["resource_changes"], "plan.resource_changes"),
        key=lambda item: (
            str(item.get("mode", "")) if isinstance(item, dict) else "",
            str(item.get("address", "")) if isinstance(item, dict) else "",
            str(item.get("deposed", "")) if isinstance(item, dict) else "",
            _digest(item),
        ),
    )
    plan_digest = _digest({"plan": identity_plan, "inventory": catalog})
    result: dict[str, object] = {
        "generated_at": generated_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "plan_id": f"tfplan-{plan_digest[:32]}",
        "source_revision": source_revision,
        "state_snapshot_digest": _digest(raw_plan["prior_state"]),
        "resources": normalized,
    }
    try:
        parse_plan(result)
    except ChangeRiskError as exc:
        raise TerraformPlanAdapterError(
            f"normalized plan violates the audit contract: {exc}"
        ) from exc
    return result


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TerraformPlanAdapterError("generated_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TerraformPlanAdapterError("generated_at must include a timezone")
    return parsed


def _write_json(value: object, output: Path | None) -> None:
    payload = _canonical_json(value) + b"\n"
    if output is None:
        print(payload.decode("utf-8"), end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize Terraform/OpenTofu show -json for the change-risk gate"
    )
    parser.add_argument("plan", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        normalized = adapt_terraform_plan(
            _load_json(arguments.plan, MAX_PLAN_BYTES),
            _load_json(arguments.inventory, MAX_INVENTORY_BYTES),
            source_revision=arguments.source_revision,
            generated_at=_timestamp(arguments.generated_at),
        )
        _write_json(normalized, arguments.output)
    except (OSError, TerraformPlanAdapterError) as exc:
        _write_json(
            {"accepted": False, "error": "malformed_evidence", "detail": str(exc)},
            arguments.output,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
