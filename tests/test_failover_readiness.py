from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from tools.failover_readiness import EvidenceError, Policy, audit, load_manifest

NOW = datetime(2026, 9, 28, 5, 0, tzinfo=UTC)


def valid_manifest() -> dict:
    return {
        "schema_version": 1,
        "rehearsal_id": "game-day-2026-09",
        "primary_region": "region-a",
        "recovery_region": "region-b",
        "started_at": "2026-09-27T04:00:00Z",
        "completed_at": "2026-09-27T04:15:00Z",
        "traffic_switch_budget_seconds": 120,
        "measured_traffic_switch_seconds": 42,
        "components": [
            {
                "name": "database",
                "tier": "critical",
                "recovery_mode": "hot_standby",
                "dependencies": [],
                "recovery_order": 1,
                "target_rto_seconds": 60,
                "measured_rto_seconds": 40,
                "target_rpo_seconds": 10,
                "measured_rpo_seconds": 4,
                "required_capacity": 100,
                "recovery_capacity": 100,
                "validation_passed": True,
            },
            {
                "name": "api",
                "tier": "critical",
                "recovery_mode": "warm_standby",
                "dependencies": ["database"],
                "recovery_order": 2,
                "target_rto_seconds": 120,
                "measured_rto_seconds": 70,
                "target_rpo_seconds": 10,
                "measured_rpo_seconds": 0,
                "required_capacity": 200,
                "recovery_capacity": 180,
                "validation_passed": True,
            },
            {
                "name": "analytics",
                "tier": "supporting",
                "recovery_mode": "unavailable",
                "dependencies": ["database"],
                "recovery_order": 3,
                "target_rto_seconds": 3600,
                "measured_rto_seconds": 0,
                "target_rpo_seconds": 3600,
                "measured_rpo_seconds": 0,
                "required_capacity": 10,
                "recovery_capacity": 0,
                "validation_passed": False,
            },
        ],
    }


class AuditTests(unittest.TestCase):
    def audit(self, manifest: dict, policy: Policy | None = None) -> dict:
        return audit(manifest, policy or Policy(), now=NOW)

    def test_accepts_complete_dependency_closure(self) -> None:
        report = self.audit(valid_manifest())
        self.assertTrue(report["accepted"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["component_count"], 3)
        self.assertEqual(len(report["evidence_digest"]), 64)

    def test_report_is_deterministic_and_order_independent(self) -> None:
        first = valid_manifest()
        second = deepcopy(first)
        second["components"].reverse()
        one = self.audit(first)
        two = self.audit(second)
        self.assertEqual(one["findings"], two["findings"])
        self.assertEqual(one["accepted"], two["accepted"])
        self.assertNotEqual(one["manifest_digest"], two["manifest_digest"])

    def test_rejects_same_region_and_stale_rehearsal(self) -> None:
        manifest = valid_manifest()
        manifest["recovery_region"] = manifest["primary_region"]
        manifest["started_at"] = "2026-01-01T00:00:00Z"
        manifest["completed_at"] = "2026-01-01T00:00:00Z"
        codes = {item["code"] for item in self.audit(manifest)["findings"]}
        self.assertEqual(codes, {"RECOVERY_REGION_NOT_DISTINCT", "REHEARSAL_STALE"})

    def test_rejects_traffic_switch_budget_breach(self) -> None:
        manifest = valid_manifest()
        manifest["measured_traffic_switch_seconds"] = 121
        self.assertEqual(
            self.audit(manifest)["findings"][0]["code"],
            "TRAFFIC_SWITCH_BUDGET_EXCEEDED",
        )

    def test_rejects_critical_cold_recovery(self) -> None:
        manifest = valid_manifest()
        manifest["components"][0]["recovery_mode"] = "backup_restore"
        self.assertEqual(
            self.audit(manifest)["findings"][0]["code"],
            "CRITICAL_COMPONENT_COLD_RECOVERY",
        )

    def test_rejects_rto_rpo_capacity_and_validation_breaches(self) -> None:
        manifest = valid_manifest()
        api = manifest["components"][1]
        api["measured_rto_seconds"] = 121
        api["measured_rpo_seconds"] = 11
        api["recovery_capacity"] = 100
        api["validation_passed"] = False
        codes = {item["code"] for item in self.audit(manifest)["findings"]}
        self.assertEqual(
            codes,
            {
                "RECOVERY_CAPACITY_INSUFFICIENT",
                "RPO_EXCEEDED",
                "RTO_EXCEEDED",
                "VALIDATION_FAILED",
            },
        )

    def test_rejects_unavailable_direct_dependency(self) -> None:
        manifest = valid_manifest()
        database = manifest["components"][0]
        database["recovery_mode"] = "unavailable"
        database["validation_passed"] = False
        codes = [item["code"] for item in self.audit(manifest)["findings"]]
        self.assertIn("DEPENDENCY_NOT_RECOVERABLE", codes)
        self.assertIn("COMPONENT_UNAVAILABLE", codes)

    def test_rejects_unavailable_transitive_dependency(self) -> None:
        manifest = valid_manifest()
        api = manifest["components"][1]
        analytics = manifest["components"][2]
        api["dependencies"] = ["analytics"]
        analytics["recovery_mode"] = "warm_standby"
        analytics["validation_passed"] = True
        analytics["recovery_capacity"] = 10
        analytics["recovery_order"] = 2
        api["recovery_order"] = 3
        database = manifest["components"][0]
        database["recovery_mode"] = "unavailable"
        database["validation_passed"] = False
        codes = {item["code"] for item in self.audit(manifest)["findings"]}
        self.assertIn("COMPONENT_UNAVAILABLE", codes)
        self.assertIn("DEPENDENCY_NOT_RECOVERABLE", codes)

    def test_rejects_dependency_order_and_rto_misalignment(self) -> None:
        manifest = valid_manifest()
        database = manifest["components"][0]
        database["recovery_order"] = 2
        database["target_rto_seconds"] = 200
        codes = {item["code"] for item in self.audit(manifest)["findings"]}
        self.assertIn("DEPENDENCY_RECOVERY_ORDER_INVALID", codes)
        self.assertIn("DEPENDENCY_RTO_MISALIGNED", codes)

    def test_rejects_dependency_cycle(self) -> None:
        manifest = valid_manifest()
        manifest["components"][0]["dependencies"] = ["api"]
        self.assertIn(
            "DEPENDENCY_CYCLE",
            {item["code"] for item in self.audit(manifest)["findings"]},
        )

    def test_can_exclude_important_components_from_closure(self) -> None:
        manifest = valid_manifest()
        manifest["components"][2]["tier"] = "important"
        strict = self.audit(manifest)
        relaxed = self.audit(
            manifest, Policy(require_important_dependency_closure=False)
        )
        self.assertFalse(strict["accepted"])
        self.assertTrue(relaxed["accepted"])

    def test_findings_do_not_expose_component_names(self) -> None:
        manifest = valid_manifest()
        manifest["components"][1]["validation_passed"] = False
        serialized = json.dumps(self.audit(manifest)["findings"])
        self.assertNotIn("api", serialized)
        self.assertIn("component_ref", serialized)


class MalformedEvidenceTests(unittest.TestCase):
    def test_rejects_unknown_dependency(self) -> None:
        manifest = valid_manifest()
        manifest["components"][1]["dependencies"] = ["missing"]
        with self.assertRaises(EvidenceError):
            audit(manifest, Policy(), now=NOW)

    def test_rejects_duplicate_component_and_dependency(self) -> None:
        duplicate_component = valid_manifest()
        duplicate_component["components"].append(
            deepcopy(duplicate_component["components"][0])
        )
        with self.assertRaises(EvidenceError):
            audit(duplicate_component, Policy(), now=NOW)
        duplicate_dependency = valid_manifest()
        duplicate_dependency["components"][1]["dependencies"] = ["database", "database"]
        with self.assertRaises(EvidenceError):
            audit(duplicate_dependency, Policy(), now=NOW)

    def test_rejects_naive_reversed_and_future_timestamps(self) -> None:
        for key, value in [
            ("completed_at", "2026-09-27T04:15:00"),
            ("started_at", "2026-09-27T05:00:00Z"),
            ("completed_at", "2026-09-28T05:06:00Z"),
        ]:
            with self.subTest(key=key, value=value):
                manifest = valid_manifest()
                manifest[key] = value
                with self.assertRaises(EvidenceError):
                    audit(manifest, Policy(), now=NOW)

    def test_rejects_naive_evaluation_clock(self) -> None:
        with self.assertRaises(EvidenceError):
            audit(valid_manifest(), Policy(), now=datetime(2026, 9, 28, 5, 0))

    def test_rejects_boolean_numeric_and_non_finite_values(self) -> None:
        for value in [True, float("nan"), float("inf"), -1]:
            with self.subTest(value=value):
                manifest = valid_manifest()
                manifest["components"][0]["measured_rto_seconds"] = value
                with self.assertRaises(EvidenceError):
                    audit(manifest, Policy(), now=NOW)

    def test_rejects_schema_drift_and_invalid_policy(self) -> None:
        manifest = valid_manifest()
        manifest["unexpected"] = True
        with self.assertRaises(EvidenceError):
            audit(manifest, Policy(), now=NOW)
        with self.assertRaises(EvidenceError):
            Policy(minimum_capacity_ratio=0)

    def test_rejects_component_and_dependency_budgets(self) -> None:
        manifest = valid_manifest()
        manifest["components"] = [
            deepcopy(manifest["components"][0]) for _ in range(513)
        ]
        with self.assertRaises(EvidenceError):
            audit(manifest, Policy(), now=NOW)
        manifest = valid_manifest()
        manifest["components"][1]["dependencies"] = [
            f"dep-{index}" for index in range(65)
        ]
        with self.assertRaises(EvidenceError):
            audit(manifest, Policy(), now=NOW)

    def test_loader_rejects_duplicate_keys_non_finite_and_large_input(self) -> None:
        samples = [
            b'{"schema_version":1,"schema_version":1}',
            b'{"value":NaN}',
            b"{" + b" " * (256 * 1024),
        ]
        for raw in samples:
            with (
                self.subTest(size=len(raw)),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "evidence.json"
                path.write_bytes(raw)
                with self.assertRaises(EvidenceError):
                    load_manifest(path)


class CliTests(unittest.TestCase):
    def run_cli(self, manifest: dict | str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "manifest.json"
            output = Path(directory) / "report.json"
            source.write_text(
                manifest if isinstance(manifest, str) else json.dumps(manifest),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.failover_readiness",
                    str(source),
                    "--output",
                    str(output),
                    "--max-rehearsal-age-days",
                    "365",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            result.report = json.loads(output.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
            return result

    def test_cli_exit_codes_and_atomic_report(self) -> None:
        accepted = self.run_cli(valid_manifest())
        self.assertEqual(accepted.returncode, 0)
        self.assertTrue(accepted.report["accepted"])  # type: ignore[attr-defined]
        rejected_manifest = valid_manifest()
        rejected_manifest["primary_region"] = rejected_manifest["recovery_region"]
        rejected = self.run_cli(rejected_manifest)
        self.assertEqual(rejected.returncode, 2)
        malformed = self.run_cli('{"schema_version": 1, "schema_version": 1}')
        self.assertEqual(malformed.returncode, 3)
        self.assertEqual(malformed.report["error"], "malformed_evidence")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
