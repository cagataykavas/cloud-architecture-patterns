# Infrastructure change blast-radius audit

Infrastructure plans are often reviewed resource by resource. That misses correlated failure: a
single database replacement can transitively affect several critical services, while multiple
individually safe updates can concentrate risk in one failure domain.

`tools.change_risk_audit` is a dependency-free, fail-closed admission gate for a normalized
Terraform/OpenTofu or provider-plan artifact. It combines change intent, dependency reachability,
security posture, approval evidence, and backup readiness before apply.

## Controls

The audit:

- computes the reverse transitive dependency closure of every changed resource;
- limits the union of impacted critical resources and the largest per-resource blast radius;
- limits total changed resources and changes concentrated in one failure domain;
- requires a ticket plus approval digest for persistent delete/replace, new public access,
  account/organization privilege expansion, and region moves;
- requires a fresh verified backup for destructive persistent-data changes;
- requires replacement readiness before replacing persistent resources; and
- always rejects removal of encryption, deletion protection, or multi-zone resilience from
  protected workloads.

## Normalized artifact

Provider adapters should emit the complete relevant dependency inventory, including `no_op`
resources, so the audit can measure downstream impact. The `before`/`after` contract is:

- `create`: `before` is null, `after` is present;
- `delete`: `before` is present, `after` is null;
- `update`, `replace`, and `no_op`: both are present;
- `no_op`: states must be identical.

Each state records region, failure domain, public access, encryption, multi-zone status, deletion
protection, and privilege scope. Resources also declare criticality, data class, dependency IDs,
change ticket, approval digest, backup verification timestamp, and replacement readiness.

```json
{
  "generated_at": "2026-10-01T13:00:00Z",
  "plan_id": "prod-plan-42",
  "source_revision": "<lowercase SHA-256>",
  "state_snapshot_digest": "<lowercase SHA-256>",
  "resources": [
    {
      "id": "orders-db",
      "kind": "database",
      "criticality": "critical",
      "data_class": "persistent",
      "action": "update",
      "depends_on": [],
      "before": {
        "region": "eu-west",
        "failure_domain": "data-a",
        "public_access": false,
        "encrypted": true,
        "multi_zone": true,
        "deletion_protection": true,
        "privilege_scope": "scoped"
      },
      "after": {
        "region": "eu-west",
        "failure_domain": "data-a",
        "public_access": false,
        "encrypted": true,
        "multi_zone": true,
        "deletion_protection": true,
        "privilege_scope": "scoped"
      },
      "change_ticket": null,
      "approval_digest": null,
      "backup_verified_at": null,
      "replacement_ready": false
    }
  ]
}
```

Run the gate immediately before apply against the same immutable plan and state snapshot:

```bash
python -m tools.change_risk_audit normalized-plan.json \
  --now 2026-10-01T13:00:30Z \
  --output change-risk-report.json
```

Exit codes are `0` for accepted evidence, `2` for a policy rejection, and `3` for malformed or
operational input. Reports use hashed plan/resource references and do not reproduce raw resource
IDs. Evidence is canonical across resource and dependency ordering. JSON output is atomic.

## Resource bounds and trust boundary

The loader rejects duplicate keys, non-finite constants, symbolic links, unknown fields, invalid
timestamps, dependency cycles, and inputs above 2 MiB. Plans are bounded to 1,024 resources and
8,192 dependency edges; reports retain at most 2,048 findings while preserving the total count and
truncation flag.

This module does not parse raw provider plans. The adapter that maps Terraform/OpenTofu/provider
output into this contract is a trust boundary and must not omit dependencies or posture changes.
The source-revision and state-snapshot digests bind content but do not authenticate it; production
approval digests should refer to signed, immutable approval records.

Static plan evidence cannot prove that a backup restores, quotas remain available, DNS converges,
provider admission is unchanged, or apply finishes atomically. The gate complements policy-as-code,
provider-native plan review, staged rollout, and post-apply reconciliation; it does not replace
them.
