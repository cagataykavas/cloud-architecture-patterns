# Terraform/OpenTofu change-risk adapter

`tools.terraform_plan_adapter` converts machine-readable `show -json` output into
the normalized artifact consumed by `tools.change_risk_audit`. It follows the
documented [Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
and [OpenTofu JSON output format](https://opentofu.org/docs/internals/json-format/)
for resource addresses, lifecycle actions, before/after values, unknown values,
and sensitive-value markers.

The adapter does not guess provider semantics. A reviewed inventory declares the
criticality and dependency graph and maps the seven governed posture fields to
explicit JSON pointers or literals. This keeps provider-specific knowledge visible
in code review and makes a missing resource or unresolved value a hard failure.

## Generate and adapt a plan

Save the exact plan that will be applied, then render its JSON representation:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

python -m tools.terraform_plan_adapter tfplan.json reviewed-inventory.json \
  --source-revision <lowercase-commit-sha256> \
  --generated-at 2026-11-08T17:30:00Z \
  --output normalized-plan.json

python -m tools.change_risk_audit normalized-plan.json \
  --now 2026-11-08T17:30:05Z \
  --output change-risk-report.json
```

Use the same immutable binary plan for `show -json`, review, and apply. The adapter
requires JSON format major version 1, `applyable=true`, `complete=true`,
`errored=false`, prior-state evidence, and one catalog entry for every managed
resource change. Data-source reads are ignored because they are not apply actions.
Deposed objects and unsupported actions such as `read` or OpenTofu `forget` fail
closed rather than being silently misclassified.

## Reviewed inventory

The inventory has one exact resource address per managed entry in
`resource_changes`, including `no-op` resources needed to calculate downstream
blast radius:

```json
{
  "schema_version": "terraform-plan-adapter/v1",
  "resources": {
    "aws_db_instance.orders": {
      "kind": "database",
      "criticality": "critical",
      "data_class": "persistent",
      "depends_on": [],
      "change_ticket": null,
      "approval_digest": null,
      "backup_verified_at": null,
      "replacement_ready": false,
      "posture": {
        "region": {"path": "/region"},
        "failure_domain": {"path": "/availability_zone"},
        "public_access": {"path": "/publicly_accessible"},
        "encrypted": {"path": "/storage_encrypted"},
        "multi_zone": {"path": "/multi_az"},
        "deletion_protection": {"path": "/deletion_protection"},
        "privilege_scope": {"literal": "scoped"}
      }
    }
  }
}
```

JSON pointers use RFC 6901 escaping (`~0` for `~`, `~1` for `/`) and are bounded
to 16 segments and 512 UTF-8 bytes. A selector may instead contain one `literal`
for reviewed facts that are not represented in provider state. The downstream gate
validates every selected value, including allowed enum values and booleans.

The same selector is resolved independently against before and after state. A
path marked unknown in `after_unknown` or sensitive in `before_sensitive` or
`after_sensitive` is rejected. This prevents a partially known plan from being
normalized as a safe value and prevents governed evidence from copying a value the
provider marked sensitive.

## Evidence and trust boundary

The normalized plan ID commits to the complete raw plan and reviewed inventory, while
`inventory_digest` separately permits the post-apply reconciler to reject a changed selector
catalog without needing the raw plan again. Resource-list order does not change the identity.
The state snapshot digest commits
to `prior_state`, while the downstream audit digest commits to all normalized
actions, metadata, dependencies, and posture values. Raw provider attributes are
not copied into the audit report.

The adapter still trusts the reviewed inventory to describe dependency edges and
choose correct provider paths. A malicious or mistaken inventory can classify a
resource incorrectly, and a provider can expose posture through a schema the
inventory does not understand. Require inventory review alongside infrastructure
code, pin provider and CLI versions, reject catalog drift in CI, and compare the
accepted digest with post-apply reconciliation evidence.

This is an admission adapter, not an apply executor. It does not authenticate the
plan producer, prove restore success, validate provider behavior, or guarantee that
the reviewed plan is the artifact eventually applied.

After apply, run the [post-apply reconciler](terraform-apply-reconciliation.md) against
the resulting `terraform show -json` state. It reuses this inventory's posture selectors,
checks the complete expected resource set, and binds the observed managed state into a
privacy-reduced release artifact.
