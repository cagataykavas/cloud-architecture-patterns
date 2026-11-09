# Terraform/OpenTofu post-apply reconciliation

An accepted plan does not prove that the resulting infrastructure matches the reviewed change.
Provider defaults, admission-time mutation, a different plan artifact, or a concurrent apply can
produce a state whose security and resilience posture differs from the approved `after` values.

`tools.terraform_apply_reconciler` compares a post-apply `terraform show -json` state with the exact
normalized plan and reviewed inventory produced for the change-risk gate. It:

- recursively inventories managed resources in root and child modules;
- requires the applied managed-resource set to equal the plan's expected post-apply set;
- proves that planned deletions are absent and planned create/update/replace/no-op resources exist;
- resolves the same seven reviewed posture selectors against applied values;
- requires the inventory digest to match the catalog bound into the reviewed plan;
- rejects drift in region, failure domain, public access, encryption, multi-zone resilience,
  deletion protection, or privilege scope;
- rejects duplicate addresses and sensitive or unresolvable governed values rather than guessing;
- commits to complete managed-resource values in a deterministic applied-state digest; and
- emits only aggregate counts, stable reason codes, and hashed resource references.

## Release workflow

Use the same reviewed inventory at plan and reconciliation time. Apply only the saved binary plan,
then render the resulting state and reconcile it before declaring the release complete:

```bash
terraform apply tfplan
terraform show -json > applied-state.json

python -m tools.terraform_apply_reconciler \
  normalized-plan.json reviewed-inventory.json applied-state.json \
  --output apply-reconciliation.json
```

Exit code `0` means the governed state and resource set match. Exit code `2` means valid evidence
contains drift. Exit code `3` means the plan, inventory, or state evidence is malformed or cannot be
resolved safely. Output writes are atomic.

The report carries the reviewed inventory digest, while the applied-state digest covers complete
managed-resource values and sensitive-value markers, not only the seven policy fields. Ungoverned
provider drift therefore changes the evidence identity even when it does not block this policy. Raw
addresses, attributes, and sensitive values are not copied into the report.

## Trust boundary and limitations

The reconciler trusts the Terraform/OpenTofu state producer, provider schema, reviewed inventory,
and the identity used to read state. It does not authenticate evidence, prove that the state belongs
to the intended backend/workspace, inspect provider APIs independently, or detect drift after the
snapshot. A compromised state source can lie consistently.

Production use should fetch state with a least-privilege CI identity, bind the accepted plan and
reconciliation digests to an immutable release record, verify the backend/workspace identity, and
run a delayed provider-side drift check. The current posture vocabulary intentionally omits many
provider-specific controls; an unchanged governed projection is not proof that every resource
attribute is safe.
