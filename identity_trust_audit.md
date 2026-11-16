# Workload identity trust audit

Static cloud credentials and broad federation trust can turn a small workload compromise into an
account-wide incident. `tools/identity_trust_audit.py` evaluates a normalized snapshot of AWS, GCP,
Azure, and Huawei Cloud identity bindings without requiring provider credentials in CI.

The audit detects:

- public or wildcard principals;
- wildcard actions and resources;
- privileged roles assigned to workload identities;
- static credentials;
- federated workloads without bounded issuer and subject constraints;
- break-glass grants without approval, expiry, or timely removal.

## Input contract

```json
{
  "bindings": [
    {
      "binding_id": "deploy-main",
      "provider": "aws",
      "principal": "arn:aws:iam::123456789012:role/deploy-main",
      "principal_type": "workload",
      "role": "deployment-reader",
      "actions": ["s3:GetObject"],
      "resources": ["arn:aws:s3:::release-bucket/main/model.tar"],
      "credential_mode": "federated",
      "federation_issuer": "https://token.actions.githubusercontent.com",
      "federation_subjects": ["repo:example/service:ref:refs/heads/main"]
    }
  ]
}
```

Do not put credentials, tokens, private keys, or proprietary identifiers in the input. Provider
export adapters should normalize metadata only.

```bash
python -m tools.identity_trust_audit bindings.json \
  --as-of 2026-11-16T08:00:00Z \
  --output artifacts/identity-trust-report.json
```

Exit code `0` means no findings, `2` means policy findings were emitted, and `3` means the evidence
was malformed or could not be processed. The required evaluation time keeps expiration decisions
reproducible. Reports are atomically replaced with owner-only file permissions and expose binding
IDs and finding metadata rather than raw principals.

## Limits

This is a normalized policy audit, not proof of effective cloud authorization. It does not resolve
provider-specific role inheritance, deny statements, organization policies, conditional access,
session duration, resource ownership, or runtime token issuance. Pattern matching cannot replace
provider-native access analysis. The next step is to add read-only AWS/GCP/Azure/Huawei export
adapters and fixture-based parity tests against their native policy evaluators.
