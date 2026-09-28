# Cross-region failover readiness gate

A region pair on a diagram is not recovery evidence. A service may pass its own
rehearsal while a database, identity service, queue or traffic switch remains unable
to recover soon enough. This standard-library Python gate checks the dependency
closure of a failover rehearsal before its evidence is accepted.

## Contract

The manifest binds one rehearsal to distinct primary and recovery regions, UTC-aware
start/completion times, a traffic-switch budget and a bounded component graph. Each
component declares:

- recovery tier and mode;
- direct dependencies and recovery order;
- target and measured RTO/RPO;
- required and observed recovery capacity;
- an explicit validation outcome.

For critical and important components, the gate requires a recoverable mode, passing
validation, RTO/RPO compliance and sufficient recovery capacity. Their full transitive
dependency closure must also be recoverable; every dependency is ordered before its
consumer and has an RTO target no worse than the consumer. Critical components cannot
use cold `backup_restore` mode.
The whole graph must be acyclic and the traffic switch must meet its budget.

## Run

```bash
python -m tools.failover_readiness rehearsal.json --output failover-report.json
```

Exit codes are `0` for accepted evidence, `2` for a policy rejection and `3` for a
malformed artifact. Reports contain stable reason codes, hashed component references,
canonical SHA-256 identities and aggregate measurements—not component names or cloud
credentials. Output-file replacement is atomic.

The parser rejects duplicate JSON fields, non-finite numbers, unknown schema fields,
naive or inconsistent timestamps, unknown/duplicate/self dependencies and artifacts
outside the byte, component and edge budgets. Default policy accepts evidence no more
than 30 days old and requires at least 80% recovery capacity.

## Evidence collection

Generate the manifest from a controlled game day, not configuration intent alone.
Examples of provider-specific evidence include health checks, database replica lag,
queue depth, capacity/quota snapshots and observed DNS/global-load-balancer transition
time. Keep raw telemetry in the governed system of record; pass only the normalized
measurements required by this contract.

## Trust boundary and limitations

This gate does not authenticate the collector, execute failover, prove application
correctness or simulate a cloud control-plane outage. Dependency closure cannot detect
an omitted component. Capacity totals do not prove zone distribution, quota
availability, compatible instance shape or downstream saturation. RTO/RPO measurements
remain only as trustworthy as their clocks and producer.

Production use should sign the source artifact, bind it to immutable infrastructure
and application revisions, collect it with least privilege, and retain the report with
the change approval. The next useful increment is a provider adapter that collects
regional health and replication evidence, plus a signed attestation binding the
manifest digest to the rehearsal run.
