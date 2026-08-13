# Cross-cloud failure-mode playbook

The same failure classes appear across AWS, GCP, Azure and Huawei Cloud even when service names differ.

| Failure | Typical symptom | First mitigation | Architectural mitigation |
|---|---|---|---|
| Instance/container crash | 5xx or dropped request | health check + restart | multiple replicas across failure domains |
| Dependency timeout | request latency spikes | client timeout | circuit breaker + bulkhead + bounded retries |
| Queue consumer lag | stale processing | scale consumers | partitioning + autoscaling + backpressure |
| Cache outage | DB load spike | bypass cache | cache-aside + request coalescing + DB capacity headroom |
| Database failover | transient connection errors | reconnect with jitter | managed HA + connection pool reset + idempotent writes |
| DNS issue | endpoint unreachable | cached resolver result | multi-zone endpoints + sensible TTLs |
| Region outage | broad unavailability | traffic failover | multi-region replication and tested RTO/RPO |
| Credential rotation | auth failures | refresh secret/token | workload identity + short-lived credentials |
| Bad deployment | elevated errors | rollback | canary/blue-green + automated health gates |
| Traffic surge | saturation | shed load | autoscaling + queues + rate limits + admission control |

## Portability principle

Design against capabilities first: object storage, relational database, queue, event bus, container runtime, function runtime, metrics, secrets and identity. Vendor-specific services then become implementation choices rather than architecture itself.

## Interview checklist

For every architecture, be ready to state:

1. failure domain;
2. timeout budget;
3. retry owner;
4. idempotency boundary;
5. source of truth;
6. cache consistency strategy;
7. scaling signal;
8. observability signal;
9. RTO and RPO expectation;
10. rollback path.
