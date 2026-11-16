# event-path-bench

Benchmark for multi-hop relationship path search over security events.
It compares three ways of answering the same question, "which events are reachable from this alert within N hops, in time order":

| Approach | Description |
|---|---|
| PostgreSQL recursive query | `WITH RECURSIVE` over the 1-hop edge table stored in PostgreSQL |
| PostgreSQL pruning + DuckDB | Per-edge pruning in PostgreSQL, recursive CTE in an embedded DuckDB session |
| Neo4j | Events and relationships loaded continuously, variable-length path queries |

All approaches run on the same synthetic dataset and must return the same path set before any timing is recorded.

## Dataset

Raw records follow the [OCSF](https://schema.ocsf.io/) 1.9.0 schema.
Records that describe the same action are grouped into an event through the standard `metadata.correlation_uid` field, and 1-hop edges between events are derived from standard OCSF anchor fields.
Values that have no place in the schema, such as ground-truth labels for planted attack chains, are written to `unmapped`.

See [docs/PLAN.md](docs/PLAN.md) for the data model, scenarios, and metrics.

## Requirements

- Docker with Compose v2
- About 12 GB of memory for the containers

## License

Apache-2.0
