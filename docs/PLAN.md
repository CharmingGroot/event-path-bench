# Plan

## Data model

| Layer | Form | Notes |
|---|---|---|
| Raw record | OCSF 1.9.0 JSON | One record per log line from a device |
| Event | Group of raw records | Grouped by `metadata.correlation_uid` |
| Edge | 1-hop relationship between two events | Derived from anchor fields, carries start and end time |

OCSF calls a single record an "event".
In this repository, "record" means an OCSF record and "event" means the grouped unit that edges connect.

### OCSF classes

| Class (uid) | Role |
|---|---|
| HTTP Activity (4002) | WAF log, web shell upload request |
| File System Activity (1001) | EDR file log, web shell write and credential file read |
| Process Activity (1007) | EDR process log, shell execution |
| Network Activity (4001) | Firewall and proxy log, internal DB connection, scan noise |
| DNS Activity (4003) | Main source of hub anchors (resolver IPs) |
| Authentication (3002) | User and session anchors |
| Detection Finding (2004) | Alert, used as the search seed |

### Edge rules

All anchors are standard OCSF fields.

| Rule | Anchor |
|---|---|
| Same session | `actor.session.uid` |
| Parent and child process | `process.parent_process.uid` to `process.uid` |
| Same host, adjacent in time | `device.uid` |
| Network connection | `src_endpoint.ip` / `dst_endpoint.ip` to the target `device.ip` |
| Written file executed | `file.path` in 1001 to `process.file.path` in 1007 |
| Same user | `actor.user.uid` |

### Distributions

- Resolver and proxy IPs follow a Zipf distribution so that they become hub anchors.
- Scan bursts (bulk, both directions) and beaconing (repeated traffic between the same pair) are mixed in as noise.
- Attack chains (web shell upload, shell execution, credential read, DB connection) are planted with consistent timestamps and serve as ground truth.

## Environment

| Container | Memory limit | Notes |
|---|---|---|
| `pg` (PostgreSQL 17) | 4 GB | `wal_level=replica`, `archive_mode=on`, archive volume size is measured |
| `neo4j` (Community 5.x) | 4 GB | Heap 2 GB, page cache 2 GB |
| `bench` (Python, embedded DuckDB) | 4 GB | Generator, runner, measurement |
| `ingest` | small | Ingest load during scenario E and N3 |

PostgreSQL and Neo4j scenarios run separately.
Both run at the same time only for the dual-write comparison (N3).

## Scenarios

| ID | Approach | Measures |
|---|---|---|
| A | PostgreSQL `WITH RECURSIVE` over all edges | Baseline |
| B | Same query with pruning conditions | Effect of pruning alone |
| C | Pruning in PostgreSQL, recursive CTE in DuckDB | Proposed structure, DuckDB share compared with B |
| D | Intermediate results in regular and UNLOGGED tables | WAL bytes, archive size |
| E | A and C under ingest load | Ingest latency |
| N1 | Continuous transactional load of events and relationships into Neo4j | Ingest throughput, store size, memory |
| N2 | Variable-length path query in Neo4j with the same conditions (quantified path pattern, time order, hop limit) | Query time compared with C |
| N3 | PostgreSQL alone vs PostgreSQL + Neo4j dual write | Added cost of always-on loading |

A, C, and N2 must return the same path set for the same seed alerts before timing starts.

## Metrics

- Query latency median and p95
- Peak memory, temporary file bytes
- WAL bytes (LSN difference) and archive size
- Number of edges loaded into DuckDB
- Recall of planted attack chains
- Ingest throughput
- Neo4j store size, dual-write throughput

Runs alternate between approaches within a single session.
Results are reported as % change and multiples, with versions and settings recorded.

## Scale

1M OCSF records first, to confirm every scenario completes, then 5M and 20M.
20M depends on whether Neo4j stays within its memory limit.

## Steps

1. OCSF record generator and schema validation (required fields)
2. Event grouping and edge derivation, load into PostgreSQL and Neo4j
3. Path set equality check at 1M
4. Scenarios A to E and N1 to N3
5. Scale to 5M and 20M, write up results
