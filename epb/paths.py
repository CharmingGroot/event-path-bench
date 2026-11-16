"""Multi-hop path search with the same semantics in PostgreSQL, DuckDB, and Neo4j.

From the seed event, with arrival time a0 = seed start time:
- follow edge e out of node u only if e.t_end >= arrival(u) (still alive after arrival)
- arrival(v) = max(arrival(u), e.t_start)
- at most H hops, no node twice in a path

Pruning (scenarios B, C, N2) keeps edges with
  t_start in [lo, hi] AND out_rank <= fanout
where out_rank is set at definition time only for edges that pass the static
filters (anchor count <= 1000 per hour, no reflection, fold rank 1) and orders
each node's outgoing edges by start time.

Every engine returns (paths, reached, nodes): number of paths of length >= 1,
number of distinct reached nodes other than the seed, and the sorted node ids.
"""

from __future__ import annotations

from dataclasses import dataclass

PRUNE_SQL = "t_start BETWEEN {lo} AND {hi} AND out_rank <= {fanout}"


@dataclass
class Seed:
    seed: int
    a0: int
    alert_time: int
    chain_id: str | None


@dataclass
class Params:
    hops: int = 6
    before_ms: int = 3_600_000
    after_ms: int = 6 * 3_600_000
    fanout: int = 10

    def window(self, s: Seed) -> tuple[int, int]:
        return s.alert_time - self.before_ms, s.alert_time + self.after_ms


def prune_predicate(s: Seed, p: Params) -> str:
    lo, hi = p.window(s)
    return PRUNE_SQL.format(lo=lo, hi=hi, fanout=p.fanout)


# --------------------------------------------------------------------------- PostgreSQL

def pg_sql(s: Seed, p: Params, prune: bool) -> str:
    where = f"WHERE {prune_predicate(s, p)}" if prune else ""
    return f"""
WITH RECURSIVE pe AS (SELECT src, dst, t_start, t_end FROM edges {where}),
walk(node, arr, hops, path) AS (
  SELECT {s.seed}::bigint, {s.a0}::bigint, 0, ARRAY[{s.seed}::bigint]
  UNION ALL
  SELECT e.dst, greatest(w.arr, e.t_start), w.hops + 1, w.path || e.dst
  FROM walk w JOIN pe e ON e.src = w.node
  WHERE w.hops < {p.hops} AND e.t_end >= w.arr AND e.dst <> ALL(w.path)
)
SELECT count(*) - 1, count(DISTINCT node) - 1,
       coalesce(array_agg(DISTINCT node) FILTER (WHERE node <> {s.seed}), '{{}}')
FROM walk"""


# --------------------------------------------------------------------------- DuckDB

DUCK_WALK = """
WITH RECURSIVE walk(node, arr, hops, path) AS (
  SELECT $seed::BIGINT, $a0::BIGINT, 0, [$seed::BIGINT]
  UNION ALL
  SELECT e.dst, greatest(w.arr, e.t_start), w.hops + 1, list_append(w.path, e.dst)
  FROM walk w JOIN pe e ON e.src = w.node
  WHERE w.hops < $hops AND e.t_end >= w.arr AND NOT list_contains(w.path, e.dst)
)
SELECT count(*) - 1, count(DISTINCT node) - 1,
       coalesce(list(DISTINCT node ORDER BY node) FILTER (WHERE node <> $seed), [])
FROM walk"""


def duck_prune_query(s: Seed, p: Params) -> str:
    return f"SELECT src, dst, t_start, t_end FROM edges WHERE {prune_predicate(s, p)}"


# --------------------------------------------------------------------------- Neo4j

CYPHER_POSTFILTER = """
MATCH (s:Event {eid: $seed})
MATCH p = (s)(()-[r:REL WHERE r.t_start >= $lo AND r.t_start <= $hi AND r.out_rank <= $fanout]->()){1,%d}(x)
WITH p, x, relationships(p) AS rs, nodes(p) AS ns
WHERE all(i IN range(0, size(rs) - 1) WHERE
          rs[i].t_end >= reduce(a = $a0, j IN range(0, i - 1) |
                                CASE WHEN rs[j].t_start > a THEN rs[j].t_start ELSE a END))
  AND all(i IN range(1, size(ns) - 1) WHERE NOT ns[i] IN ns[0..i])
RETURN count(p) AS paths, count(DISTINCT x) AS reached, collect(DISTINCT x.eid) AS nodes
"""


# Fastest form found: allReduce (Cypher 25) checks the time condition while the
# quantified path pattern expands, instead of filtering finished paths.
CYPHER = """CYPHER 25
MATCH (s:Event {eid: $seed})
MATCH p = (s)(()-[r:REL WHERE r.t_start >= $lo AND r.t_start <= $hi AND r.out_rank <= $fanout]->()){1,%d}(x)
  WHERE allReduce(acc = {arr: $a0, ok: true}, rel IN r |
                  {arr: CASE WHEN rel.t_start > acc.arr THEN rel.t_start ELSE acc.arr END, ok: rel.t_end >= acc.arr},
                  acc.ok)
WITH p, x, nodes(p) AS ns
WHERE all(i IN range(1, size(ns) - 1) WHERE NOT ns[i] IN ns[0..i])
RETURN count(p) AS paths, count(DISTINCT x) AS reached, collect(DISTINCT x.eid) AS nodes
"""
