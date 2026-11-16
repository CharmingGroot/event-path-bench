"""Definition stage: OCSF records -> events -> 1-hop edges, computed in DuckDB.

Events group the records that share `metadata.correlation_uid`. The event's host
is the device of its first record. Edges point forward in time from u to v and
carry v's lifetime as [t_start, t_end]. Several rule instances between the same
pair of events are folded into one edge row; the per-edge values that pruning
reads later (anchor count, reflection flag, fold rank) are computed here, as
counters maintained at definition time would provide them.

Usage: python -m epb.derive data/d1
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import duckdb

S = 1000
W_HOST = 60 * S          # same_host
W_SESSION = 600 * S      # same_session
W_USER = 300 * S         # same_user (cross-host)
W_DST = 10 * S           # same_dst (cross-host)
NET_GRACE = 60 * S       # net_conn: target events until the connection ends + grace
LINEAGE_MAX = 3600 * S   # process lineage, file written then executed
HOUR = 3600 * S
FOLD_BUCKET = 600 * S
REFL_MIN = 3             # connections per hour in both directions
STATIC_HUB = 1000        # anchor events per hour above which the anchor counts as a hub

RULES = {"same_host": 1, "same_session": 2, "same_user": 4, "lineage": 8,
         "file_exec": 16, "net_conn": 32, "same_dst": 64}

EVENTS_SQL = r"""
CREATE OR REPLACE TABLE rec AS
SELECT row_number() OVER () AS rn, json AS j
FROM read_ndjson_objects('{glob}', format = 'newline_delimited');

CREATE OR REPLACE TABLE rec_x AS
SELECT rn,
  j->>'$.metadata.correlation_uid' AS corr,
  j->>'$.metadata.uid' AS rec_uid,
  (j->>'$.class_uid')::INT AS class_uid,
  (j->>'$.activity_id')::INT AS activity_id,
  j->>'$.device.uid' AS host,
  coalesce(j->>'$.actor.user.uid', j->>'$.user.uid') AS usr,
  coalesce(j->>'$.actor.session.uid', j->>'$.session.uid') AS sess,
  j->>'$.process.uid' AS proc,
  j->>'$.actor.process.uid' AS aproc,
  j->>'$.process.parent_process.uid' AS parent,
  j->>'$.process.file.path' AS pfile,
  CASE WHEN (j->>'$.class_uid')::INT = 1001 AND (j->>'$.activity_id')::INT = 1
       THEN j->>'$.file.path' END AS wfile,
  j->>'$.dst_endpoint.uid' AS dst,
  coalesce((j->>'$.start_time')::BIGINT, (j->>'$.time')::BIGINT) AS t0,
  coalesce((j->>'$.end_time')::BIGINT, (j->>'$.time')::BIGINT) AS t1
FROM rec;

CREATE OR REPLACE TABLE events AS
SELECT row_number() OVER (ORDER BY min(t0), corr) AS eid, corr,
  arg_min(host, rn) AS host,
  max(usr) AS usr, max(sess) AS sess, max(proc) AS proc, max(aproc) AS aproc,
  max(parent) AS parent, max(pfile) AS pfile, max(wfile) AS wfile,
  arg_min(dst, rn) FILTER (WHERE dst IS NOT NULL) AS dst,
  min(t0) AS t0, max(t1) AS t1, count(*) AS n_records,
  list(DISTINCT class_uid ORDER BY class_uid) AS classes
FROM rec_x WHERE class_uid <> 2004
GROUP BY corr;
"""

# Each instance: (src, dst, rule, anchor value, pair_a, pair_b) where the pair is
# used for reflection and folding on network rules.
EDGES_SQL = f"""
CREATE OR REPLACE TABLE inst (src BIGINT, dst BIGINT, rule INT, anchor VARCHAR, ha VARCHAR, hb VARCHAR, net BOOLEAN);

-- same host, v starts within W_HOST after u
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['same_host']}, 'host:' || u.host, NULL, NULL, false
FROM (SELECT eid, host, t0, t0 // {W_HOST} AS b FROM events WHERE host IS NOT NULL) u
CROSS JOIN (VALUES (0), (1)) k(o)
JOIN (SELECT eid, host, t0, t0 // {W_HOST} AS b FROM events WHERE host IS NOT NULL) v
  ON v.host = u.host AND v.b = u.b + k.o
WHERE v.t0 >= u.t0 AND v.t0 <= u.t0 + {W_HOST} AND (v.t0 > u.t0 OR v.eid > u.eid);

-- same host, v is long-lived and still alive when u happens
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['same_host']}, 'host:' || u.host, NULL, NULL, false
FROM events u JOIN (SELECT * FROM events WHERE t1 - t0 > {W_HOST}) v
  ON v.host = u.host AND v.t0 < u.t0 AND v.t1 >= u.t0 AND v.eid <> u.eid;

-- same session
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['same_session']}, 'session:' || u.sess, NULL, NULL, false
FROM (SELECT eid, sess, t0, t0 // {W_SESSION} AS b FROM events WHERE sess IS NOT NULL AND sess <> 'none') u
CROSS JOIN (VALUES (0), (1)) k(o)
JOIN (SELECT eid, sess, t0, t0 // {W_SESSION} AS b FROM events WHERE sess IS NOT NULL AND sess <> 'none') v
  ON v.sess = u.sess AND v.b = u.b + k.o
WHERE v.t0 >= u.t0 AND v.t0 <= u.t0 + {W_SESSION} AND (v.t0 > u.t0 OR v.eid > u.eid);

-- same user on another host
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['same_user']}, 'user:' || u.usr, NULL, NULL, false
FROM (SELECT eid, usr, host, t0, t0 // {W_USER} AS b FROM events WHERE usr IS NOT NULL) u
CROSS JOIN (VALUES (0), (1)) k(o)
JOIN (SELECT eid, usr, host, t0, t0 // {W_USER} AS b FROM events WHERE usr IS NOT NULL) v
  ON v.usr = u.usr AND v.b = u.b + k.o
WHERE v.host <> u.host AND v.t0 >= u.t0 AND v.t0 <= u.t0 + {W_USER} AND (v.t0 > u.t0 OR v.eid > u.eid);

-- process lineage: u's process (or acting process) is v's parent or acting process
INSERT INTO inst
WITH uk AS (SELECT eid, t0, proc AS k FROM events WHERE proc IS NOT NULL
            UNION ALL SELECT eid, t0, aproc FROM events WHERE aproc IS NOT NULL),
     vk AS (SELECT eid, t0, parent AS k FROM events WHERE parent IS NOT NULL
            UNION ALL SELECT eid, t0, aproc FROM events WHERE aproc IS NOT NULL)
SELECT DISTINCT u.eid, v.eid, {RULES['lineage']}, 'proc:' || u.k, NULL, NULL, false
FROM uk u JOIN vk v ON v.k = u.k
WHERE v.eid <> u.eid AND v.t0 >= u.t0 AND v.t0 <= u.t0 + {LINEAGE_MAX} AND (v.t0 > u.t0 OR v.eid > u.eid);

-- file written on a host, then executed there
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['file_exec']}, 'file:' || u.wfile, NULL, NULL, false
FROM events u JOIN events v ON v.pfile = u.wfile AND v.host = u.host
WHERE u.wfile IS NOT NULL AND v.eid <> u.eid AND v.t0 >= u.t0 AND v.t0 <= u.t0 + {LINEAGE_MAX};

-- network connection: u connects to host X, v happens on X while the connection is open
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['net_conn']}, 'dst:' || u.dst, u.host, u.dst, true
FROM events u JOIN events v ON v.host = u.dst
WHERE u.dst IS NOT NULL AND v.host <> u.host AND v.t0 >= u.t0 AND v.t0 <= u.t1 + {NET_GRACE};

-- same internal destination from another host, within W_DST
INSERT INTO inst
SELECT u.eid, v.eid, {RULES['same_dst']}, 'dst:' || u.dst, u.host, u.dst, true
FROM (SELECT eid, host, dst, t0, t0 // {W_DST} AS b FROM events WHERE dst IS NOT NULL) u
CROSS JOIN (VALUES (0), (1)) k(o)
JOIN (SELECT eid, host, dst, t0, t0 // {W_DST} AS b FROM events WHERE dst IS NOT NULL) v
  ON v.dst = u.dst AND v.b = u.b + k.o
WHERE v.host <> u.host AND v.t0 >= u.t0 AND v.t0 <= u.t0 + {W_DST} AND (v.t0 > u.t0 OR v.eid > u.eid);
"""

COUNTERS_SQL = f"""
-- events per anchor value per hour, as a definition-time counter would hold them
CREATE OR REPLACE TABLE anchor_counts AS
SELECT anchor, hr, count(*) AS cnt FROM (
  SELECT 'host:' || host AS anchor, t0 // {HOUR} AS hr FROM events WHERE host IS NOT NULL
  UNION ALL SELECT 'dst:' || dst, t0 // {HOUR} FROM events WHERE dst IS NOT NULL
  UNION ALL SELECT 'session:' || sess, t0 // {HOUR} FROM events WHERE sess IS NOT NULL
  UNION ALL SELECT 'user:' || usr, t0 // {HOUR} FROM events WHERE usr IS NOT NULL
  UNION ALL SELECT 'proc:' || proc, t0 // {HOUR} FROM events WHERE proc IS NOT NULL
  UNION ALL SELECT 'proc:' || aproc, t0 // {HOUR} FROM events WHERE aproc IS NOT NULL
  UNION ALL SELECT 'file:' || wfile, t0 // {HOUR} FROM events WHERE wfile IS NOT NULL
) GROUP BY ALL;

-- host pairs with connections in both directions within the same hour
CREATE OR REPLACE TABLE refl_pairs AS
WITH c AS (SELECT host AS a, dst AS b, t0 // {HOUR} AS hr, count(*) AS n
           FROM events WHERE dst IS NOT NULL AND host IS NOT NULL GROUP BY ALL)
SELECT x.a, x.b, x.hr FROM c x JOIN c y ON y.a = x.b AND y.b = x.a AND y.hr = x.hr
WHERE x.n >= {REFL_MIN} AND y.n >= {REFL_MIN};
"""

FOLD_SQL = f"""
CREATE OR REPLACE TABLE inst2 AS
SELECT i.src, i.dst, i.rule, i.anchor,
  coalesce(ac.cnt, 1) AS anchor_cnt,
  (i.net AND rp.a IS NOT NULL) AS refl,
  CASE WHEN i.rule = {RULES['net_conn']} THEN
    row_number() OVER (PARTITION BY i.rule, i.ha, v.host, v.t0 // {FOLD_BUCKET} ORDER BY v.t0, i.src, i.dst)
  ELSE 1 END AS fold_rank,
  v.t0 AS t_start, v.t1 AS t_end
FROM inst i
JOIN events u ON u.eid = i.src
JOIN events v ON v.eid = i.dst
LEFT JOIN anchor_counts ac ON ac.anchor = i.anchor AND ac.hr = u.t0 // {HOUR}
LEFT JOIN refl_pairs rp ON rp.a = i.ha AND rp.b = i.hb AND rp.hr = u.t0 // {HOUR};

CREATE OR REPLACE TABLE edges AS
SELECT src, dst, bit_or(rule)::SMALLINT AS rules, min(anchor_cnt)::INT AS anchor_cnt,
  bool_and(refl) AS refl, min(fold_rank)::INT AS fold_rank,
  any_value(t_start) AS t_start, any_value(t_end) AS t_end
FROM inst2 GROUP BY src, dst;

-- per-node fan-out order among edges that pass the static filters (hub, reflection,
-- folding); search follows only the first K edges of each node by start time
CREATE OR REPLACE TABLE edges AS
SELECT *, CASE WHEN keep THEN row_number() OVER (PARTITION BY src, keep ORDER BY t_start, dst) END::INT AS out_rank
FROM (SELECT *, (anchor_cnt <= {STATIC_HUB} AND NOT refl AND fold_rank = 1) AS keep FROM edges);
ALTER TABLE edges DROP COLUMN keep;
"""

SEEDS_SQL = """
CREATE OR REPLACE TABLE alerts AS
SELECT a.alert_uid, a.time AS alert_time, a.chain_id, e.eid AS seed, e.t0 AS seed_t0
FROM read_json('{dir}/alerts.json') a
JOIN rec_x r ON r.rec_uid = a.related_record_uid
JOIN events e ON e.corr = r.corr;

CREATE OR REPLACE TABLE truth AS
SELECT t.chain_id, x.step, e.eid
FROM (SELECT chain_id, unnest(events) AS ev FROM read_json('{dir}/ground_truth.json')) t,
     LATERAL (SELECT t.ev.step AS step, t.ev.correlation_uid AS corr) x
JOIN events e ON e.corr = x.corr;
"""


def run(data_dir: str, threads: int = 4, memory: str = "3GB") -> None:
    d = Path(data_dir)
    con = duckdb.connect()  # in memory; only the parquet output is kept
    (d / "tmp").mkdir(exist_ok=True)
    con.execute(f"SET threads = {threads}; SET memory_limit = '{memory}'; SET preserve_insertion_order = true")
    con.execute(f"SET temp_directory = '{d / 'tmp'}'; SET max_temp_directory_size = '5GB'")
    steps = [
        ("events", EVENTS_SQL.format(glob=str(d / "records-*.ndjson.gz"))),
        ("edges", EDGES_SQL),
        ("counters", COUNTERS_SQL),
        ("fold", FOLD_SQL),
        ("seeds", SEEDS_SQL.format(dir=str(d))),
    ]
    for name, sql in steps:
        t = time.perf_counter()
        con.execute(sql)
        print(f"{name}: {time.perf_counter() - t:.1f}s", flush=True)
    for q in ["SELECT count(*) FROM rec", "SELECT count(*) FROM events", "SELECT count(*) FROM inst",
              "SELECT count(*) FROM edges", "SELECT count(*) FROM alerts", "SELECT count(*) FROM truth"]:
        print(q, con.execute(q).fetchone()[0])
    print(con.execute(f"""
        SELECT r.name, count(*) FROM inst i JOIN (VALUES {', '.join(f"('{k}', {v})" for k, v in RULES.items())}) r(name, bit)
        ON i.rule = r.bit GROUP BY 1 ORDER BY 2 DESC""").fetchall())
    out = d / "parquet"
    out.mkdir(exist_ok=True)
    con.execute(f"COPY (SELECT eid, corr, host, t0, t1, n_records FROM events ORDER BY eid) TO '{out}/events.parquet'")
    con.execute(f"COPY (SELECT * FROM edges ORDER BY src, dst) TO '{out}/edges.parquet'")
    con.execute(f"COPY anchor_counts TO '{out}/anchor_counts.parquet'")
    con.execute(f"COPY alerts TO '{out}/alerts.parquet'")
    con.execute(f"COPY truth TO '{out}/truth.parquet'")
    con.close()


if __name__ == "__main__":
    run(sys.argv[1])
