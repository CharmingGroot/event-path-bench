"""Definition stage, incremental: stream events and their 1-hop edges in time order.

An edge becomes known when the later of its two events arrives. Each batch
holds BATCH events and the edges that become known with them, written in one
transaction (PostgreSQL: COPY into indexed tables; Neo4j: UNWIND CREATE).
Both go through a Python driver so client overhead is similar; server CPU is
measured from the container cgroup.

Usage:
  python -m epb.ingest pg data/d1
  python -m epb.ingest neo4j data/d1
"""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import duckdb

from epb.load import PG_DSN
from epb.run import ContainerMem, cgroup_cpu_usec

BATCH = 1000
NEO4J_URI, NEO4J_AUTH = "bolt://127.0.0.1:57687", ("neo4j", "benchbench")


def batches(d: Path):
    con = duckdb.connect()
    con.execute("SET memory_limit = '1GB'; SET threads = 2")
    con.execute(f"CREATE TABLE ev AS SELECT eid, corr, host, t0, t1, n_records FROM '{d}/parquet/events.parquet' ORDER BY eid")
    con.execute(f"""CREATE TABLE ed AS SELECT greatest(src, dst) // {BATCH} AS b, src, dst, rules, anchor_cnt, refl,
                    fold_rank, t_start, t_end, out_rank FROM '{d}/parquet/edges.parquet' ORDER BY b""")
    nb = con.execute(f"SELECT max(eid) // {BATCH} FROM ev").fetchone()[0]
    for b in range(nb + 1):
        evs = con.execute(f"SELECT * FROM ev WHERE eid // {BATCH} = {b}").fetchall()
        eds = con.execute(f"SELECT src, dst, rules, anchor_cnt, refl, fold_rank, t_start, t_end, out_rank "
                          f"FROM ed WHERE b = {b}").fetchall()
        yield evs, eds


def du_bytes(container: str, path: str) -> int:
    out = subprocess.run(["docker", "exec", container, "du", "-sb", path], capture_output=True, text=True).stdout
    return int(out.split()[0]) if out else 0


def report(name: str, lat: list[float], n_ev: int, n_ed: int, wall: float, extra: dict) -> dict:
    s = sorted(lat)
    r = {"engine": name, "events": n_ev, "edges": n_ed, "wall_s": wall, "events_per_s": n_ev / wall,
         "edges_per_s": n_ed / wall, "batch_p50_ms": 1000 * statistics.median(s),
         "batch_p95_ms": 1000 * s[int(.95 * (len(s) - 1))], "batch_p99_ms": 1000 * s[int(.99 * (len(s) - 1))],
         **extra}
    print(json.dumps(r, indent=1))
    out = Path("results/raw") / f"ingest-{name}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(r, indent=1))
    return r


def ingest_pg(d: Path) -> None:
    import psycopg
    pg = psycopg.connect(PG_DSN, autocommit=True)
    pg.execute("""DROP TABLE IF EXISTS ed_i; DROP TABLE IF EXISTS ev_i;
        CREATE TABLE ev_i (eid BIGINT PRIMARY KEY, corr TEXT NOT NULL, host TEXT, t0 BIGINT NOT NULL,
                           t1 BIGINT NOT NULL, n_records INT NOT NULL);
        CREATE TABLE ed_i (src BIGINT NOT NULL, dst BIGINT NOT NULL, rules SMALLINT NOT NULL, anchor_cnt INT NOT NULL,
                           refl BOOLEAN NOT NULL, fold_rank INT NOT NULL, t_start BIGINT NOT NULL, t_end BIGINT NOT NULL,
                           out_rank INT, PRIMARY KEY (src, dst));
        CREATE INDEX ed_i_src ON ed_i (src) INCLUDE (dst, t_start, t_end, out_rank);
        CREATE INDEX ed_i_time ON ed_i (t_start) INCLUDE (src, dst, t_end, out_rank);
        CHECKPOINT""")
    lsn0 = pg.execute("SELECT pg_current_wal_insert_lsn()").fetchone()[0]
    mem = ContainerMem("epb-pg-1")
    cpu0, lat, n_ev, n_ed = cgroup_cpu_usec("epb-pg-1"), [], 0, 0
    t_all = time.perf_counter()
    for evs, eds in batches(d):
        t = time.perf_counter()
        with pg.transaction():
            with pg.cursor().copy("COPY ev_i FROM STDIN") as cp:
                for row in evs:
                    cp.write_row(row)
            with pg.cursor().copy("COPY ed_i FROM STDIN") as cp:
                for row in eds:
                    cp.write_row(row)
        lat.append(time.perf_counter() - t)
        n_ev += len(evs)
        n_ed += len(eds)
        if len(lat) % 100 == 0:
            print(f"batch {len(lat)}: {n_ev} events, {n_ed} edges, {time.perf_counter() - t_all:.0f}s", flush=True)
    wall = time.perf_counter() - t_all
    extra = {
        "server_cpu_s": (cgroup_cpu_usec("epb-pg-1") - cpu0) / 1e6,
        "server_anon_peak_mb": mem.get() / 2**20,
        "wal_bytes": int(pg.execute("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), %s)", (lsn0,)).fetchone()[0]),
        "store_bytes": pg.execute("SELECT pg_total_relation_size('ev_i') + pg_total_relation_size('ed_i')").fetchone()[0],
    }
    mem.close()
    report("pg", lat, n_ev, n_ed, wall, extra)


def ingest_neo4j(d: Path) -> None:
    from neo4j import GraphDatabase
    drv = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    with drv.session() as s:
        s.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS").consume()
        s.run("CREATE INDEX event_eid IF NOT EXISTS FOR (e:Event) ON (e.eid)").consume()
        s.run("CALL db.awaitIndexes()").consume()
    store0 = du_bytes("epb-neo4j-1", "/data/databases/neo4j")
    tx0 = du_bytes("epb-neo4j-1", "/data/transactions/neo4j")
    mem = ContainerMem("epb-neo4j-1")
    cpu0, lat, n_ev, n_ed = cgroup_cpu_usec("epb-neo4j-1"), [], 0, 0
    q_ev = "UNWIND $rows AS r CREATE (:Event {eid: r[0], corr: r[1], host: r[2], t0: r[3], t1: r[4], n_records: r[5]})"
    q_ed = ("UNWIND $rows AS r MATCH (a:Event {eid: r[0]}) MATCH (b:Event {eid: r[1]}) "
            "CREATE (a)-[:REL {rules: r[2], anchor_cnt: r[3], refl: r[4], fold_rank: r[5], "
            "t_start: r[6], t_end: r[7], out_rank: r[8]}]->(b)")

    def write(tx, evs, eds):
        tx.run(q_ev, rows=[list(e) for e in evs]).consume()
        tx.run(q_ed, rows=[list(e) for e in eds]).consume()

    t_all = time.perf_counter()
    with drv.session() as s:
        for evs, eds in batches(d):
            t = time.perf_counter()
            s.execute_write(write, evs, eds)
            lat.append(time.perf_counter() - t)
            n_ev += len(evs)
            n_ed += len(eds)
            if len(lat) % 100 == 0:
                print(f"batch {len(lat)}: {n_ev} events, {n_ed} edges, {time.perf_counter() - t_all:.0f}s", flush=True)
    wall = time.perf_counter() - t_all
    extra = {
        "server_cpu_s": (cgroup_cpu_usec("epb-neo4j-1") - cpu0) / 1e6,
        "server_anon_peak_mb": mem.get() / 2**20,
        "store_bytes": du_bytes("epb-neo4j-1", "/data/databases/neo4j") - store0,
        "tx_log_bytes": du_bytes("epb-neo4j-1", "/data/transactions/neo4j") - tx0,
    }
    mem.close()
    drv.close()
    report("neo4j", lat, n_ev, n_ed, wall, extra)


if __name__ == "__main__":
    {"pg": ingest_pg, "neo4j": ingest_neo4j}[sys.argv[1]](Path(sys.argv[2]))
