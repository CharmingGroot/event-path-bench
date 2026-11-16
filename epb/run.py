"""Scenario runner.

  python -m epb.run abc data/d1 --reps 5      # A, B, C latency, memory, temp bytes, equality, recall

Results go to results/raw/<scenario>-<timestamp>.jsonl, one line per run, and a
summary is printed. Runs alternate between approaches within one session; the
order of A, B, C rotates every repetition.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import threading
import time
from pathlib import Path

import duckdb
import psutil
import psycopg

from epb.load import PG_DSN
from epb.paths import DUCK_WALK, Params, Seed, duck_prune_query, pg_sql, prune_predicate


# --------------------------------------------------------------------------- sampling

class ContainerMem:
    """Peak anonymous memory of a container, sampled from its cgroup every 100 ms."""

    def __init__(self, container: str) -> None:
        self.proc = subprocess.Popen(
            ["docker", "exec", container, "sh", "-c",
             "while :; do grep '^anon ' /sys/fs/cgroup/memory.stat | cut -d' ' -f2; sleep 0.1; done"],
            stdout=subprocess.PIPE, text=True)
        self.peak = 0
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            v = int(line)
            with self.lock:
                self.peak = max(self.peak, v)

    def reset(self) -> None:
        with self.lock:
            self.peak = 0

    def get(self) -> int:
        time.sleep(0.15)
        with self.lock:
            return self.peak

    def close(self) -> None:
        self.proc.kill()


class ProcMem:
    """Peak RSS of this process (embedded DuckDB), sampled every 20 ms."""

    def __init__(self) -> None:
        self.p = psutil.Process(os.getpid())
        self.peak = 0
        self.on = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            if self.on:
                self.peak = max(self.peak, self.p.memory_info().rss)
            time.sleep(0.02)

    def start(self) -> None:
        self.peak = self.p.memory_info().rss
        self.on = True

    def stop(self) -> int:
        time.sleep(0.03)
        self.on = False
        return self.peak


# --------------------------------------------------------------------------- helpers

def load_seeds(d: Path) -> tuple[list[Seed], dict[str, set[int]]]:
    con = duckdb.connect()
    seeds = [Seed(*r) for r in con.execute(
        f"SELECT seed, seed_t0, alert_time, chain_id FROM '{d}/parquet/alerts.parquet' ORDER BY alert_time").fetchall()]
    truth = {c: set(e) for c, e in con.execute(
        f"SELECT chain_id, list(eid) FROM '{d}/parquet/truth.parquet' GROUP BY 1").fetchall()}
    return seeds, truth


def pg_temp_bytes(pg: psycopg.Connection) -> int:
    return pg.execute("SELECT temp_bytes FROM pg_stat_database WHERE datname = current_database()").fetchone()[0]


def summarize(rows: list[dict]) -> None:
    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]
    by = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    print(f"\n{'scenario':10} {'n':>4} {'ok':>4} {'median_s':>9} {'p95_s':>8} {'max_s':>8} "
          f"{'pg_anon_p95_MB':>14} {'duck_rss_p95_MB':>15} {'temp_MB_max':>11}")
    for sc, rs in sorted(by.items()):
        ok = [r for r in rs if r["ok"]]
        lat = [r["seconds"] for r in ok] or [float("nan")]
        print(f"{sc:10} {len(rs):4} {len(ok):4} {statistics.median(lat):9.3f} {pct(lat, .95):8.3f} {max(lat):8.3f} "
              f"{pct([r.get('pg_anon', 0) for r in rs], .95) / 2**20:14.0f} "
              f"{pct([r.get('duck_rss', 0) for r in rs], .95) / 2**20:15.0f} "
              f"{max(r.get('temp_bytes', 0) for r in rs) / 2**20:11.0f}")


# --------------------------------------------------------------------------- scenario A, B, C

def run_abc(d: Path, reps: int, params: Params, timeout_s: int, out: Path, order: list[str]) -> list[dict]:
    seeds, truth = load_seeds(d)
    pgmem = ContainerMem("epb-pg-1")
    procmem = ProcMem()
    pg = psycopg.connect(PG_DSN, autocommit=True)
    pg.execute(f"SET statement_timeout = '{timeout_s}s'")
    stat = psycopg.connect(PG_DSN, autocommit=True)
    duck = duckdb.connect()
    duck.execute("SET threads = 4; SET memory_limit = '3GB'; INSTALL postgres; LOAD postgres")
    duck.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres, READ_ONLY)")
    rows, results = [], {}
    with out.open("w") as f:
        for rep in range(reps):
            for s in seeds:
                for sc in order:
                    r = {"scenario": sc, "rep": rep, "seed": s.seed, "chain_id": s.chain_id, "ok": True}
                    pgmem.reset()
                    temp0 = pg_temp_bytes(stat)
                    t = time.perf_counter()
                    try:
                        if sc in ("A", "B"):
                            paths, reached, nodes = pg.execute(pg_sql(s, params, sc == "B")).fetchone()
                        else:
                            procmem.start()
                            duck.execute("CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM postgres_query('pg', $q)",
                                         {"q": duck_prune_query(s, params)})
                            t_prune = time.perf_counter()
                            paths, reached, nodes = duck.execute(
                                DUCK_WALK, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()
                            r["prune_s"] = t_prune - t
                            r["walk_s"] = time.perf_counter() - t_prune
                            r["edges_loaded"] = duck.execute("SELECT count(*) FROM pe").fetchone()[0]
                            r["duck_rss"] = procmem.stop()
                        r["seconds"] = time.perf_counter() - t
                        r.update(paths=paths, reached=reached)
                        nodes = set(nodes)
                        if s.chain_id:
                            tr = truth[s.chain_id] - {s.seed}
                            r["recall"] = len(tr & nodes) / len(tr)
                        results[(sc, s.seed)] = (paths, frozenset(nodes))
                    except Exception as e:  # timeouts and resource limits are results too
                        r.update(ok=False, seconds=time.perf_counter() - t, error=f"{type(e).__name__}: {str(e).splitlines()[0]}")
                        if sc == "C":
                            procmem.stop()
                    r["pg_anon"] = pgmem.get()
                    stat.execute("SELECT pg_stat_force_next_flush()")
                    r["temp_bytes"] = max(0, pg_temp_bytes(stat) - temp0)
                    f.write(json.dumps(r) + "\n")
                    f.flush()
                    rows.append(r)
                print(f"rep {rep} seed {s.seed}: " + " ".join(
                    f"{x['scenario']}={x['seconds']:.2f}s{'' if x['ok'] else '!'}" for x in rows[-len(order):]), flush=True)
            order = order[1:] + order[:1]
    pgmem.close()
    mismatch = [s.seed for s in seeds if results.get(("B", s.seed)) != results.get(("C", s.seed))]
    print(f"\nB vs C equal result sets: {len(seeds) - len(mismatch)}/{len(seeds)} {mismatch[:5]}")
    for sc in "ABC":
        rec = [r["recall"] for r in rows if r["scenario"] == sc and r.get("recall") is not None and r["rep"] == 0]
        if rec:
            print(f"{sc} recall over chains: {sum(rec) / len(rec):.3f}")
    return rows


# --------------------------------------------------------------------------- scenario D

def run_d(d: Path, reps: int, params: Params, out: Path) -> list[dict]:
    """Hop-by-hop search with intermediate results in tables: WAL bytes per mode.

    B (one recursive query) and C (DuckDB) are measured with the same WAL counter
    for comparison.
    """
    seeds, _ = load_seeds(d)
    pg = psycopg.connect(PG_DSN, autocommit=True)
    duck = duckdb.connect()
    duck.execute("SET threads = 4; SET memory_limit = '3GB'; INSTALL postgres; LOAD postgres")
    duck.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres, READ_ONLY)")
    pg.execute("CHECKPOINT")

    def lsn() -> str:
        return pg.execute("SELECT pg_current_wal_insert_lsn()").fetchone()[0]

    def wal_since(start: str) -> int:
        return int(pg.execute("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), %s)", (start,)).fetchone()[0])

    rows = []
    modes = ["table", "unlogged", "temp", "B", "C"]
    with out.open("w") as f:
        for rep in range(reps):
            for s in seeds:
                for mode in modes:
                    start, t = lsn(), time.perf_counter()
                    if mode == "B":
                        n = pg.execute(pg_sql(s, params, True)).fetchone()[0]
                    elif mode == "C":
                        duck.execute("CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM postgres_query('pg', $q)",
                                     {"q": duck_prune_query(s, params)})
                        n = duck.execute(DUCK_WALK, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()[0]
                    else:
                        kind = {"table": "", "unlogged": "UNLOGGED", "temp": "TEMP"}[mode]
                        pg.execute(f"CREATE {kind} TABLE w0 AS SELECT {s.seed}::bigint AS node, {s.a0}::bigint AS arr, "
                                   f"ARRAY[{s.seed}::bigint] AS path")
                        n = 0
                        for h in range(1, params.hops + 1):
                            pg.execute(f"""CREATE {kind} TABLE w{h} AS
                                SELECT e.dst AS node, greatest(w.arr, e.t_start) AS arr, w.path || e.dst AS path
                                FROM w{h - 1} w JOIN edges e ON e.src = w.node
                                WHERE {duck_prune_query(s, params).split('WHERE ', 1)[1]}
                                  AND e.t_end >= w.arr AND e.dst <> ALL(w.path)""")
                            n += pg.execute(f"SELECT count(*) FROM w{h}").fetchone()[0]
                        for h in range(params.hops + 1):
                            pg.execute(f"DROP TABLE w{h}")
                    r = {"scenario": f"D-{mode}", "rep": rep, "seed": s.seed, "paths": n,
                         "seconds": time.perf_counter() - t, "wal_bytes": wal_since(start), "ok": True}
                    f.write(json.dumps(r) + "\n")
                    rows.append(r)
                print(f"rep {rep} seed {s.seed}: " + " ".join(
                    f"{x['scenario'][2:]}={x['wal_bytes'] / 2**20:.1f}MB" for x in rows[-len(modes):]), flush=True)
    by = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    print(f"\n{'mode':12} {'wal_MB_total':>12} {'wal_MB_median':>13} {'wal_MB_max':>10} {'median_s':>9}")
    for sc, rs in by.items():
        w = [r["wal_bytes"] / 2**20 for r in rs]
        print(f"{sc:12} {sum(w):12.1f} {statistics.median(w):13.2f} {max(w):10.1f} "
              f"{statistics.median([r['seconds'] for r in rs]):9.3f}")
    return rows


# --------------------------------------------------------------------------- scenario E

def run_e(d: Path, params: Params, out: Path, phase_s: int, rate: int, batch: int, rounds: int) -> None:
    """Ingest at a fixed rate while path queries run; batch commit latency per phase."""
    import gzip
    seeds, _ = load_seeds(d)
    lines = []
    with gzip.open(next(d.glob("records-*.ndjson.gz")), "rt") as f:
        for i, line in enumerate(f):
            if i >= 200_000:
                break
            lines.append(line.rstrip("\n"))  # write_row escapes for COPY
    ing = psycopg.connect(PG_DSN, autocommit=True)
    ing.execute("DROP TABLE IF EXISTS records; CREATE TABLE records (id BIGSERIAL PRIMARY KEY, rec JSONB NOT NULL)")
    stop = threading.Event()
    lat: list[tuple[float, float]] = []  # (wall time, commit latency)

    def ingest() -> None:
        pos, interval = 0, batch / rate
        nxt = time.perf_counter()
        while not stop.is_set():
            t = time.perf_counter()
            with ing.cursor().copy("COPY records (rec) FROM STDIN") as cp:
                for k in range(batch):
                    cp.write_row((lines[(pos + k) % len(lines)],))
            lat.append((time.time(), time.perf_counter() - t))
            pos += batch
            nxt += interval
            time.sleep(max(0.0, nxt - time.perf_counter()))

    q = psycopg.connect(PG_DSN, autocommit=True)
    q.execute("SET statement_timeout = '60s'")
    duck = duckdb.connect()
    duck.execute("SET threads = 4; SET memory_limit = '3GB'; INSTALL postgres; LOAD postgres")
    duck.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres, READ_ONLY)")

    def query(sc: str, s: Seed) -> None:
        try:
            if sc in ("A", "B"):
                q.execute(pg_sql(s, params, sc == "B")).fetchone()
            else:
                duck.execute("CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM postgres_query('pg', $q)",
                             {"q": duck_prune_query(s, params)})
                duck.execute(DUCK_WALK, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()
        except Exception:
            pass

    th = threading.Thread(target=ingest, daemon=True)
    th.start()
    time.sleep(5)  # warm-up
    phases = []
    with out.open("w") as f:
        for rnd in range(rounds):
            for sc in ["idle", "A", "B", "C"]:
                t0, nq = time.time(), 0
                while time.time() - t0 < phase_s:
                    if sc == "idle":
                        time.sleep(0.2)
                        continue
                    query(sc, seeds[nq % len(seeds)])
                    nq += 1
                t1 = time.time()
                ls = [l for (w, l) in lat if t0 <= w < t1]
                r = {"scenario": f"E-{sc}", "round": rnd, "queries": nq, "batches": len(ls),
                     "rows_per_s": len(ls) * batch / (t1 - t0),
                     "p50_ms": 1000 * statistics.median(ls), "p95_ms": 1000 * sorted(ls)[int(.95 * (len(ls) - 1))],
                     "p99_ms": 1000 * sorted(ls)[int(.99 * (len(ls) - 1))], "max_ms": 1000 * max(ls)}
                f.write(json.dumps(r) + "\n")
                phases.append(r)
                print(json.dumps(r), flush=True)
    stop.set()
    th.join()
    print(f"\n{'phase':8} {'queries':>8} {'rows/s':>8} {'p50_ms':>7} {'p95_ms':>7} {'p99_ms':>7} {'max_ms':>7}")
    for sc in ["idle", "A", "B", "C"]:
        rs = [r for r in phases if r["scenario"] == f"E-{sc}"]
        print(f"{sc:8} {sum(r['queries'] for r in rs):8} {statistics.mean(r['rows_per_s'] for r in rs):8.0f} "
              f"{statistics.median(r['p50_ms'] for r in rs):7.1f} {statistics.median(r['p95_ms'] for r in rs):7.1f} "
              f"{statistics.median(r['p99_ms'] for r in rs):7.1f} {max(r['max_ms'] for r in rs):7.1f}")
    ing.execute("DROP TABLE records")


# --------------------------------------------------------------------------- resource accounting

def cgroup_cpu_usec(container: str) -> int:
    out = subprocess.run(["docker", "exec", container, "grep", "^usage_usec", "/sys/fs/cgroup/cpu.stat"],
                         capture_output=True, text=True, check=True).stdout
    return int(out.split()[1])


def explain_buffers(pg: psycopg.Connection, sql: str) -> dict:
    """Shared buffer blocks touched and temp blocks, from EXPLAIN (ANALYZE, BUFFERS)."""
    plan = pg.execute(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}").fetchone()[0][0]
    p = plan["Plan"]
    return {"shared_blocks": p.get("Shared Hit Blocks", 0) + p.get("Shared Read Blocks", 0),
            "temp_blocks": p.get("Temp Written Blocks", 0), "exec_ms": plan["Execution Time"]}


DUCK_WALK_EDGES = DUCK_WALK.replace(
    "walk(node, arr, hops, path)", "walk(node, arr, hops, path, prev)").replace(
    "[$seed::BIGINT]\n", "[$seed::BIGINT], NULL::BIGINT\n").replace(
    "list_append(w.path, e.dst)\n", "list_append(w.path, e.dst), w.node\n").split("SELECT count(*) - 1")[0] + \
    "SELECT count(DISTINCT (prev, node)) FILTER (WHERE prev IS NOT NULL) FROM walk"


def run_funnel(d: Path, params: Params, out: Path) -> None:
    """Per alert: how much each pruning stage keeps, and what each approach costs.

    Not timed for latency; every query runs alone so the cgroup CPU delta and
    buffer counts belong to it.
    """
    seeds, _ = load_seeds(d)
    pg = psycopg.connect(PG_DSN, autocommit=True)
    pg.execute("SET statement_timeout = '60s'")
    duck = duckdb.connect()
    duck.execute("SET threads = 4; SET memory_limit = '3GB'; INSTALL postgres; LOAD postgres")
    duck.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres, READ_ONLY)")
    me = psutil.Process(os.getpid())
    procmem = ProcMem()
    rows = []
    total_edges = pg.execute("SELECT count(*) FROM edges").fetchone()[0]
    with out.open("w") as f:
        for s in seeds:
            lo, hi = params.window(s)
            r = {"seed": s.seed, "chain_id": s.chain_id, "total": total_edges}
            r["in_window"], r["static_kept"], r["fanout_kept"] = pg.execute(f"""
                SELECT count(*), count(*) FILTER (WHERE out_rank IS NOT NULL),
                       count(*) FILTER (WHERE out_rank <= {params.fanout})
                FROM edges WHERE t_start BETWEEN {lo} AND {hi}""").fetchone()
            # A and B inside PostgreSQL: buffers and temp blocks, then CPU on a clean run
            for sc, prune in (("A", False), ("B", True)):
                sql = pg_sql(s, params, prune)
                try:
                    r[sc] = explain_buffers(pg, sql)
                    c0 = cgroup_cpu_usec("epb-pg-1")
                    pg.execute(sql).fetchone()
                    r[sc]["pg_cpu_ms"] = (cgroup_cpu_usec("epb-pg-1") - c0) / 1000
                except Exception as e:
                    r[sc] = {"error": f"{type(e).__name__}: {str(e).splitlines()[0]}"}
            # C: PostgreSQL side (pruning query) and DuckDB side (transfer + walk)
            r["C"] = explain_buffers(pg, duck_prune_query(s, params))
            c0, u0 = cgroup_cpu_usec("epb-pg-1"), sum(me.cpu_times()[:2])
            procmem.start()
            duck.execute("CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM postgres_query('pg', $q)",
                         {"q": duck_prune_query(s, params)})
            r["C"]["pg_cpu_ms"] = (cgroup_cpu_usec("epb-pg-1") - c0) / 1000
            u1 = sum(me.cpu_times()[:2])
            duck.execute(DUCK_WALK, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()
            r["C"]["app_cpu_transfer_ms"] = (u1 - u0) * 1000
            r["C"]["app_cpu_walk_ms"] = (sum(me.cpu_times()[:2]) - u1) * 1000
            r["C"]["app_rss_peak"] = procmem.stop()
            r["C"]["pe_bytes"] = duck.execute(
                "SELECT sum(memory_usage_bytes) FROM duckdb_memory()").fetchone()[0]
            r["traversed"] = duck.execute(DUCK_WALK_EDGES, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()[0]
            f.write(json.dumps(r) + "\n")
            rows.append(r)
            print(f"seed {s.seed}: window={r['in_window']} static={r['static_kept']} fanout={r['fanout_kept']} "
                  f"traversed={r['traversed']} | A={r['A'].get('pg_cpu_ms', 'ERR')} B={r['B'].get('pg_cpu_ms')} "
                  f"C_pg={r['C']['pg_cpu_ms']} C_app={r['C']['app_cpu_transfer_ms'] + r['C']['app_cpu_walk_ms']:.0f}",
                  flush=True)

    def med(xs):
        xs = [x for x in xs if x is not None]
        return statistics.median(xs) if xs else float("nan")

    def p95(xs):
        xs = sorted(x for x in xs if x is not None)
        return xs[int(round(.95 * (len(xs) - 1)))] if xs else float("nan")

    print("\npruning funnel (edges per alert, median / p95)")
    for k in ("total", "in_window", "static_kept", "fanout_kept", "traversed"):
        print(f"  {k:12} {med([r[k] for r in rows]):>12,.0f} {p95([r[k] for r in rows]):>12,.0f}")
    print("\nper-alert cost (median / p95)")
    for sc in ("A", "B", "C"):
        ok = [r[sc] for r in rows if "error" not in r[sc]]
        print(f"  {sc}: ok {len(ok)}/{len(rows)}")
        for k in ("pg_cpu_ms", "shared_blocks", "temp_blocks", "app_cpu_transfer_ms", "app_cpu_walk_ms",
                  "app_rss_peak", "pe_bytes"):
            vals = [x.get(k) for x in ok]
            if any(v is not None for v in vals):
                print(f"    {k:20} {med(vals):>14,.1f} {p95(vals):>14,.1f}")


# --------------------------------------------------------------------------- scenario F

WALK_SUMMARY_TAIL = """,
agg AS (SELECT node, min(hops) AS h, min(arr) AS a FROM walk GROUP BY node)
SELECT (SELECT count(*) - 1 FROM walk), (SELECT count(*) - 1 FROM agg),
       (SELECT {list_agg} FROM (SELECT node, h, a FROM agg ORDER BY a, node LIMIT 50) x)"""


def pg_bundle_sql(s: Seed, p: Params) -> tuple[str, str]:
    walk = pg_sql(s, p, True).split("\nSELECT count(*) - 1")[0]
    q1 = walk + WALK_SUMMARY_TAIL.format(list_agg="json_agg(json_build_array(node, h, a))")
    q2 = (f"SELECT src, count(*) FROM edges WHERE {prune_predicate(s, p)} "
          f"GROUP BY src ORDER BY 2 DESC, src LIMIT 20")
    return q1, q2


DUCK_BUNDLE_WALK = DUCK_WALK.split("\nSELECT count(*) - 1")[0] + WALK_SUMMARY_TAIL.format(
    list_agg="list([node, h, a])")
DUCK_BUNDLE_STATS = "SELECT src, count(*) FROM pe GROUP BY src ORDER BY 2 DESC, src LIMIT 20"


def run_f(d: Path, params: Params, out: Path, levels: list[int], dur_s: int, rate: int, batch: int,
          rounds: int, timeout_s: int) -> None:
    """Concurrent alerts (path search + candidate statistics) under steady ingest."""
    import gzip
    import random
    seeds, _ = load_seeds(d)
    lines = []
    with gzip.open(next(d.glob("records-*.ndjson.gz")), "rt") as f:
        for i, line in enumerate(f):
            if i >= 200_000:
                break
            lines.append(line.rstrip("\n"))
    ing = psycopg.connect(PG_DSN, autocommit=True)
    ing.execute("DROP TABLE IF EXISTS records; CREATE TABLE records (id BIGSERIAL PRIMARY KEY, rec JSONB NOT NULL)")
    stop_ing = threading.Event()
    lat: list[tuple[float, float]] = []

    def ingest() -> None:
        pos, interval, nxt = 0, batch / rate, time.perf_counter()
        while not stop_ing.is_set():
            t = time.perf_counter()
            with ing.cursor().copy("COPY records (rec) FROM STDIN") as cp:
                for k in range(batch):
                    cp.write_row((lines[(pos + k) % len(lines)],))
            lat.append((time.time(), time.perf_counter() - t))
            pos += batch
            nxt += interval
            time.sleep(max(0.0, nxt - time.perf_counter()))

    duckdb_db = duckdb.connect()
    duckdb_db.execute("SET threads = 4; SET memory_limit = '3GB'; INSTALL postgres; LOAD postgres")
    duckdb_db.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres, READ_ONLY)")
    me = psutil.Process(os.getpid())
    pgmem, procmem = ContainerMem("epb-pg-1"), ProcMem()
    th = threading.Thread(target=ingest, daemon=True)
    th.start()
    time.sleep(5)
    results = []
    with out.open("w") as f:
        for rnd in range(rounds):
            for n in levels:
                for approach in (["B", "C"] if rnd % 2 == 0 else ["C", "B"]):
                    stop = threading.Event()
                    done: list[dict] = []
                    lock = threading.Lock()

                    def worker(wid: int) -> None:
                        rng = random.Random(wid * 7919 + n)
                        if approach == "B":
                            conn = psycopg.connect(PG_DSN, autocommit=True)
                            conn.execute(f"SET statement_timeout = '{timeout_s}s'")
                        else:
                            conn = duckdb_db.cursor()
                        while not stop.is_set():
                            s = seeds[rng.randrange(len(seeds))]
                            t = time.perf_counter()
                            rec = {"seed": s.seed, "ok": True}
                            try:
                                if approach == "B":
                                    q1, q2 = pg_bundle_sql(s, params)
                                    rec["paths"] = conn.execute(q1).fetchone()[0]
                                    conn.execute(q2).fetchall()
                                else:
                                    conn.execute("CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM postgres_query('pg', $q)",
                                                 {"q": duck_prune_query(s, params)})
                                    rec["paths"] = conn.execute(
                                        DUCK_BUNDLE_WALK, {"seed": s.seed, "a0": s.a0, "hops": params.hops}).fetchone()[0]
                                    conn.execute(DUCK_BUNDLE_STATS).fetchall()
                            except Exception as e:
                                rec.update(ok=False, error=f"{type(e).__name__}: {str(e).splitlines()[0][:100]}")
                            rec["seconds"] = time.perf_counter() - t
                            with lock:
                                done.append(rec)
                        conn.close()

                    pgmem.reset()
                    procmem.start()
                    temp0 = pg_temp_bytes(ing)
                    cpu_pg0, cpu_app0 = cgroup_cpu_usec("epb-pg-1"), sum(me.cpu_times()[:2])
                    t0 = time.time()
                    ws = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
                    for w in ws:
                        w.start()
                    time.sleep(dur_s)
                    stop.set()
                    for w in ws:
                        w.join()
                    t1 = time.time()
                    ing.execute("SELECT pg_stat_force_next_flush()")
                    ok = sorted(r["seconds"] for r in done if r["ok"])
                    ls = sorted(l for (w, l) in lat if t0 <= w < t1)
                    pick = lambda xs, q: xs[int(q * (len(xs) - 1))] if xs else float("nan")
                    r = {"scenario": f"F-{approach}", "round": rnd, "workers": n, "wall_s": t1 - t0,
                         "bundles": len(done), "ok": len(ok), "errors": len(done) - len(ok),
                         "bundles_per_s": len(ok) / (t1 - t0),
                         "lat_p50_s": pick(ok, .5), "lat_p95_s": pick(ok, .95), "lat_max_s": ok[-1] if ok else None,
                         "pg_cores": (cgroup_cpu_usec("epb-pg-1") - cpu_pg0) / 1e6 / (t1 - t0),
                         "app_cores": (sum(me.cpu_times()[:2]) - cpu_app0) / (t1 - t0),
                         "pg_anon_peak_mb": pgmem.get() / 2**20, "app_rss_peak_mb": procmem.stop() / 2**20,
                         "pg_temp_mb": (pg_temp_bytes(ing) - temp0) / 2**20,
                         "ingest_rows_per_s": len(ls) * batch / (t1 - t0),
                         "ingest_p50_ms": 1000 * pick(ls, .5), "ingest_p95_ms": 1000 * pick(ls, .95),
                         "ingest_p99_ms": 1000 * pick(ls, .99),
                         "error_kinds": sorted({x["error"] for x in done if not x["ok"]})[:3]}
                    f.write(json.dumps(r) + "\n")
                    f.flush()
                    results.append(r)
                    print(f"{r['scenario']} w={n:2d} ok={r['ok']:5d} err={r['errors']:3d} {r['bundles_per_s']:6.1f}/s "
                          f"p50={r['lat_p50_s']:.3f} p95={r['lat_p95_s']:.3f} pg_cores={r['pg_cores']:.2f} "
                          f"app_cores={r['app_cores']:.2f} temp={r['pg_temp_mb']:.0f}MB "
                          f"ingest p95={r['ingest_p95_ms']:.0f} p99={r['ingest_p99_ms']:.0f}ms", flush=True)
                    time.sleep(5)
    stop_ing.set()
    th.join()
    pgmem.close()
    ing.execute("DROP TABLE records")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["abc", "d", "e", "funnel", "f"])
    ap.add_argument("data")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--hops", type=int, default=6)
    ap.add_argument("--fanout", type=int, default=10)
    ap.add_argument("--before-min", type=int, default=60)
    ap.add_argument("--after-min", type=int, default=360)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--only", default="A,B,C")
    a = ap.parse_args()
    params = Params(hops=a.hops, fanout=a.fanout, before_ms=a.before_min * 60_000, after_ms=a.after_min * 60_000)
    out_dir = Path("results/raw")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{a.scenario}-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    (out.with_suffix(".params.json")).write_text(json.dumps({**vars(a), **params.__dict__}, indent=1))
    if a.scenario == "abc":
        rows = run_abc(Path(a.data), a.reps, params, a.timeout, out, a.only.split(","))
        summarize(rows)
    elif a.scenario == "f":
        run_f(Path(a.data), params, out, levels=[1, 4, 8, 16], dur_s=60, rate=10_000, batch=2_000,
              rounds=a.reps, timeout_s=a.timeout)
    elif a.scenario == "funnel":
        run_funnel(Path(a.data), params, out)
    elif a.scenario == "d":
        run_d(Path(a.data), a.reps, params, out)
    else:
        run_e(Path(a.data), params, out, phase_s=40, rate=10_000, batch=2_000, rounds=a.reps)
    print(f"\nraw: {out}")


if __name__ == "__main__":
    main()
