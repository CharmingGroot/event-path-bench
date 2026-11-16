"""Load derived events and edges into PostgreSQL, and export CSV for Neo4j import.

Usage:
  python -m epb.load pg data/d1        # COPY into PostgreSQL, build indexes, VACUUM ANALYZE
  python -m epb.load neo4j-csv data/d1 # write data/import/{events,edges}.csv for neo4j-admin import
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import duckdb
import psycopg

PG_DSN = "host=127.0.0.1 port=55432 dbname=bench user=bench password=bench"

SCHEMA = """
DROP TABLE IF EXISTS edges; DROP TABLE IF EXISTS events;
CREATE TABLE events (eid BIGINT PRIMARY KEY, corr TEXT NOT NULL, host TEXT, t0 BIGINT NOT NULL,
                     t1 BIGINT NOT NULL, n_records INT NOT NULL);
CREATE TABLE edges (src BIGINT NOT NULL, dst BIGINT NOT NULL, rules SMALLINT NOT NULL, anchor_cnt INT NOT NULL,
                    refl BOOLEAN NOT NULL, fold_rank INT NOT NULL, t_start BIGINT NOT NULL, t_end BIGINT NOT NULL,
                    out_rank INT);
"""

INDEXES = """
ALTER TABLE edges ADD PRIMARY KEY (src, dst);
CREATE INDEX edges_src_cover ON edges (src) INCLUDE (dst, t_start, t_end, out_rank);
CREATE INDEX edges_time_cover ON edges (t_start) INCLUDE (src, dst, t_end, out_rank);
"""


def load_pg(data_dir: str) -> None:
    pq = Path(data_dir) / "parquet"
    with psycopg.connect(PG_DSN, autocommit=True) as pg:
        pg.execute(SCHEMA)
    con = duckdb.connect()
    con.execute("INSTALL postgres; LOAD postgres")
    con.execute(f"ATTACH '{PG_DSN}' AS pg (TYPE postgres)")
    for table in ("events", "edges"):
        t = time.perf_counter()
        con.execute(f"INSERT INTO pg.public.{table} SELECT * FROM '{pq}/{table}.parquet'")
        print(f"copy {table}: {time.perf_counter() - t:.1f}s", flush=True)
    con.close()
    with psycopg.connect(PG_DSN, autocommit=True) as pg:
        t = time.perf_counter()
        pg.execute(INDEXES)
        print(f"indexes: {time.perf_counter() - t:.1f}s", flush=True)
        t = time.perf_counter()
        pg.execute("VACUUM (ANALYZE) events")
        pg.execute("VACUUM (ANALYZE) edges")
        print(f"vacuum analyze: {time.perf_counter() - t:.1f}s", flush=True)
        for row in pg.execute("""SELECT relname, pg_size_pretty(pg_total_relation_size(oid)) FROM pg_class
                                 WHERE relname IN ('events', 'edges')""").fetchall():
            print(row)


def neo4j_csv(data_dir: str) -> None:
    pq = Path(data_dir) / "parquet"
    out = Path("data/import")
    out.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"""COPY (SELECT eid AS "eid:ID(Event)", host, t0 AS "t0:long", t1 AS "t1:long", 'Event' AS ":LABEL"
                         FROM '{pq}/events.parquet') TO '{out}/events.csv' (HEADER, DELIMITER ',')""")
    con.execute(f"""COPY (SELECT src AS ":START_ID(Event)", dst AS ":END_ID(Event)", rules AS "rules:int",
                                anchor_cnt AS "anchor_cnt:int", refl AS "refl:boolean", fold_rank AS "fold_rank:int",
                                t_start AS "t_start:long", t_end AS "t_end:long", out_rank AS "out_rank:int", 'REL' AS ":TYPE"
                         FROM '{pq}/edges.parquet') TO '{out}/edges.csv' (HEADER, DELIMITER ',')""")
    for f in sorted(out.iterdir()):
        print(f, f.stat().st_size)


if __name__ == "__main__":
    {"pg": load_pg, "neo4j-csv": neo4j_csv}[sys.argv[1]](sys.argv[2])
