"""Scenario N2: the same pruned path search as B and C, as a Cypher query in Neo4j.

Results (path count, reached count) are checked against scenario B from an
earlier abc run with the same parameters.

Usage: python -m epb.n2 data/d1 results/raw/abc-....jsonl --reps 5
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from neo4j import GraphDatabase, Query

from epb.ingest import NEO4J_AUTH, NEO4J_URI
from epb.paths import CYPHER, Params
from epb.run import ContainerMem, cgroup_cpu_usec, load_seeds


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("abc_jsonl")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args()
    d, p = Path(a.data), Params()
    seeds, truth = load_seeds(d)
    ref = {}
    for line in open(a.abc_jsonl):
        r = json.loads(line)
        if r["scenario"] == "B" and r["ok"]:
            ref[r["seed"]] = (r["paths"], r["reached"])
    drv = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    mem = ContainerMem("epb-neo4j-1")
    q = Query(CYPHER % p.hops, timeout=a.timeout)
    out = Path("results/raw") / f"n2-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    rows = []
    with drv.session() as s, out.open("w") as f:
        for rep in range(a.reps):
            for sd in seeds:
                lo, hi = p.window(sd)
                r = {"scenario": "N2", "rep": rep, "seed": sd.seed, "chain_id": sd.chain_id, "ok": True}
                mem.reset()
                c0 = cgroup_cpu_usec("epb-neo4j-1")
                t = time.perf_counter()
                try:
                    rec = s.run(q, seed=sd.seed, lo=lo, hi=hi, fanout=p.fanout, a0=sd.a0).single()
                    r["seconds"] = time.perf_counter() - t
                    r.update(paths=rec["paths"], reached=rec["reached"])
                    nodes = set(rec["nodes"])
                    if sd.chain_id:
                        tr = truth[sd.chain_id] - {sd.seed}
                        r["recall"] = len(tr & nodes) / len(tr)
                    r["equal_to_B"] = ref.get(sd.seed) == (r["paths"], r["reached"])
                except Exception as e:
                    r.update(ok=False, seconds=time.perf_counter() - t, error=f"{type(e).__name__}: {str(e)[:150]}")
                r["server_cpu_ms"] = (cgroup_cpu_usec("epb-neo4j-1") - c0) / 1000
                r["server_anon_peak"] = mem.get()
                f.write(json.dumps(r) + "\n")
                f.flush()
                rows.append(r)
                print(f"rep {rep} seed {sd.seed}: {r['seconds']:.2f}s ok={r['ok']} "
                      f"paths={r.get('paths')} eq={r.get('equal_to_B')} cpu={r['server_cpu_ms']:.0f}ms", flush=True)
    mem.close()
    ok = [r for r in rows if r["ok"]]
    lat = sorted(r["seconds"] for r in ok)
    cpu = sorted(r["server_cpu_ms"] for r in ok)
    pct = lambda xs, q: xs[int(round(q * (len(xs) - 1)))]
    print(f"\nN2 n={len(rows)} ok={len(ok)} median={statistics.median(lat):.3f}s p95={pct(lat, .95):.3f}s "
          f"max={lat[-1]:.3f}s cpu_median={statistics.median(cpu):.0f}ms cpu_p95={pct(cpu, .95):.0f}ms "
          f"anon_p95={pct(sorted(r['server_anon_peak'] for r in rows), .95) / 2**20:.0f}MB")
    first = [r for r in ok if r["rep"] == 0]
    print(f"equal to B: {sum(r['equal_to_B'] for r in first)}/{len(seeds)}")
    rec = [r["recall"] for r in first if r.get("recall") is not None]
    if rec:
        print(f"recall over chains: {sum(rec) / len(rec):.3f}")
    print(f"raw: {out}")


if __name__ == "__main__":
    main()
