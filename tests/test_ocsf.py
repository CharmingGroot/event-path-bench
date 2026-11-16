"""Every kind of record the generator emits must validate against OCSF 1.9.0."""

from epb.gen import Gen
from epb.ocsf import validate


def test_all_generated_records_validate():
    g = Gen(1)
    g.topo.by_role["ws"] = g.topo.by_role["ws"][:20]
    g.topo.hosts = [h for h in g.topo.hosts if h.role != "ws"] + g.topo.by_role["ws"]
    g.day(0, chains=2, fp_alerts=3)
    kinds, bad = set(), []
    for _, recs in g.events:
        for r in recs:
            kinds.add((r["class_uid"], r["activity_id"], r["metadata"]["product"]["name"]))
            errs = validate(r)
            if errs:
                bad.append((r["metadata"]["uid"], errs))
    assert not bad, bad[:5]
    assert len(kinds) >= 12


def test_validator_rejects_unknown_and_missing():
    r = {"class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701, "time": 1,
         "severity_id": 1, "metadata": {"product": {"name": "x"}, "version": "1.9.0"},
         "device": {"type_id": 1}, "actor": {}, "bogus": 1}
    errs = validate(r)
    assert any("process: required" in e or ".process: required" in e for e in errs)
    assert any("bogus: not in schema" in e for e in errs)
