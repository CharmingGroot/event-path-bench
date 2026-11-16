"""Fetch a trimmed copy of the OCSF schema for the classes this benchmark emits.

The full export endpoint refuses 1.9.0 in the legacy format, so classes and the
objects they reference are fetched one by one from the schema server API and
reduced to what the validator needs: requirement, type, object type, enum keys,
and the profiles an attribute belongs to.
"""

import json
import sys
import urllib.request
from pathlib import Path

VERSION = "1.9.0"
BASE = f"https://schema.ocsf.io/api/{VERSION}"
CLASSES = [
    "file_activity",
    "process_activity",
    "authentication",
    "network_activity",
    "http_activity",
    "dns_activity",
    "detection_finding",
]


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=30) as resp:
        return json.load(resp)


def trim(attrs: dict) -> dict:
    out = {}
    for name, a in attrs.items():
        out[name] = {
            "requirement": a.get("requirement"),
            "type": a.get("type"),
            "object_type": a.get("object_type"),
            "is_array": bool(a.get("is_array")),
            "profiles": a.get("profiles"),
            "enum": sorted(a["enum"].keys(), key=lambda k: (not k.lstrip("-").isdigit(), int(k) if k.lstrip("-").isdigit() else 0, k)) if a.get("enum") else None,
        }
    return out


def main(out_path: str) -> None:
    schema = {"version": VERSION, "classes": {}, "objects": {}}
    pending = []
    for name in CLASSES:
        c = get(f"classes/{name}")
        schema["classes"][name] = {
            "uid": c["uid"],
            "category_uid": c["category_uid"],
            "attributes": trim(c["attributes"]),
        }
        pending += [a["object_type"] for a in schema["classes"][name]["attributes"].values() if a["object_type"]]
    while pending:
        obj = pending.pop()
        if obj in schema["objects"]:
            continue
        o = get(f"objects/{obj}")
        schema["objects"][obj] = {"attributes": trim(o["attributes"])}
        pending += [a["object_type"] for a in schema["objects"][obj]["attributes"].values() if a["object_type"]]
        
    Path(out_path).write_text(json.dumps(schema, indent=1, sort_keys=True) + "\n")
    print(f"\n{len(schema['classes'])} classes, {len(schema['objects'])} objects -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "schema/ocsf-1.9.0.json")
