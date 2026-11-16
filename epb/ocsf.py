"""OCSF 1.9.0 record validation against the trimmed schema in schema/.

Checks, recursively through objects:
- every required attribute is present (profile attributes only when the
  profile is listed in metadata.profiles)
- no attribute outside the schema, except inside `unmapped`
- enum attributes (`*_id`) hold a defined value
- scalar types and array shape match
- class_uid, category_uid, and type_uid agree with each other
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "ocsf-1.9.0.json"

_SCALAR = {
    "string_t": str,
    "integer_t": int,
    "long_t": int,
    "timestamp_t": int,
    "boolean_t": bool,
    "float_t": (int, float),
    "ip_t": str,
    "port_t": int,
    "hostname_t": str,
    "url_t": str,
    "file_path_t": str,
    "file_name_t": str,
    "username_t": str,
    "email_t": str,
    "mac_t": str,
    "uuid_t": str,
    "datetime_t": str,
    "process_name_t": str,
    "subnet_t": str,
    "resource_uid_t": str,
    "file_hash_t": str,
    "bytestring_t": str,
    "json_t": object,
}


@lru_cache(maxsize=1)
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@lru_cache(maxsize=1)
def class_by_uid() -> dict[int, tuple[str, dict]]:
    return {c["uid"]: (name, c) for name, c in schema()["classes"].items()}


def _check_value(path: str, spec: dict, value, profiles: set[str], errors: list[str]) -> None:
    if spec["is_array"]:
        if not isinstance(value, list):
            errors.append(f"{path}: expected array")
            return
        for i, item in enumerate(value):
            _check_single(f"{path}[{i}]", spec, item, profiles, errors)
    else:
        _check_single(path, spec, value, profiles, errors)


def _check_single(path: str, spec: dict, value, profiles: set[str], errors: list[str]) -> None:
    if spec["type"] == "object_t":
        if not isinstance(value, dict):
            errors.append(f"{path}: expected object")
            return
        if spec["object_type"] == "object":
            return  # free-form, used by `unmapped`
        obj = schema()["objects"].get(spec["object_type"])
        if obj is None:
            errors.append(f"{path}: unknown object type {spec['object_type']}")
            return
        _check_attrs(path, obj["attributes"], value, profiles, errors)
        return
    expected = _SCALAR.get(spec["type"])
    if expected is None:
        errors.append(f"{path}: unhandled type {spec['type']}")
        return
    if expected is int and isinstance(value, bool):
        errors.append(f"{path}: expected {spec['type']}, got bool")
    elif not isinstance(value, expected):
        errors.append(f"{path}: expected {spec['type']}, got {type(value).__name__}")
    if spec["enum"] is not None and str(value) not in spec["enum"]:
        errors.append(f"{path}: {value!r} not in enum")


def _check_attrs(path: str, attrs: dict, record: dict, profiles: set[str], errors: list[str]) -> None:
    for name, spec in attrs.items():
        if spec["requirement"] != "required" or name in record:
            continue
        if spec["profiles"] and not profiles.intersection(spec["profiles"]):
            continue
        errors.append(f"{path}.{name}: required attribute missing")
    for name, value in record.items():
        spec = attrs.get(name)
        if spec is None:
            errors.append(f"{path}.{name}: not in schema")
            continue
        if spec["profiles"] and not profiles.intersection(spec["profiles"]):
            errors.append(f"{path}.{name}: needs profile {spec['profiles']}")
            continue
        _check_value(f"{path}.{name}", spec, value, profiles, errors)


def validate(record: dict) -> list[str]:
    """Return a list of problems; an empty list means the record is valid."""
    errors: list[str] = []
    cls = class_by_uid().get(record.get("class_uid"))
    if cls is None:
        return [f"class_uid {record.get('class_uid')!r} is not one of the generated classes"]
    name, spec = cls
    profiles = set(record.get("metadata", {}).get("profiles", []))
    _check_attrs(name, spec["attributes"], record, profiles, errors)
    if record.get("category_uid") != spec["category_uid"]:
        errors.append(f"{name}.category_uid: expected {spec['category_uid']}")
    if record.get("type_uid") != spec["uid"] * 100 + record.get("activity_id", -1):
        errors.append(f"{name}.type_uid: must be class_uid * 100 + activity_id")
    return errors
