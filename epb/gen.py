"""Synthetic OCSF 1.9.0 record generator.

Each simulated action becomes one event: one or more OCSF records from
different products that share `metadata.correlation_uid`. Records are written
as NDJSON in time order, one file per day, together with the alert seeds and
the ground truth of the planted attack chains.

Usage: python -m epb.gen --out data/d1 --days 1 --seed 7
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

DAY_MS = 86_400_000
MIN_MS = 60_000
T0 = 1_793_577_600_000  # 2026-11-02T00:00:00Z
VERSION = "1.9.0"
VENDOR = "event-path-bench"


# --------------------------------------------------------------------------- topology

@dataclass
class Host:
    uid: str
    name: str
    ip: str
    role: str
    type_id: int  # OCSF device.type_id: 1 Server, 2 Desktop
    user: str | None = None

    def device(self) -> dict:
        return {"type_id": self.type_id, "uid": self.uid, "hostname": self.name, "ip": self.ip}

    def endpoint(self, port: int | None = None) -> dict:
        ep = {"ip": self.ip, "hostname": self.name, "uid": self.uid}
        if port is not None:
            ep["port"] = port
        return ep


@dataclass
class Topology:
    hosts: list[Host] = field(default_factory=list)
    by_role: dict[str, list[Host]] = field(default_factory=dict)

    def add(self, role: str, count: int, type_id: int, subnet: int) -> None:
        for i in range(count):
            h = Host(
                uid=f"h-{role}-{i:04d}",
                name=f"{role}-{i:04d}",
                ip=f"10.{subnet}.{i // 250}.{i % 250 + 1}",
                role=role,
                type_id=type_id,
                user=f"u{i:04d}" if role == "ws" else None,
            )
            self.hosts.append(h)
            self.by_role.setdefault(role, []).append(h)


ROLES = [  # role, count, device.type_id, subnet
    ("ws", 1200, 2, 20),
    ("web", 20, 1, 10),
    ("app", 40, 1, 11),
    ("db", 12, 1, 12),
    ("file", 8, 1, 13),
    ("dns", 3, 1, 1),
    ("proxy", 2, 1, 2),
    ("mon", 2, 1, 3),
    ("dc", 2, 1, 4),
    ("scan", 1, 1, 5),
]


def build_topology() -> Topology:
    topo = Topology()
    for role, count, type_id, subnet in ROLES:
        topo.add(role, count, type_id, subnet)
    return topo


# --------------------------------------------------------------------------- records

class Ids:
    def __init__(self) -> None:
        self.n = 0

    def next(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}{self.n:x}"


PRODUCTS = {
    "waf": {"name": "waf-sim", "vendor_name": VENDOR},
    "edr": {"name": "edr-sim", "vendor_name": VENDOR},
    "fw": {"name": "fw-sim", "vendor_name": VENDOR},
    "proxy": {"name": "proxy-sim", "vendor_name": VENDOR},
    "dns": {"name": "dns-sim", "vendor_name": VENDOR},
    "idp": {"name": "auth-sim", "vendor_name": VENDOR},
    "det": {"name": "detect-sim", "vendor_name": VENDOR},
}

CLASSES = {  # name: (class_uid, category_uid)
    "file_activity": (1001, 1),
    "process_activity": (1007, 1),
    "detection_finding": (2004, 2),
    "authentication": (3002, 3),
    "network_activity": (4001, 4),
    "http_activity": (4002, 4),
    "dns_activity": (4003, 4),
}


def base(cls: str, activity_id: int, t: int, product: str, rec_uid: str, corr: str,
         device: Host | None, host_profile: bool, severity_id: int = 1) -> dict:
    class_uid, category_uid = CLASSES[cls]
    meta = {"product": PRODUCTS[product], "version": VERSION, "uid": rec_uid, "correlation_uid": corr}
    if host_profile:
        meta["profiles"] = ["host"]
    r = {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "time": t,
        "metadata": meta,
    }
    if device is not None:
        r["device"] = device.device()
    return r


def user_obj(uid: str, type_id: int = 1) -> dict:
    return {"uid": uid, "name": uid, "type_id": type_id}


def proc_obj(uid: str, pid: int, path: str, cmd: str | None = None, parent: dict | None = None) -> dict:
    p = {"uid": uid, "pid": pid, "name": path.rsplit("/", 1)[-1],
         "file": {"name": path.rsplit("/", 1)[-1], "path": path, "type_id": 1}}
    if cmd:
        p["cmd_line"] = cmd
    if parent:
        p["parent_process"] = parent
    return p


def file_obj(path: str) -> dict:
    return {"name": path.rsplit("/", 1)[-1], "path": path, "type_id": 1}


# --------------------------------------------------------------------------- generator

class Gen:
    def __init__(self, seed: int) -> None:
        self.rnd = random.Random(seed)
        self.ids = Ids()
        self.topo = build_topology()
        self.ext = [f"203.0.113.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
        # long-lived anchors that span events
        self.sessions: dict[str, str] = {}
        self.events: list[tuple[int, list[dict]]] = []
        self.alerts: list[dict] = []
        self.truth: list[dict] = []

    # helpers
    def R(self) -> str:
        return self.ids.next("r")

    def E(self) -> str:
        return self.ids.next("e")

    def P(self) -> str:
        return self.ids.next("p")

    def pick_dns(self) -> Host:
        # Zipf-like: resolver 0 takes most of the traffic
        return self.topo.by_role["dns"][0 if self.rnd.random() < 0.7 else self.rnd.randint(1, 2)]

    def pick_proxy(self) -> Host:
        return self.topo.by_role["proxy"][0 if self.rnd.random() < 0.8 else 1]

    def day_time(self, day0: int, office: bool) -> int:
        if office and self.rnd.random() < 0.85:
            return day0 + self.rnd.randint(8 * 60, 19 * 60 - 1) * MIN_MS + self.rnd.randint(0, MIN_MS - 1)
        return day0 + self.rnd.randint(0, DAY_MS - 1)

    def emit(self, t: int, records: list[dict]) -> None:
        self.events.append((t, records))

    # activities -------------------------------------------------------------
    def dns_query(self, t: int, src: Host, name: str | None = None) -> None:
        res, corr = self.pick_dns(), self.E()
        name = name or f"svc{self.rnd.randint(1, 4000)}.example.com"
        r1 = base("dns_activity", 1, t, "dns", self.R(), corr, src, True)
        r1.update(src_endpoint=src.endpoint(), dst_endpoint=res.endpoint(53),
                  query={"hostname": name, "type": "A"}, answers=[{"rdata": self.rnd.choice(self.ext)}])
        r2 = base("network_activity", 6, t, "fw", self.R(), corr, src, True)
        r2.update(src_endpoint=src.endpoint(), dst_endpoint=res.endpoint(53),
                  connection_info={"direction_id": 3, "protocol_name": "udp"})
        self.emit(t, [r1, r2])

    def browse(self, t: int, ws: Host) -> None:
        px, corr = self.pick_proxy(), self.E()
        host = f"site{self.rnd.randint(1, 20000)}.example.org"
        r1 = base("http_activity", 3, t, "proxy", self.R(), corr, ws, True)
        r1.update(src_endpoint=ws.endpoint(), dst_endpoint=px.endpoint(3128),
                  http_request={"http_method": "GET", "url": {"hostname": host, "path": "/", "scheme": "https",
                                                               "url_string": f"https://{host}/"}},
                  http_response={"code": 200})
        r2 = base("network_activity", 6, t, "fw", self.R(), corr, ws, True)
        r2.update(src_endpoint=ws.endpoint(), dst_endpoint=px.endpoint(3128),
                  connection_info={"direction_id": 3, "protocol_name": "tcp"})
        self.emit(t, [r1, r2])

    def ws_logon(self, t: int, ws: Host, hours: float) -> str:
        sess, corr = self.ids.next("s"), self.E()
        end = t + int(hours * 3_600_000)
        r = base("authentication", 1, t, "idp", self.R(), corr, ws, True)
        r.update(user=user_obj(ws.user), session={"uid": sess, "created_time": t},
                 logon_type_id=2, is_remote=False, start_time=t, end_time=end)
        self.emit(t, [r])
        self.sessions[ws.uid] = sess
        return sess

    def ws_process(self, t: int, ws: Host) -> None:
        corr = self.E()
        exe = self.rnd.choice(["/usr/bin/office", "/usr/bin/browser", "/usr/bin/mail", "/usr/bin/python3",
                               "/usr/bin/git", "/usr/bin/ssh", "/usr/bin/zip"])
        r = base("process_activity", 1, t, "edr", self.R(), corr, ws, False)
        r.update(actor={"user": user_obj(ws.user), "session": {"uid": self.sessions.get(ws.uid, "none")}},
                 process=proc_obj(self.P(), self.rnd.randint(1000, 60000), exe,
                                  parent={"uid": f"shell-{ws.uid}", "pid": 900, "name": "shell"}))
        self.emit(t, [r])

    def ws_file(self, t: int, ws: Host) -> None:
        corr = self.E()
        path = f"/home/{ws.user}/doc{self.rnd.randint(1, 500)}.txt"
        r = base("file_activity", self.rnd.choice([1, 2, 3]), t, "edr", self.R(), corr, ws, False)
        r.update(actor={"user": user_obj(ws.user), "session": {"uid": self.sessions.get(ws.uid, "none")},
                        "process": {"uid": self.P(), "pid": self.rnd.randint(1000, 60000), "name": "editor"}},
                 file=file_obj(path))
        self.emit(t, [r])

    def file_share(self, t: int, ws: Host) -> None:
        fs, corr = self.rnd.choice(self.topo.by_role["file"]), self.E()
        sess = self.ids.next("s")
        end = t + self.rnd.randint(5, 90) * MIN_MS
        r1 = base("authentication", 1, t, "idp", self.R(), corr, fs, True)
        r1.update(user=user_obj(ws.user), session={"uid": sess, "created_time": t}, logon_type_id=3,
                  is_remote=True, src_endpoint=ws.endpoint(), dst_endpoint=fs.endpoint(445),
                  start_time=t, end_time=end)
        r2 = base("network_activity", 1, t, "fw", self.R(), corr, ws, True)
        r2.update(src_endpoint=ws.endpoint(), dst_endpoint=fs.endpoint(445), start_time=t, end_time=end,
                  connection_info={"direction_id": 3, "protocol_name": "tcp"})
        self.emit(t, [r2, r1])  # flow first: the event belongs to the workstation that connects

    def dc_auth(self, t: int, ws: Host) -> None:
        dc, corr = self.rnd.choice(self.topo.by_role["dc"]), self.E()
        r = base("authentication", 1, t, "idp", self.R(), corr, dc, True)
        r.update(user=user_obj(ws.user), logon_type_id=3, is_remote=True,
                 src_endpoint=ws.endpoint(), dst_endpoint=dc.endpoint(88))
        self.emit(t, [r])

    def web_request(self, t: int, web: Host) -> None:
        corr = self.E()
        src = {"ip": self.rnd.choice(self.ext), "port": self.rnd.randint(30000, 65000)}
        path = self.rnd.choice(["/", "/login", "/api/items", "/static/app.js", "/search"])
        r1 = base("http_activity", self.rnd.choice([3, 6]), t, "waf", self.R(), corr, web, True)
        r1.update(src_endpoint=src, dst_endpoint=web.endpoint(443),
                  http_request={"http_method": "GET", "url": {"path": path, "hostname": "www.example.net",
                                                               "scheme": "https"}},
                  http_response={"code": 200})
        r2 = base("network_activity", 6, t, "fw", self.R(), corr, web, True)
        r2.update(src_endpoint=src, dst_endpoint=web.endpoint(443),
                  connection_info={"direction_id": 1, "protocol_name": "tcp"})
        self.emit(t, [r1, r2])

    def web_to_app(self, t: int, web: Host) -> None:
        app, corr = self.rnd.choice(self.topo.by_role["app"]), self.E()
        r = base("network_activity", 6, t, "fw", self.R(), corr, web, True)
        r.update(src_endpoint=web.endpoint(), dst_endpoint=app.endpoint(8080),
                 connection_info={"direction_id": 3, "protocol_name": "tcp"})
        self.emit(t, [r])

    def app_db_pool(self, t: int, app: Host, hours: float) -> None:
        db, corr = self.topo.by_role["db"][int(app.uid.rsplit("-", 1)[1]) % len(self.topo.by_role["db"])], self.E()
        end = t + int(hours * 3_600_000)
        r = base("network_activity", 1, t, "fw", self.R(), corr, app, True)
        r.update(src_endpoint=app.endpoint(), dst_endpoint=db.endpoint(5432), start_time=t, end_time=end,
                 connection_info={"direction_id": 3, "protocol_name": "tcp"})
        self.emit(t, [r])

    def server_process(self, t: int, h: Host) -> None:
        corr = self.E()
        exe = self.rnd.choice(["/usr/sbin/cron", "/usr/bin/logrotate", "/usr/sbin/php-fpm", "/usr/bin/backup"])
        r = base("process_activity", 1, t, "edr", self.R(), corr, h, False)
        r.update(actor={"user": user_obj("root", 2)},
                 process=proc_obj(self.P(), self.rnd.randint(1000, 60000), exe,
                                  parent={"uid": f"init-{h.uid}", "pid": 1, "name": "systemd"}))
        self.emit(t, [r])

    def monitor_poll(self, t: int, mon: Host, target: Host) -> None:
        corr = self.E()
        r = base("network_activity", 6, t, "fw", self.R(), corr, mon, True)
        r.update(src_endpoint=mon.endpoint(), dst_endpoint=target.endpoint(9100),
                 connection_info={"direction_id": 3, "protocol_name": "tcp"})
        self.emit(t, [r])

    def scan_burst(self, t: int, scanner: Host) -> None:
        targets = [h for h in self.topo.hosts if h.role != "scan"]
        for i, h in enumerate(targets):
            for j, port in enumerate((22, 445, 3389)):
                ts = t + (i * 3 + j) * 900  # spread over about an hour
                corr = self.E()
                r = base("network_activity", 1, ts, "fw", self.R(), corr, scanner, True)
                r.update(src_endpoint=scanner.endpoint(), dst_endpoint=h.endpoint(port),
                         connection_info={"direction_id": 3, "protocol_name": "tcp"})
                self.emit(ts, [r])
                corr = self.E()
                r = base("network_activity", 6, ts + 5, "fw", self.R(), corr, h, True)
                r.update(src_endpoint=h.endpoint(port), dst_endpoint=scanner.endpoint(),
                         connection_info={"direction_id": 3, "protocol_name": "tcp"})
                self.emit(ts + 5, [r])

    def beacon(self, t: int, ws: Host) -> None:
        corr = self.E()
        dst = {"ip": "198.51.100.200", "port": 443}
        r1 = base("network_activity", 6, t, "fw", self.R(), corr, ws, True)
        r1.update(src_endpoint=ws.endpoint(), dst_endpoint=dst,
                  connection_info={"direction_id": 2, "protocol_name": "tcp"})
        r2 = base("http_activity", 3, t, "proxy", self.R(), corr, ws, True)
        r2.update(src_endpoint=ws.endpoint(), dst_endpoint=dst,
                  http_request={"http_method": "GET", "url": {"hostname": "updates.example.com",
                                                               "path": "/check", "scheme": "https"}},
                  http_response={"code": 204})
        self.emit(t, [r1, r2])

    # attack chain -----------------------------------------------------------
    def attack_chain(self, t: int, chain_id: str) -> None:
        web = self.rnd.choice(self.topo.by_role["web"])
        db = self.rnd.choice(self.topo.by_role["db"])
        attacker = self.rnd.choice(self.ext)
        c2 = self.rnd.choice(self.ext)
        fpm = {"uid": self.P(), "pid": 2100, "name": "php-fpm"}
        shell_uid, agent_uid, dump_uid = self.P(), self.P(), self.P()
        shell_path, agent_path = "/var/www/html/uploads/img.php", "/tmp/.cache/agent"
        db_sess = self.ids.next("s")
        steps: list[tuple[str, int, list[dict]]] = []

        def add(name: str, dt_s: int, recs: list[dict]) -> None:
            steps.append((name, t + dt_s * 1000, recs))

        def tag(r: dict, step: str) -> dict:
            r["unmapped"] = {"epb": {"chain_id": chain_id, "step": step}}
            return r

        # e1 upload: WAF request + EDR file create, same action
        c = self.E(); ts = t
        r1 = base("http_activity", 6, ts, "waf", self.R(), c, web, True, 3)
        r1.update(src_endpoint={"ip": attacker, "port": 51000}, dst_endpoint=web.endpoint(443),
                  http_request={"http_method": "POST", "url": {"path": "/upload.php", "hostname": "www.example.net",
                                                                "scheme": "https"}}, http_response={"code": 200})
        r2 = base("file_activity", 1, ts + 200, "edr", self.R(), c, web, False, 3)
        r2.update(actor={"user": user_obj("www-data", 2), "process": fpm}, file=file_obj(shell_path))
        add("upload", 0, [tag(r1, "upload"), tag(r2, "upload")])
        e1_rec = r1["metadata"]["uid"]
        # e2 web shell spawns a shell
        c = self.E(); ts = t + 40_000
        r = base("process_activity", 1, ts, "edr", self.R(), c, web, False, 4)
        r.update(actor={"user": user_obj("www-data", 2), "process": fpm},
                 process=proc_obj(shell_uid, 2201, "/bin/sh", "sh -c id", parent=fpm))
        add("shell", 40, [tag(r, "shell")])
        # e3 tool download: file create by the shell + outbound connection
        c = self.E(); ts = t + 95_000
        r1 = base("file_activity", 1, ts, "edr", self.R(), c, web, False, 3)
        r1.update(actor={"user": user_obj("www-data", 2), "process": {"uid": shell_uid, "pid": 2201, "name": "sh"}},
                  file=file_obj(agent_path))
        r2 = base("network_activity", 6, ts - 500, "fw", self.R(), c, web, True, 3)
        r2.update(src_endpoint=web.endpoint(), dst_endpoint={"ip": c2, "port": 443},
                  actor={"process": {"uid": shell_uid, "pid": 2201, "name": "sh"}},
                  connection_info={"direction_id": 2, "protocol_name": "tcp"})
        add("download", 95, [tag(r1, "download"), tag(r2, "download")])
        # e4 dropped file executed
        c = self.E(); ts = t + 130_000
        r = base("process_activity", 1, ts, "edr", self.R(), c, web, False, 4)
        r.update(actor={"user": user_obj("www-data", 2), "process": {"uid": shell_uid, "pid": 2201, "name": "sh"}},
                 process=proc_obj(agent_uid, 2301, agent_path, parent={"uid": shell_uid, "pid": 2201, "name": "sh"}))
        add("exec", 130, [tag(r, "exec")])
        # e5 credential file read
        c = self.E(); ts = t + 190_000
        r = base("file_activity", 2, ts, "edr", self.R(), c, web, False, 4)
        r.update(actor={"user": user_obj("www-data", 2), "process": {"uid": agent_uid, "pid": 2301, "name": "agent"}},
                 file=file_obj("/var/www/html/.env"))
        add("cred_read", 190, [tag(r, "cred_read")])
        # e6 connection to the DB server, held open for 30 minutes
        c = self.E(); ts = t + 260_000
        end = ts + 30 * MIN_MS
        r = base("network_activity", 1, ts, "fw", self.R(), c, web, True, 3)
        r.update(src_endpoint=web.endpoint(), dst_endpoint=db.endpoint(5432), start_time=ts, end_time=end,
                 actor={"process": {"uid": agent_uid, "pid": 2301, "name": "agent"}},
                 connection_info={"direction_id": 3, "protocol_name": "tcp"})
        add("db_connect", 260, [tag(r, "db_connect")])
        # e7 DB authentication from the web server
        c = self.E(); ts = t + 262_000
        r = base("authentication", 1, ts, "idp", self.R(), c, db, True, 3)
        r.update(user=user_obj("app_db"), session={"uid": db_sess, "created_time": ts}, logon_type_id=3,
                 is_remote=True, src_endpoint=web.endpoint(), dst_endpoint=db.endpoint(5432),
                 start_time=ts, end_time=end)
        add("db_auth", 262, [tag(r, "db_auth")])
        # e8 dump tool in the DB session
        c = self.E(); ts = t + 420_000
        r = base("process_activity", 1, ts, "edr", self.R(), c, db, False, 4)
        r.update(actor={"user": user_obj("app_db"), "session": {"uid": db_sess}},
                 process=proc_obj(dump_uid, 4401, "/usr/bin/pg_dump", "pg_dump appdb",
                                  parent={"uid": f"init-{db.uid}", "pid": 1, "name": "postgres"}))
        add("dump", 420, [tag(r, "dump")])
        # e9 exfiltration from the DB server
        c = self.E(); ts = t + 600_000
        r = base("network_activity", 6, ts, "fw", self.R(), c, db, True, 4)
        r.update(src_endpoint=db.endpoint(), dst_endpoint={"ip": c2, "port": 443},
                 actor={"process": {"uid": dump_uid, "pid": 4401, "name": "pg_dump"}},
                 connection_info={"direction_id": 2, "protocol_name": "tcp"})
        add("exfil", 600, [tag(r, "exfil")])

        for _, ts, recs in steps:
            self.emit(ts, recs)
        self.alert(t + 2_000, web, e1_rec, chain_id)
        self.truth.append({"chain_id": chain_id, "seed_correlation_uid": steps[0][2][0]["metadata"]["correlation_uid"],
                           "events": [{"step": n, "correlation_uid": recs[0]["metadata"]["correlation_uid"]}
                                      for n, _, recs in steps]})

    def alert(self, t: int, host: Host, related_record: str, chain_id: str | None) -> None:
        corr = self.ids.next("a")
        r = base("detection_finding", 1, t, "det", self.R(), corr, host, False, 4 if chain_id else 3)
        r.update(finding_info={"uid": self.ids.next("f"), "title": "Suspicious web upload" if chain_id
                               else "Suspicious process",
                               "related_events": [{"uid": related_record}]},
                 is_alert=True)
        if chain_id:
            r["unmapped"] = {"epb": {"chain_id": chain_id}}
        self.emit(t, [r])
        self.alerts.append({"alert_uid": r["metadata"]["uid"], "related_record_uid": related_record,
                            "time": t, "host": host.uid, "chain_id": chain_id})

    # one day ----------------------------------------------------------------
    def day(self, d: int, chains: int, fp_alerts: int) -> None:
        day0 = T0 + d * DAY_MS
        rnd, roles = self.rnd, self.topo.by_role
        for ws in roles["ws"]:
            self.ws_logon(day0 + rnd.randint(7 * 60, 9 * 60) * MIN_MS, ws, rnd.uniform(7, 10))
        for ws in roles["ws"]:
            for _ in range(60):
                self.dns_query(self.day_time(day0, True), ws)
            for _ in range(80):
                self.browse(self.day_time(day0, True), ws)
            for _ in range(100):
                self.ws_process(self.day_time(day0, True), ws)
            for _ in range(60):
                self.ws_file(self.day_time(day0, True), ws)
            for _ in range(10):
                self.file_share(self.day_time(day0, True), ws)
            for _ in range(20):
                self.dc_auth(self.day_time(day0, True), ws)
        servers = [h for h in self.topo.hosts if h.role not in ("ws", "scan")]
        for h in servers:
            for _ in range(200):
                self.dns_query(self.day_time(day0, False), h)
            for _ in range(rnd.randint(20, 60)):
                self.server_process(self.day_time(day0, False), h)
        for web in roles["web"]:
            for _ in range(5000):
                self.web_request(self.day_time(day0, False), web)
            for _ in range(2000):
                self.web_to_app(self.day_time(day0, False), web)
        for app in roles["app"]:
            for k in range(12):
                for _ in range(4):
                    self.app_db_pool(day0 + k * 2 * 3_600_000 + rnd.randint(0, 600_000), app, 2.0)
        for mon in roles["mon"]:
            for target in servers:
                for k in range(0, DAY_MS, 15 * MIN_MS * len(roles["mon"])):
                    self.monitor_poll(day0 + k + rnd.randint(0, 60_000), mon, target)
            for target in roles["ws"][mon is roles["mon"][1]::2]:
                for k in range(0, DAY_MS, 60 * MIN_MS):
                    self.monitor_poll(day0 + k + rnd.randint(0, 600_000), mon, target)
        self.scan_burst(day0 + 2 * 3_600_000, roles["scan"][0])
        for ws in roles["ws"][:10]:
            for k in range(0, DAY_MS, MIN_MS):
                self.beacon(day0 + k + rnd.randint(0, 2000), ws)
        for i in range(chains):
            self.attack_chain(day0 + rnd.randint(9 * 60, 17 * 60) * MIN_MS, f"chain-{d:02d}-{i:02d}")
        by_uid = {h.uid: h for h in self.topo.hosts}
        for _ in range(fp_alerts):  # alerts on ordinary events, no planted chain behind them
            t, recs = rnd.choice(self.events)
            if "device" not in recs[0] or recs[0]["class_uid"] == 2004:
                continue
            self.alert(t + 2_000, by_uid[recs[0]["device"]["uid"]], recs[0]["metadata"]["uid"], None)


def write_day(events: list[tuple[int, list[dict]]], path: Path) -> int:
    events.sort(key=lambda e: e[0])
    n = 0
    with gzip.open(path, "wt", compresslevel=1) as f:
        for _, recs in events:
            for r in recs:
                f.write(json.dumps(r, separators=(",", ":")))
                f.write("\n")
                n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--chains-per-day", type=int, default=5)
    ap.add_argument("--fp-alerts-per-day", type=int, default=20)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    g = Gen(args.seed)
    total = 0
    for d in range(args.days):
        g.events = []
        g.day(d, args.chains_per_day, args.fp_alerts_per_day)
        n = write_day(g.events, out / f"records-{d:03d}.ndjson.gz")
        total += n
        print(f"day {d}: {len(g.events)} events, {n} records")
    (out / "alerts.json").write_text(json.dumps(g.alerts, indent=1))
    (out / "ground_truth.json").write_text(json.dumps(g.truth, indent=1))
    (out / "hosts.json").write_text(json.dumps([h.__dict__ for h in g.topo.hosts]))
    print(f"total {total} records, {len(g.alerts)} alerts, {len(g.truth)} chains")


if __name__ == "__main__":
    main()
