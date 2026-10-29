"""Per-process state built from Hodometer's stream and polls, and the ledger persisted across runs."""
import json
import logging
import os
import threading
import time

log = logging.getLogger("state")

LEVELS = ["CLEAR", "WATCH", "SUSPECT", "HOSTILE"]


def level_index(level):
    return LEVELS.index(level) if level in LEVELS else 0


class Flow:
    """One connection as Hodometer reports it (conns reply or flow events), keyed by (proto, lport, remote, port)."""
    __slots__ = ("proto", "lport", "remote", "port", "host", "sni", "alpn", "tls", "quic", "http", "state", "local",
                 "tx", "rx", "first", "last", "connect_ms", "closed")

    def __init__(self, proto, lport, remote, port):
        self.proto, self.lport, self.remote, self.port = proto, lport, remote, port
        self.host = ""
        self.sni = ""
        self.alpn = ""
        self.tls = ""
        self.quic = False
        self.http = ""
        self.state = ""
        self.local = False
        self.tx = 0
        self.rx = 0
        self.first = time.time()
        self.last = self.first
        self.connect_ms = -1
        self.closed = False


class ProcState:
    def __init__(self, pid, name="", path=""):
        self.pid = pid
        self.name = name
        self.path = path            # Win32 path when known
        self.first_seen = time.time()
        self.last_active = self.first_seen
        self.vm = False
        self.tx_total = 0
        self.rx_total = 0
        self.tx_bps = 0.0
        self.rx_bps = 0.0
        self.conns_active = 0
        self.fails_total = 0
        self.fail_times = []        # timestamps of failed connects
        self.contacts = {}          # (remote, port, proto) -> [(t, tx, rx), ...] connection attempts, for beaconing
        self.flows = {}             # (proto, lport, remote, port) -> Flow
        self.children = []          # [{"t", "pid", "image"}]
        self.child_connected = False
        self.dll_loads = []         # image paths (only while a case is open)
        self.exited = False
        self.exit_t = 0.0
        self.killed = False
        self.seen_network = False   # appeared in list/tick/conn (not just a trace start)
        self.respawned_after_kill = False
        # identity, from inspect
        self.inspected = False
        self.inspect_t = 0.0
        self.inspect_scheduled = False
        self.inspect_failed = ""
        self.cmdline = ""
        self.user = ""
        self.integrity = ""
        self.parent_pid = 0
        self.parent_name = ""
        self.started = ""
        self.alive = True
        self.signer_state = ""
        self.signer_name = ""
        self.sha256 = ""
        self.disk_read_bps = 0.0
        self.disk_write_bps = 0.0
        self.alive_at_inspect = True
        self.respawn_of = None      # ledger key of the hostile entry this matches
        # scoring
        self.score = 0
        self.level = "CLEAR"
        self.signals = []
        self.categories = []
        self.reported_level = "CLEAR"     # highest level already sent to Sentinel
        self.first_sight_due = 0.0        # when the first_sight digest may go out (0 = not yet, -1 = sent)
        self.case_id = None
        self.capture_path = ""
        self.last_score_t = 0.0

    def remotes(self):
        """talks-to table: (remote, port, proto) -> aggregate of flows."""
        table = {}
        for f in self.flows.values():
            key = (f.remote, f.port, f.proto)
            row = table.get(key)
            if row is None:
                row = table[key] = {"ip": f.remote, "port": f.port, "proto": f.proto, "names": set(), "sni": set(),
                                    "alpn": set(), "tls": set(), "http": set(), "quic": False, "conns": 0, "tx": 0,
                                    "rx": 0, "local": f.local, "first": f.first, "last": f.last}
            if f.host:
                row["names"].add(f.host)
            if f.sni:
                row["sni"].add(f.sni)
            if f.alpn:
                row["alpn"].add(f.alpn)
            if f.tls:
                row["tls"].add(f.tls)
            if f.http:
                row["http"].add(f.http)
            row["quic"] = row["quic"] or f.quic
            row["conns"] += 1
            row["tx"] += f.tx
            row["rx"] += f.rx
            row["first"] = min(row["first"], f.first)
            row["last"] = max(row["last"], f.last)
        return table

    def hosts(self):
        """DNS names and SNIs seen, for the ledger."""
        out = set()
        for f in self.flows.values():
            if f.host:
                out.add(f.host.lower())
            if f.sni:
                out.add(f.sni.lower())
        return out


class Case:
    def __init__(self, case_id, pid, priority, brief, score, path, name):
        self.id = case_id
        self.pid = pid
        self.priority = priority
        self.brief = brief
        self.score = score
        self.path = path
        self.name = name
        self.opened = time.time()
        self.started = 0.0
        self.closed = False
        self.closed_why = ""
        self.verdict = None
        self.events = None          # the investigator's queue, once running
        self.tool_calls = 0


class Ledger:
    """What the daemon knows about a program across runs, keyed by lower-cased path.
    verdict: known | trusted | watch | hostile (set by Sentinel through mark); None until vetted."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.entries = {}
        self._dirty = False
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.entries = data
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("ledger unreadable (%s); starting empty", e)

    def save(self):
        with self._lock:
            if not self._dirty:
                return
            tmp = self.path + ".tmp"
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.entries, f, indent=1, sort_keys=True)
                os.replace(tmp, self.path)
                self._dirty = False
            except OSError as e:
                log.warning("ledger save failed: %s", e)

    @staticmethod
    def key(path):
        return (path or "").lower()

    def get(self, path):
        return self.entries.get(self.key(path))

    def touch(self, ps):
        """Record a sighting of this program: hash, signer, hosts, first/last seen."""
        if not ps.path:
            return None
        with self._lock:
            k = self.key(ps.path)
            e = self.entries.get(k)
            now = time.time()
            if e is None:
                e = self.entries[k] = {"path": ps.path, "verdict": None, "note": "", "first_seen": now, "last_seen": now,
                                       "sha256": ps.sha256, "signer": ps.signer_name, "signer_state": ps.signer_state,
                                       "hosts": [], "sightings": 0}
            e["last_seen"] = now
            e["sightings"] = e.get("sightings", 0) + 1
            if ps.sha256:
                e["sha256"] = ps.sha256
            if ps.signer_state:
                e["signer_state"] = ps.signer_state
                e["signer"] = ps.signer_name
            self._dirty = True
            return e

    def add_hosts(self, path, hosts):
        if not path or not hosts:
            return
        with self._lock:
            e = self.entries.get(self.key(path))
            if e is None:
                return
            have = set(e.get("hosts", []))
            new = set(hosts) - have
            if new:
                e["hosts"] = sorted(have | new)[:400]
                self._dirty = True

    def mark(self, path, verdict, note, ps=None, vetted_level="CLEAR"):
        with self._lock:
            k = self.key(path)
            e = self.entries.get(k)
            now = time.time()
            if e is None:
                e = self.entries[k] = {"path": path, "verdict": None, "note": "", "first_seen": now, "last_seen": now,
                                       "sha256": "", "signer": "", "signer_state": "", "hosts": [], "sightings": 0}
            e["verdict"] = verdict
            e["note"] = (note or "")[:500]
            e["marked_at"] = now
            e["vetted_level"] = vetted_level     # the daemon raises this program again only above this level
            if ps is not None:
                if ps.sha256:
                    e["sha256"] = ps.sha256
                if ps.signer_state:
                    e["signer_state"] = ps.signer_state
                    e["signer"] = ps.signer_name
                e["hosts"] = sorted(set(e.get("hosts", [])) | ps.hosts())[:400]
            self._dirty = True
            return e

    def hostile_match(self, ps):
        """A ledger entry marked hostile that this process matches by path, hash, or signer + hosts."""
        with self._lock:
            k = self.key(ps.path)
            hosts = ps.hosts()
            for ek, e in self.entries.items():
                if e.get("verdict") != "hostile":
                    continue
                if ek == k:
                    return e
                if ps.sha256 and e.get("sha256") and ps.sha256 == e["sha256"]:
                    return e
                shared = hosts & set(e.get("hosts", []))
                if len(shared) >= 2 and ps.signer_state and ps.signer_state == e.get("signer_state") \
                        and (ps.signer_name or "") == (e.get("signer") or ""):
                    return e
        return None

    def counts(self):
        with self._lock:
            c = {"known": 0, "trusted": 0, "watch": 0, "hostile": 0, "unvetted": 0}
            for e in self.entries.values():
                v = e.get("verdict")
                c[v if v in c else "unvetted"] += 1
            return c
