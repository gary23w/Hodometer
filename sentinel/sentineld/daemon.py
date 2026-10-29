"""The sentinel daemon: owns the Hodometer connections, scores every process in code, batches digests to Sentinel,
starts evidence capture at SUSPECT, and runs up to four investigators in parallel."""
import ctypes
import hashlib
import heapq
import json
import logging
import os
import queue
import sys
import threading
import time

from . import prompts, rubric, tools
from .hodometer import AuthGate, HodometerClient
from .models import ModelError, ModelSession, Transcript
from .state import Case, Flow, Ledger, ProcState, level_index

log = logging.getLogger("daemon")

LEVEL_SCORE = {"WATCH": 3, "SUSPECT": 5, "HOSTILE": 7}
MB_ICONWARNING, MB_TOPMOST, MB_SETFOREGROUND = 0x30, 0x40000, 0x10000


class Config:
    def __init__(self, **kw):
        self.port = 48201
        self.dry_run = True
        self.model = "claude-sonnet-5-5"
        self.watch_model = None
        self.effort = "medium"
        self.max_investigators = 4
        self.state_dir = ""
        self.prompts_path = ""
        self.use_fallback = True
        self.models_enabled = True
        self.popup = False
        self.heartbeat_s = 60
        self.batch_s = 5
        self.context_limit = 100000
        self.capture_s = 300
        self.test_cases = []
        self.max_items_per_turn = 15
        self.__dict__.update(kw)
        if not self.watch_model:
            self.watch_model = self.model


def nt_device_map():
    out = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
            out[buf.value.lower()] = f"{letter}:"
    return out


def nt_to_win32(path, devmap):
    if not path or not path.startswith("\\Device\\"):
        return path
    low = path.lower()
    best = ""
    for dev in devmap:
        if low.startswith(dev + "\\") and len(dev) > len(best):
            best = dev
    return devmap[best] + path[len(best):] if best else path


_hash_cache = {}


def sha256_file(path):
    if not path:
        return ""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path.lower(), st.st_size, int(st.st_mtime))
    h = _hash_cache.get(key)
    if h is not None:
        return h
    try:
        d = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                d.update(chunk)
        h = d.hexdigest()
    except OSError:
        h = ""
    if len(_hash_cache) > 5000:
        _hash_cache.clear()
    _hash_cache[key] = h
    return h


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.dry_run = cfg.dry_run
        self.state_dir = cfg.state_dir
        self.transcripts_dir = os.path.join(self.state_dir, "transcripts")
        os.makedirs(self.transcripts_dir, exist_ok=True)
        self.ledger = Ledger(os.path.join(self.state_dir, "ledger.json"))
        self.gate = AuthGate()
        self.stream = HodometerClient("stream", cfg.port, self.gate, on_event=self._enqueue_event, on_pending=self._on_pending)
        self.control = HodometerClient("control", cfg.port, self.gate, on_event=None, on_pending=self._on_pending)
        self._control_lock = threading.Lock()
        self.devmap = nt_device_map()
        self.lock = threading.RLock()
        self.procs = {}
        self.events = queue.Queue(maxsize=50000)
        self.events_dropped = 0
        self.stop = threading.Event()
        self.outbox = []
        self.outbox_cv = threading.Condition()
        self.last_send = 0.0
        self.cases = {}
        self.cased_pids = set()
        self.case_queue = []
        self.case_seq = 0
        self.running_cases = {}
        self.capture = {"pid": 0, "score": 0, "until": 0.0, "path": "", "by": ""}
        self.inspect_q = queue.Queue()
        self.inspect_pending = set()
        self.active_pids = set()
        self.hodometer_status = {}
        self.killed_paths = {}
        self.resolved = {}          # ip -> (name or "", t): names from ticks and Hodometer's resolve (DNS, PTR, SNI)
        self.first_sight_keys = set()
        self.self_pid = os.getpid()
        self.self_ppid = os.getppid()
        self.self_exe = (sys.executable or "").lower()
        self.hodometer_pid = 0
        self.test_cases = list(cfg.test_cases)
        self.stats = {"first_sight": 0, "cases": 0, "reports": 0, "turns": 0, "events": 0, "inspects": 0}
        self.started = time.time()
        self._pending_told = 0.0
        self.api_client = None
        self.blocks = None
        self.sentinel = None
        self.sentinel_system = ""
        self.investigator_system = ""
        self.models_enabled = cfg.models_enabled
        self.outbox_log = os.path.join(self.state_dir, "outbox.jsonl")
        self.actions_log = os.path.join(self.state_dir, "actions.log")
        self.notifications_log = os.path.join(self.state_dir, "notifications.log")
        self.last_status_line = ""

    # ================================================================== lifecycle
    def run(self):
        self._banner()
        if self.models_enabled:
            self._setup_models()
        threads = [
            threading.Thread(target=self._event_loop, name="events", daemon=True),
            threading.Thread(target=self._poll_loop, name="poll", daemon=True),
            threading.Thread(target=self._inspect_worker, name="inspect", daemon=True),
            threading.Thread(target=self._ticker, name="ticker", daemon=True),
            threading.Thread(target=self._console, name="console", daemon=True),
        ]
        if self.models_enabled:
            threads.append(threading.Thread(target=self._sentinel_loop, name="sentinel", daemon=True))
        for t in threads:
            t.start()
        self._say("Connecting to Hodometer on 127.0.0.1:%d ..." % self.cfg.port)
        try:
            self._supervise()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            with self.outbox_cv:
                self.outbox_cv.notify_all()
            self.ledger.save()
            for c in (self.stream, self.control):
                c.close()
            self._say("stopped.")

    def _banner(self):
        self._say(f"sentinel daemon · mode {'DRY-RUN (kill/block logged, never sent)' if self.dry_run else 'LIVE'} · "
                  f"models {'on: ' + self.cfg.model if self.models_enabled else 'off'} · state {self.state_dir}")
        self._say(f"this program: {sys.executable} (pid {self.self_pid})")

    def _setup_models(self):
        import anthropic
        try:
            self.blocks = prompts.load_blocks(self.cfg.prompts_path)
        except (OSError, ValueError) as e:
            self._say(f"cannot load prompts from {self.cfg.prompts_path}: {e}; models off")
            self.models_enabled = False
            return
        self.sentinel_system = prompts.sentinel_system(self.blocks, self.dry_run)
        self.investigator_system = prompts.investigator_system(self.blocks, self.dry_run)
        if not os.environ.get("ANTHROPIC_API_KEY"):
            self._say("ANTHROPIC_API_KEY is not set; the SDK will look for another credential (ant auth login profile)")
        self.api_client = anthropic.Anthropic(timeout=180.0, max_retries=2)
        self.sentinel = ModelSession(self.api_client, self.cfg.model, self.sentinel_system, tools.SENTINEL_TOOLS,
                                     self.cfg.effort, "sentinel", use_fallback=self.cfg.use_fallback,
                                     transcript=Transcript(os.path.join(self.transcripts_dir, "sentinel.jsonl")),
                                     context_limit=self.cfg.context_limit)

    def _supervise(self):
        """Main thread: keep the stream connection up (and the control one when models run), save the ledger."""
        last_save = time.time()
        delay = 5.0
        while not self.stop.is_set():
            if not self.stream.alive:
                st = self._connect(self.stream)
                if st == "allowed":
                    delay = 5.0
                    self._after_stream_connect()
                elif st in ("refused", "closed"):
                    log.info("Hodometer not reachable (%s); retry in %.0f s", st, delay)
                    self.stop.wait(delay)
                    delay = min(delay * 2, 60.0)
                elif st == "cooldown":
                    self.stop.wait(5.0)
                elif st == "denied":
                    self.stop.wait(5.0)
            if self.models_enabled and self.stream.alive and not self.control.alive and self.gate.seconds_to_wait() == 0:
                self._control_conn()
            if time.time() - last_save > 30:
                self.ledger.save()
                last_save = time.time()
            self.stop.wait(1.0)

    def _connect(self, client):
        wait = self.gate.seconds_to_wait()
        if wait > 0:
            if wait > 4:
                log.info("[%s] not connecting for another %.0f s (denial cooldown)", client.label, wait)
            return "cooldown"
        st = client.connect()
        if st == "allowed":
            self._say(f"[{client.label}] allowed by Hodometer" + (" (remembered)" if client.remembered else " (this time only)"))
        elif st == "denied":
            self._denied_message(client)
        return st

    def _after_stream_connect(self):
        r = self.stream.command("watch all", 15)
        if r.get("reply") != "watch":
            self._say(f"watch all failed: {r.get('error')}")
        st = self.stream.command("status", 15)
        self.hodometer_status.update({k: st.get(k) for k in ("version", "etw", "audit", "audit_auto", "clients", "uptime_s") if k in st})
        text = (f"stream connection to Hodometer {st.get('version', '?')} is up and watching every process; "
                f"etw {st.get('etw')}, audit {st.get('audit')}")
        if st.get("etw") != "running":
            text += " — Hodometer cannot see traffic (etw not running)"
        if st.get("audit") != "on":
            text += " — connection events are missing (audit off)"
        self._say(text)
        self._system("connection", text)
        uptime = int(st.get("uptime_s", 0) or 0)
        if uptime < self.hodometer_status.get("last_uptime_s", 1 << 30):
            self.first_sight_keys.clear()    # Hodometer restarted: every program is a first sight again
        self.hodometer_status["last_uptime_s"] = uptime

    def _control_conn(self):
        """Sentinel's connection, opened lazily; returns the client when allowed, else None."""
        with self._control_lock:
            if self.control.alive and self.control.auth == "allowed":
                return self.control
            if self.gate.seconds_to_wait() > 0:
                return None
            st = self._connect(self.control)
            return self.control if st == "allowed" else None

    def _on_pending(self, client):
        if time.time() - self._pending_told < 20:
            return
        self._pending_told = time.time()
        self._say("")
        self._say("Sentinel is connecting to Hodometer. A Hodometer window is asking whether to allow")
        self._say(f"    {sys.executable}")
        self._say("Click **Allow always** so Sentinel can protect you continuously. **Allow once** works until Sentinel restarts.")
        self._say("")

    def _denied_message(self, client):
        n = self.gate.denials
        self._say(f"Hodometer denied this program ({client.auth_why}). Sentinel is off until you allow it; "
                  f"it will not try again for 10 minutes (every earlier attempt counts as another denial).")
        if n >= 3:
            self._say("Three denials: Hodometer may have firewalled this program. Remove the "
                      "\"Hodometer block: python.exe\" rule in Windows Firewall, or send `pardon sentinel` from a trusted client.")
        self._system("auth", f"Hodometer denied connection {client.label} ({client.auth_why}); denials {n}; next attempt in 10 min")

    def auth_status_json(self):
        wait = self.gate.seconds_to_wait()
        if wait > 0 and self.gate.denied_until > time.time():
            return json.dumps({"ev": "auth", "status": "denied", "path": sys.executable, "retry_in_s": int(wait),
                               "denials": self.gate.denials})
        if self.control.auth == "pending":
            return json.dumps({"ev": "auth", "status": "pending", "path": sys.executable})
        return json.dumps({"reply": "error", "error": "not connected to Hodometer", "path": sys.executable})

    # ================================================================== console / notifications / logs
    def _say(self, text):
        print(f"{time.strftime('%H:%M:%S')} {text}", flush=True)

    def notify_user(self, level, text, source="daemon"):
        bar = {"info": "·", "alert": "⚠", "incident": "⛔"}.get(level, "·")
        print(f"\n{bar} [{source} {level}] {now_str()}\n{text}\n", flush=True)
        try:
            with open(self.notifications_log, "a", encoding="utf-8") as f:
                f.write(f"{now_str()} {level} {source}\n{text}\n\n")
        except OSError:
            pass
        if self.cfg.popup and level in ("alert", "incident"):
            threading.Thread(target=lambda: ctypes.windll.user32.MessageBoxW(
                0, text, f"Sentinel {level}", MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND), daemon=True).start()

    def log_action(self, label, cmd, outcome, detail):
        line = f"{now_str()} [{label}] {outcome}: {cmd} — {detail}"
        log.info("action %s", line)
        try:
            with open(self.actions_log, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    # ================================================================== items to Sentinel
    def add_item(self, item, urgent=False):
        item.setdefault("t", now_str())
        try:
            with open(self.outbox_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        except OSError:
            pass
        with self.outbox_cv:
            self.outbox.append((urgent, item))
            self.outbox_cv.notify_all()

    def _system(self, kind, text, urgent=False):
        self.add_item({"type": "system", "kind": kind, "text": text}, urgent)

    # ================================================================== process table
    @staticmethod
    def _same_program(a, b):
        return a.rsplit("\\", 1)[-1].lower() == b.rsplit("\\", 1)[-1].lower()

    def _proc(self, pid, name="", path="", network=False):
        """Get or create the ProcState for a pid (caller holds self.lock). Hodometer spells the same program's path
        as an NT device path in some replies and Win32 in others, so a pid is only treated as reused when the
        program name changes."""
        path = nt_to_win32(path, self.devmap) if path else ""
        ps = self.procs.get(pid)
        if ps is not None:
            if path and ps.path and ps.path.lower() != path.lower():
                if self._same_program(ps.path, path):
                    if ps.path.startswith("\\Device\\"):
                        ps.path = path
                else:
                    ps = None            # the pid was reused by another program
            elif name and ps.name and name.lower() != ps.name.lower() and not path and not ps.path:
                ps = None
        if ps is None:
            ps = self.procs[pid] = ProcState(pid, name or "", path or "")
        else:
            if name and not ps.name:
                ps.name = name
            if path and not ps.path:
                ps.path = path
        if network:
            ps.seen_network = True
            if not ps.inspected and not ps.inspect_scheduled and (ps.path or ps.name):
                ps.inspect_scheduled = True
                self.inspect_q.put(pid)
        return ps

    def _contact(self, ps, ip, port, proto, host, lport=None, t=None):
        t = t or time.time()
        key = (ip, port, proto)
        lst = ps.contacts.setdefault(key, [])
        lst.append((t, 0, 0))
        if len(lst) > 80:
            del lst[:-80]
        if lport is None:
            if not any(f.remote == ip and f.port == port and f.proto == proto for f in ps.flows.values()):
                f = ps.flows[(proto, 0, ip, port)] = Flow(proto, 0, ip, port)
                f.host = host or ""
                f.local = not rubric.is_internet(ip)
        ps.last_active = t
        # a child that connects out within 60 s of its start scores L3 on the parent
        parent = self.procs.get(ps.parent_pid) if ps.parent_pid else None
        if parent is not None:
            for c in parent.children:
                if c["pid"] == ps.pid and not c.get("connected") and t - c["t"] <= 60:
                    c["connected"] = True
                    parent.child_connected = True
                    self._rescore(parent, force=True)

    # ================================================================== stream events
    def _enqueue_event(self, ev):
        # watch all streams every DLL load on the machine; only pids with an open case need them (B1)
        if ev.get("ev") == "trace" and ev.get("kind") == "image" and ev.get("pid") not in self.cased_pids:
            return
        try:
            self.events.put_nowait(ev)
        except queue.Full:
            self.events_dropped += 1

    def _event_loop(self):
        while not self.stop.is_set():
            try:
                ev = self.events.get(timeout=1.0)
            except queue.Empty:
                continue
            self.stats["events"] += 1
            try:
                self._handle_event(ev)
            except Exception:
                log.exception("event handling failed: %s", str(ev)[:300])

    def _handle_event(self, ev):
        kind = ev.get("ev")
        if kind == "tick":
            self._on_tick(ev)
        elif kind == "flow":
            self._on_flow(ev)
        elif kind == "trace":
            self._on_trace(ev)
        elif kind == "conn":
            self._on_conn(ev)
        elif kind == "capture":
            self._on_capture(ev)
        elif kind == "killed":
            with self.lock:
                ps = self.procs.get(int(ev.get("pid", 0) or 0))
                if ps:
                    ps.killed = True
                    if ps.path:
                        self.killed_paths[ps.path.lower()] = time.time()
            self._say(f"Hodometer: killed pid {ev.get('pid')} by {ev.get('by', '?')}")
        elif kind in ("blocked", "unblocked"):
            self._say(f"Hodometer: {kind} {ev.get('path')}")
        elif kind == "intruder":
            self._system("auth", f"Hodometer firewalled a program after repeated denials: {ev.get('path')}", urgent=True)
        elif kind == "audit":
            if ev.get("enabled") is False:
                self._system("audit", f"Windows connection auditing is off ({ev.get('action')}); connection events are missing")
        elif kind == "_closed":
            self._system("connection", "stream connection to Hodometer dropped; reconnecting", urgent=True)
            self._say("stream connection to Hodometer dropped; reconnecting")
        elif kind == "client":
            log.info("client event: %s", ev)

    def _on_tick(self, ev):
        now = time.time()
        active = set()
        with self.lock:
            for p in ev.get("procs", []):
                pid = int(p.get("pid", 0) or 0)
                if pid <= 0:
                    continue
                ps = self._proc(pid, p.get("name", ""), p.get("path", ""), network=True)
                ps.tx_bps = float(p.get("tx_bps", 0) or 0)
                ps.rx_bps = float(p.get("rx_bps", 0) or 0)
                ps.tx_total = int(p.get("tx_total", 0) or 0)
                ps.rx_total = int(p.get("rx_total", 0) or 0)
                ps.vm = bool(p.get("vm"))
                ps.conns_active = int(p.get("conns", 0) or 0)
                fails = int(p.get("fails", 0) or 0)
                if fails > ps.fails_total:
                    ps.fail_times.extend([now] * min(fails - ps.fails_total, 50))
                    ps.fail_times = ps.fail_times[-200:]
                ps.fails_total = fails
                ps.last_active = now
                active.add(pid)
                rem, host = p.get("remote", ""), p.get("host", "")
                if rem and host and ":" in rem:
                    self.resolved[rem.rsplit(":", 1)[0]] = (host, now)
            self.active_pids = active
        prev = dict(self.hodometer_status)
        self.hodometer_status.update({"etw": ev.get("etw"), "audit": ev.get("audit"), "tx_mbps": ev.get("tx_mbps"),
                                      "rx_mbps": ev.get("rx_mbps"), "tick_t": now})
        if prev.get("etw") and ev.get("etw") != prev.get("etw"):
            self._system("etw", f"Hodometer etw session is now {ev.get('etw')}" + ("" if ev.get("etw") == "running" else " — it cannot see traffic"), urgent=True)
        if prev.get("audit") and ev.get("audit") != prev.get("audit"):
            self._system("audit", f"connection auditing is now {ev.get('audit')}")

    def _on_conn(self, ev):
        pid = int(ev.get("pid", 0) or 0)
        if pid <= 0:
            return
        path = nt_to_win32(ev.get("path", ""), self.devmap)
        proto = "udp" if str(ev.get("proto")) == "17" else "tcp"
        ip = ev.get("dst", "")
        if ":" in ip and not ip.startswith("["):
            proto += "6"
        with self.lock:
            ps = self._proc(pid, ev.get("app", ""), path, network=True)
            self._contact(ps, ip, int(ev.get("port", 0) or 0), proto, ev.get("host", ""))

    def _on_flow(self, ev):
        pid = int(ev.get("pid", 0) or 0)
        kind = ev.get("kind")
        now = time.time()
        with self.lock:
            ps = self.procs.get(pid)
            if ps is None:
                ps = self._proc(pid, "", "", network=True)
            if kind == "failed" and "remote" not in ev:
                ps.fail_times.append(now)
                ps.fail_times = ps.fail_times[-200:]
                self._rescore(ps)
                return
            proto, lport, remote, port = ev.get("proto", "tcp"), int(ev.get("lport", 0) or 0), ev.get("remote", ""), int(ev.get("port", 0) or 0)
            key = (proto, lport, remote, port)
            f = ps.flows.get(key)
            if f is None:
                f = ps.flows[key] = Flow(proto, lport, remote, port)
                f.local = not rubric.is_internet(remote)
                ps.flows.pop((proto, 0, remote, port), None)
            if ev.get("host"):
                f.host = ev["host"]
            f.last = now
            if kind in ("connect", "reconnect"):
                self._contact(ps, remote, port, proto, ev.get("host", ""), lport=lport, t=now)
            elif kind == "established":
                f.connect_ms = int(ev.get("connect_ms", -1) or -1)
                f.state = "established"
            elif kind == "closed":
                f.tx, f.rx = int(ev.get("tx", f.tx) or 0), int(ev.get("rx", f.rx) or 0)
                f.closed = True
                f.state = "closed"
                lst = ps.contacts.get((remote, port, proto))
                if lst and lst[-1][1] == 0 and lst[-1][2] == 0:
                    lst[-1] = (lst[-1][0], f.tx, f.rx)
            elif kind == "failed":
                f.state = "failed"
                f.closed = True
                ps.fail_times.append(now)
                ps.fail_times = ps.fail_times[-200:]
            self._trim_flows(ps)
            self._rescore(ps)

    def _on_trace(self, ev):
        kind = ev.get("kind")
        pid = int(ev.get("pid", 0) or 0)
        now = time.time()
        with self.lock:
            if kind == "start":
                ppid = int(ev.get("ppid", 0) or 0)
                image = nt_to_win32(ev.get("image", ""), self.devmap)
                parent = self.procs.get(ppid)
                if parent is not None:
                    parent.children.append({"t": now, "pid": pid, "image": image, "connected": False})
                    parent.children = parent.children[-100:]
                    case = self.cases.get(parent.case_id) if parent.case_id else None
                    if case and case.events is not None:
                        self._case_push(case, {"ev": "daemon", "kind": "child", "pid": pid, "ppid": ppid, "image": image})
                child = self.procs.get(pid)
                if child is None or (child.path and image and not self._same_program(child.path, image)):
                    child = self.procs[pid] = ProcState(pid, image.rsplit("\\", 1)[-1], image)
                child.parent_pid = ppid
                if parent is not None and not child.parent_name:
                    child.parent_name = parent.name
                if child.path and child.path.lower() in self.killed_paths and now - self.killed_paths[child.path.lower()] < 3600:
                    child.respawned_after_kill = True
            elif kind == "stop":
                ps = self.procs.get(pid)
                if ps is not None:
                    ps.exited = True
                    ps.exit_t = now
                    ps.alive = False
                    self._rescore(ps, force=True)
            elif kind == "image":
                ps = self.procs.get(pid)
                if ps is not None and ps.case_id:
                    ps.dll_loads.append(nt_to_win32(ev.get("image", ""), self.devmap))
                    ps.dll_loads = ps.dll_loads[-200:]
                    self._rescore(ps)

    def _on_capture(self, ev):
        pid = int(ev.get("pid", 0) or 0)
        path = ev.get("path", "")
        with self.lock:
            ps = self.procs.get(pid)
            if ps is not None:
                ps.capture_path = path
            if self.capture.get("pid") == pid:
                self.capture.update({"pid": 0, "score": 0, "until": 0.0, "by": ""})
        self._say(f"capture closed: {path} ({ev.get('packets')} packets, {ev.get('bytes')} bytes, pid {pid})")

    @staticmethod
    def _trim_flows(ps):
        if len(ps.flows) <= 600:
            return
        closed = sorted((k for k, f in ps.flows.items() if f.closed), key=lambda k: ps.flows[k].last)
        for k in closed[:len(ps.flows) - 500]:
            del ps.flows[k]

    # ================================================================== polling
    def _poll_loop(self):
        next_list = 0.0
        next_conns = 0.0
        while not self.stop.is_set():
            now = time.time()
            if self.stream.alive and self.stream.auth == "allowed":
                try:
                    if now >= next_list:
                        self._poll_list()
                        next_list = time.time() + 10
                    if now >= next_conns:
                        self._poll_conns()
                        next_conns = time.time() + 3
                except Exception:
                    log.exception("poll failed")
            self.stop.wait(0.5)

    def _poll_list(self):
        r = self.stream.command("list", 30)
        if r.get("reply") != "list":
            return
        with self.lock:
            for p in r.get("procs", []):
                pid = int(p.get("pid", 0) or 0)
                if pid <= 0:
                    continue
                ps = self._proc(pid, p.get("name", ""), p.get("path", ""), network=True)
                ps.tx_total = int(p.get("tx_total", 0) or 0)
                ps.rx_total = int(p.get("rx_total", 0) or 0)
                ps.vm = bool(p.get("vm"))
                ps.conns_active = int(p.get("conns", 0) or 0)
                ps.fails_total = max(ps.fails_total, int(p.get("fails", 0) or 0))

    def _poll_conns(self):
        with self.lock:
            pids = sorted(self.active_pids, key=lambda p: -(self.procs[p].tx_bps + self.procs[p].rx_bps) if p in self.procs else 0)[:25]
            for cid, case in self.cases.items():
                if not case.closed and case.pid not in pids:
                    pids.append(case.pid)
        for pid in pids:
            if self.stop.is_set() or not self.stream.alive:
                return
            r = self.stream.command(f"conns {pid}", 15)
            if r.get("reply") != "conns":
                continue
            with self.lock:
                ps = self.procs.get(pid)
                if ps is None:
                    continue
                self._apply_conns(ps, r.get("conns", []))
                nameless = self._nameless_remotes(ps)
            # a remote with no DNS name and no SNI is signal D1; ask Hodometer (DNS trace, PTR, SNI) before trusting that
            for ip in nameless[:10]:
                r = self.stream.command(f"resolve {ip}", 10)
                if r.get("reply") == "resolve":
                    self.resolved[ip] = (r.get("host", "") or "", time.time())
            with self.lock:
                self._rescore(ps)

    def _nameless_remotes(self, ps):
        now = time.time()
        out = []
        for f in ps.flows.values():
            if f.host or f.sni or f.local or not rubric.is_internet(f.remote):
                continue
            known = self.resolved.get(f.remote)
            if known and (known[0] or now - known[1] < 120):
                continue
            if f.remote not in out:
                out.append(f.remote)
        return out

    def _apply_resolved(self, ps):
        for f in ps.flows.values():
            if not f.host:
                known = self.resolved.get(f.remote)
                if known and known[0]:
                    f.host = known[0]

    def _apply_conns(self, ps, conns):
        now = time.time()
        for c in conns:
            try:
                proto, lport, remote, port = c.get("proto", "tcp"), int(c.get("lport", 0) or 0), c.get("remote", ""), int(c.get("port", 0) or 0)
            except (TypeError, ValueError):
                continue
            key = (proto, lport, remote, port)
            f = ps.flows.get(key)
            if f is None:
                f = ps.flows[key] = Flow(proto, lport, remote, port)
                f.first = now - float(c.get("age_s", 0) or 0)
                ps.flows.pop((proto, 0, remote, port), None)
            f.host = c.get("host") or f.host
            f.sni = c.get("sni") or f.sni
            f.alpn = c.get("alpn") or f.alpn
            f.tls = c.get("tls") or f.tls
            f.quic = bool(c.get("quic")) or f.quic
            f.http = c.get("http") or f.http
            f.state = c.get("state", f.state)
            f.local = bool(c.get("local"))
            f.tx = max(f.tx, int(c.get("tx", 0) or 0))
            f.rx = max(f.rx, int(c.get("rx", 0) or 0))
            f.last = now
            if f.state in ("closed", "failed"):
                f.closed = True
        self._trim_flows(ps)

    # ================================================================== inspect
    def _inspect_worker(self):
        while not self.stop.is_set():
            try:
                pid = self.inspect_q.get(timeout=1.0)
            except queue.Empty:
                continue
            if not (self.stream.alive and self.stream.auth == "allowed"):
                self.inspect_q.put(pid)
                self.stop.wait(2.0)
                continue
            try:
                self._inspect(pid)
            except Exception:
                log.exception("inspect %d failed", pid)
                with self.lock:
                    ps = self.procs.get(pid)
                    if ps:
                        ps.inspected = True
                        ps.inspect_failed = "daemon error"

    def _inspect(self, pid):
        r = self.stream.command(f"inspect {pid}", 30)
        self.stats["inspects"] += 1
        with self.lock:
            ps = self.procs.get(pid)
            if ps is None:
                return
            ps.inspect_scheduled = False
            now = time.time()
            if r.get("reply") != "inspect":
                ps.inspected = True
                ps.inspect_t = now
                ps.inspect_failed = str(r.get("error", "no reply"))
                log.info("inspect %d: %s", pid, ps.inspect_failed)
            else:
                ps.name = r.get("name") or ps.name
                if r.get("path"):
                    ps.path = r["path"]
                ps.cmdline = r.get("cmdline", "") or ""
                ps.user = r.get("user", "") or ""
                ps.integrity = r.get("integrity", "") or ""
                par = r.get("parent") or {}
                ps.parent_pid = int(par.get("pid", 0) or 0)
                ps.parent_name = par.get("name", "") or ""
                ps.started = r.get("started", "") or ""
                ps.alive = bool(r.get("alive", True))
                ps.alive_at_inspect = ps.alive
                sg = r.get("signer") or {}
                ps.signer_state = sg.get("state", "") or ""
                ps.signer_name = sg.get("name", "") or ""
                ps.disk_read_bps = float(r.get("disk_read_bps", 0) or 0)
                ps.disk_write_bps = float(r.get("disk_write_bps", 0) or 0)
                self._apply_conns(ps, r.get("conns", []))
                for t in r.get("timeline", []):
                    if t.get("kind") == "start" and int(t.get("ppid", 0) or 0) == pid:
                        cpid = int(t.get("pid", 0) or 0)
                        if not any(c["pid"] == cpid for c in ps.children):
                            ps.children.append({"t": now, "pid": cpid, "image": t.get("detail", ""), "connected": False, "from_timeline": True})
                ps.inspected = True
                ps.inspect_t = now
                ps.inspect_failed = ""
                if ps.signer_state == "pending" and getattr(ps, "_signer_retry", 0) < 2:
                    ps._signer_retry = getattr(ps, "_signer_retry", 0) + 1
                    ps.inspected = False
                    ps.inspect_scheduled = True
                    threading.Timer(8.0, lambda: self.inspect_q.put(pid)).start()
                    return
            path = ps.path
        sha = sha256_file(path) if path else ""
        with self.lock:
            ps.sha256 = sha
            entry = self.ledger.touch(ps)
            hostile = self.ledger.hostile_match(ps)
            if hostile is not None and not ps.respawn_of:
                ps.respawn_of = hostile.get("path")
                self._say(f"RESPAWN: pid {pid} {ps.name} matches hostile ledger entry {hostile.get('path')}")
                self.add_item({"type": "respawn", "matches": hostile.get("path"), "matched_by": "path" if self.ledger.key(hostile.get("path")) == self.ledger.key(ps.path) else "hash or signer+hosts",
                               "hostile_note": hostile.get("note", ""), **self.digest(ps)}, urgent=True)
            key = (self.ledger.key(ps.path), ps.sha256)
            if key not in self.first_sight_keys:
                self.first_sight_keys.add(key)
                ps.first_sight_due = time.time() + 8
            else:
                ps.first_sight_due = -1
            self._rescore(ps, force=True)

    # ================================================================== scoring and cases
    def _rescore(self, ps, force=False):
        now = time.time()
        if not force and now - ps.last_score_t < 2:
            return
        ps.last_score_t = now
        self._apply_resolved(ps)
        entry = self.ledger.get(ps.path)
        res = rubric.score_process(ps, entry, now, cased=ps.case_id is not None)
        changed = res["score"] != ps.score or res["level"] != ps.level
        ps.score, ps.level, ps.signals, ps.categories = res["score"], res["level"], res["signals"], res["categories"]
        if not ps.inspected or ps.vm:
            return
        li = level_index(ps.level)
        case = self.cases.get(ps.case_id) if ps.case_id else None
        if case is not None and not case.closed:
            if changed and case.events is not None:
                self._case_push(case, {"ev": "daemon", "kind": "score", "pid": ps.pid, "score": ps.score, "level": ps.level,
                                       "signals": ps.signals})
            if li >= 2:
                self._ensure_capture(ps)
            return
        if li >= 2:
            self._ensure_capture(ps)
        if li >= 1 and li > level_index(ps.reported_level):
            ps.reported_level = ps.level
            # a program Sentinel already vetted at this level is raised again only when it goes higher
            if entry and entry.get("verdict") in ("known", "trusted", "watch") and li <= level_index(entry.get("vetted_level", "CLEAR")):
                log.info("pid %d %s at %s: vetted %s at %s, not raised", ps.pid, ps.name, ps.level, entry["verdict"], entry.get("vetted_level"))
                return
            self._emit_case(ps, urgent=li >= 2)

    def _emit_case(self, ps, urgent, forced=False):
        self.stats["cases"] += 1
        item = {"type": "case", **self.digest(ps)}
        if forced:
            item["forced_test"] = True
        self._say(f"CASE {ps.level} ({ps.score}): pid {ps.pid} {ps.name} — " + "; ".join(s["id"] for s in ps.signals if s["points"] > 0))
        self.add_item(item, urgent)

    def _ensure_capture(self, ps):
        now = time.time()
        cap = self.capture
        active = cap["until"] > now and cap["pid"]
        if active and (cap["pid"] == ps.pid or cap["score"] >= ps.score):
            return
        if not self.stream.alive:
            return
        r = self.stream.command(f"capture {ps.pid} {self.cfg.capture_s}", 15)
        if r.get("ok"):
            self.capture.update({"pid": ps.pid, "score": ps.score, "until": now + self.cfg.capture_s, "path": r.get("path", ""), "by": "daemon"})
            self._say(f"capture started for pid {ps.pid} {ps.name}: {r.get('path')} ({self.cfg.capture_s} s)")
        else:
            log.info("capture for %d failed: %s", ps.pid, r.get("error"))

    def note_capture_started(self, pid, path, secs, by):
        with self.lock:
            ps = self.procs.get(pid)
            self.capture.update({"pid": pid, "score": ps.score if ps else 0, "until": time.time() + (secs or 30), "path": path, "by": by})

    def digest(self, ps):
        entry = self.ledger.get(ps.path) or {}
        rows = []
        for r in sorted(ps.remotes().values(), key=lambda r: -(r["tx"] + r["rx"])):
            if r["local"]:
                continue
            rows.append({"names": sorted(r["names"]), "sni": sorted(r["sni"]), "alpn": sorted(r["alpn"]), "ip": r["ip"],
                         "port": r["port"], "proto": r["proto"], "conns": r["conns"], "tx": r["tx"], "rx": r["rx"],
                         "http": sorted(r["http"])[:3], "tls": sorted(r["tls"]), "quic": r["quic"]})
        n_local = sum(1 for r in ps.remotes().values() if r["local"])
        cap = ""
        if ps.capture_path:
            cap = ps.capture_path
        elif self.capture["pid"] == ps.pid and self.capture["until"] > time.time():
            cap = f"running: {self.capture['path']}"
        return {
            "pid": ps.pid, "name": ps.name, "path": ps.path, "sha256": ps.sha256,
            "signer": {"state": ps.signer_state, "name": ps.signer_name}, "user": ps.user, "integrity": ps.integrity,
            "parent": {"pid": ps.parent_pid, "name": ps.parent_name}, "cmdline": ps.cmdline[:400], "started": ps.started,
            "alive": not ps.exited and ps.alive, "vm": ps.vm, "inspect_error": ps.inspect_failed or None,
            "first_seen": time.strftime("%H:%M:%S", time.localtime(ps.first_seen)),
            "children": [{"pid": c["pid"], "image": c["image"], "connected": c.get("connected", False)} for c in ps.children[-12:]],
            "talks_to": rows[:25], "talks_to_more": max(0, len(rows) - 25), "local_remotes": n_local,
            "totals": {"tx": ps.tx_total, "rx": ps.rx_total, "conns_active": ps.conns_active, "fails": ps.fails_total},
            "score": ps.score, "level": ps.level, "signals": ps.signals, "categories": ps.categories,
            "ledger": {"verdict": entry.get("verdict"), "note": entry.get("note", ""), "sightings": entry.get("sightings", 0),
                       "days_known": round((time.time() - float(entry.get("first_seen", time.time()))) / 86400, 1)},
            "capture": cap or None, "case": ps.case_id,
        }

    def open_case(self, pid, priority, brief):
        if priority not in LEVEL_SCORE:
            priority = "WATCH"
        with self.lock:
            ps = self.procs.get(pid)
            if ps is None:
                return json.dumps({"status": "error", "error": f"pid {pid} is not known to the daemon (not seen on the network)"})
            if ps.case_id and ps.case_id in self.cases and not self.cases[ps.case_id].closed:
                return json.dumps({"status": "open", "case": ps.case_id, "note": "a case is already open for this pid"})
            self.case_seq += 1
            cid = f"C{self.case_seq}-{pid}"
            case = Case(cid, pid, priority, brief, max(ps.score, LEVEL_SCORE[priority]), ps.path, ps.name)
            self.cases[cid] = case
            ps.case_id = cid
            self.cased_pids.add(pid)
            if level_index(priority) >= 2:
                self._ensure_capture(ps)
            if len(self.running_cases) < self.cfg.max_investigators:
                self._start_case(case)
                return json.dumps({"status": "started", "case": cid, "model": self.cfg.watch_model if priority == "WATCH" else self.cfg.model})
            if priority == "HOSTILE":
                del self.cases[cid]
                ps.case_id = None
                self.cased_pids.discard(pid)
                return json.dumps({"status": "busy", "note": "every investigator is busy; run the investigation yourself with Prompt B's procedure"})
            heapq.heappush(self.case_queue, (-case.score, self.case_seq, cid))
            return json.dumps({"status": "queued", "case": cid, "ahead": len(self.case_queue) - 1})

    def _start_case(self, case):
        case.started = time.time()
        t = threading.Thread(target=self._run_investigator, args=(case,), name=f"case-{case.id}", daemon=True)
        self.running_cases[case.id] = t
        t.start()

    def _start_next_case(self):
        with self.lock:
            while self.case_queue and len(self.running_cases) < self.cfg.max_investigators:
                _, _, cid = heapq.heappop(self.case_queue)
                case = self.cases.get(cid)
                if case and not case.closed:
                    self._start_case(case)

    def _case_push(self, case, ev):
        q = case.events
        if q is None:
            return
        try:
            q.put_nowait(ev)
        except queue.Full:
            try:
                q.get_nowait()
            except queue.Empty:
                pass
            case.events_dropped = getattr(case, "events_dropped", 0) + 1
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass

    def _case_tree(self, case):
        """Pids the investigator may act on: the case pid, its children (4 levels) and a script-host parent."""
        with self.lock:
            tree = {case.pid}
            frontier = [case.pid]
            for _ in range(4):
                nxt = []
                for pid in frontier:
                    ps = self.procs.get(pid)
                    if ps:
                        for c in ps.children:
                            if c["pid"] not in tree:
                                tree.add(c["pid"])
                                nxt.append(c["pid"])
                frontier = nxt
            ps = self.procs.get(case.pid)
            if ps and ps.parent_pid:
                par = self.procs.get(ps.parent_pid)
                pname = (par.name if par else ps.parent_name or "").lower()
                if pname in rubric.SCRIPT_HOSTS or not pname:
                    tree.add(ps.parent_pid)
            return tree

    def _run_investigator(self, case):
        ps = self.procs.get(case.pid)
        model = self.cfg.watch_model if case.priority == "WATCH" else self.cfg.model
        label = f"case {case.id}"
        self._say(f"[{label}] investigator starting on pid {case.pid} {case.name} ({case.priority}, {model})")
        case.events = queue.Queue(maxsize=3000)
        case.events_dropped = 0
        conn = HodometerClient(f"case-{case.id}", self.cfg.port, self.gate,
                               on_event=lambda ev: self._case_event(case, ev), on_pending=self._on_pending)
        t0 = time.time()
        report = None
        status = "unresolved"
        tool_calls = 0
        try:
            st = self._connect(conn)
            if st != "allowed":
                report = {"case": case.id, "pid": case.pid, "name": case.name, "path": case.path, "verdict": "UNRESOLVED",
                          "summary": f"the investigator could not open its Hodometer connection ({st})"}
            else:
                ctx = tools.ToolContext(self, lambda: conn, label, case)
                session = ModelSession(self.api_client, model, self.investigator_system, tools.INVESTIGATOR_TOOLS,
                                       self.cfg.effort, label, use_fallback=self.cfg.use_fallback,
                                       transcript=Transcript(os.path.join(self.transcripts_dir, f"{case.id}.jsonl")))
                executor = tools.make_investigator_executor(ctx)
                digest = self.digest(ps) if ps else {"pid": case.pid}
                user0 = (f"CASE {case.id} · priority {case.priority} · pid {case.pid} {case.name}\n"
                         f"Brief from Sentinel: {case.brief}\n"
                         f"Daemon digest:\n{json.dumps(digest, ensure_ascii=False)}\n"
                         f"Capture: {digest.get('capture') or 'none yet'}")
                deadline = t0 + 300
                res = session.run_turn(user0, executor, max_tool_rounds=40, deadline=deadline, stop_event=self.stop)
                tool_calls = session.tool_calls
                if case.verdict is None and not case.closed and res.status in ("ok", "rounds") and time.time() < deadline - 20:
                    res = session.run_turn("You ended without finish(). Call finish(verdict) now with your best verdict.",
                                           executor, max_tool_rounds=3, deadline=deadline, stop_event=self.stop)
                    tool_calls = session.tool_calls
                if case.verdict is not None:
                    report = case.verdict
                    status = "finished"
                else:
                    report = {"case": case.id, "pid": case.pid, "name": case.name, "path": case.path, "verdict": "UNRESOLVED",
                              "summary": f"the investigator did not finish ({res.status}) after {time.time() - t0:.0f} s and "
                                         f"{tool_calls} tool calls" + (f"; closed by Sentinel: {case.closed_why}" if case.closed else ""),
                              "last_text": (res.text or "")[:800]}
                log.info("[%s] %s", label, session.usage_line())
        except ModelError as e:
            report = {"case": case.id, "pid": case.pid, "name": case.name, "path": case.path, "verdict": "UNRESOLVED",
                      "summary": f"model error: {e}"}
        except Exception as e:
            log.exception("[%s] investigator crashed", label)
            report = {"case": case.id, "pid": case.pid, "name": case.name, "path": case.path, "verdict": "UNRESOLVED",
                      "summary": f"daemon error: {e}"}
        finally:
            if conn.alive:
                try:
                    conn.command("watch off", 5)
                except Exception:
                    pass
                conn.close()
            with self.lock:
                case.closed = True
                case.closed_why = case.closed_why or status
                if ps is not None and ps.case_id == case.id:
                    ps.case_id = None
                    ps.reported_level = ps.level     # raise again only if it rises further
                self.cased_pids.discard(case.pid)
                self.running_cases.pop(case.id, None)
            self.stats["reports"] += 1
            self._say(f"[{label}] {status}: {report.get('verdict')} score {report.get('score', '?')} — {str(report.get('summary', ''))[:200]}")
            self.add_item({"type": "investigator_report", "case": case.id, "priority": case.priority, "model": model,
                           "elapsed_s": int(time.time() - t0), "tool_calls": tool_calls, "status": status, "report": report}, urgent=True)
            self._start_next_case()

    def _case_event(self, case, ev):
        kind = ev.get("ev")
        if kind in ("tick", "spike", "hello", "auth"):
            return
        if kind == "conn":
            if int(ev.get("pid", 0) or 0) not in self._case_tree(case):
                return
        self._case_push(case, ev)

    def guard_action(self, ctx, word, rest):
        rest = rest.strip()
        conn = ctx.conn_getter()
        if word == "kill":
            if not rest.isdigit():
                return "usage: kill <pid>"
            pid = int(rest)
            if pid in (self.self_pid, self.self_ppid, self.hodometer_pid) or pid <= 4:
                return "hard rule 1: that pid is the daemon, its parent, Hodometer or System"
            with self.lock:
                ps = self.procs.get(pid)
                name, path = (ps.name, ps.path) if ps else ("", "")
            if not name and conn is not None:
                r = conn.command(f"inspect {pid}", 30)
                name, path = r.get("name", "") or "", r.get("path", "") or ""
            if name.lower() in tools.NEVER_TOUCH:
                return f"hard rule 1: never kill {name}"
            if path and path.lower() == self.self_exe:
                return "hard rule 1: that is the sentinel daemon's own program"
            if ctx.case is not None and pid not in self._case_tree(ctx.case):
                return f"hard rule 1 (investigator): pid {pid} is not in your case tree as the daemon knows it (case pid {ctx.case.pid})"
            return None
        target = rest.strip().strip('"')
        if not target:
            return f"usage: {word} <pid|\"path\">"
        path = ""
        if target.isdigit():
            with self.lock:
                ps = self.procs.get(int(target))
                path = ps.path if ps else ""
            if not path and conn is not None:
                r = conn.command(f"inspect {target}", 30)
                path = r.get("path", "") or ""
            if not path:
                return f"cannot resolve pid {target} to a program path"
        else:
            path = target
        low = path.lower()
        base = low.rsplit("\\", 1)[-1]
        if word == "block":
            if rubric.under_windows(path):
                return "hard rule 2: never block a program under C:\\Windows; kill the harmful instance instead"
            if base in tools.NEVER_TOUCH:
                return f"hard rule 1: never block {base}"
            if low == self.self_exe or "\\sentinel\\runtime\\" in low:
                return "hard rule 1: that is the sentinel daemon's own program"
            if ctx.case is not None:
                with self.lock:
                    tree_paths = {self.procs[p].path.lower() for p in self._case_tree(ctx.case) if p in self.procs and self.procs[p].path}
                if low not in tree_paths:
                    return f"hard rule 1 (investigator): {path} is not a program in your case tree as the daemon knows it"
        return None

    def mark(self, target, verdict, note):
        if verdict not in ("known", "trusted", "watch", "hostile"):
            return "error: verdict must be known, trusted, watch or hostile", True
        with self.lock:
            path = target
            ps = None
            if target.strip().isdigit():
                ps = self.procs.get(int(target))
                if ps is None or not ps.path:
                    return f"error: pid {target} is not known to the daemon or has no path", True
                path = ps.path
            else:
                for p in self.procs.values():
                    if p.path and p.path.lower() == path.lower():
                        ps = p
                        break
            same = [p for p in self.procs.values() if p.path and p.path.lower() == path.lower()]
            vetted_level = max((p.level for p in same), key=level_index, default="CLEAR")
            self.ledger.mark(path, verdict, note, ps, vetted_level=vetted_level)
            closed = []
            if verdict == "trusted":
                for case in self.cases.values():
                    if not case.closed and case.path.lower() == path.lower():
                        case.closed = True
                        case.closed_why = "the user trusts this program"
                        closed.append(case.id)
            for p in self.procs.values():
                if p.path and p.path.lower() == path.lower():
                    self._rescore(p, force=True)
        self.ledger.save()
        self._say(f"mark {verdict}: {path}" + (f" ({note})" if note else "") + (f"; closed {closed}" if closed else ""))
        return json.dumps({"ok": True, "path": path, "verdict": verdict, "closed_cases": closed}), False

    # ================================================================== Sentinel loop
    def _build_batch(self):
        with self.outbox_cv:
            if not self.outbox:
                return None
            urgent = [i for u, i in self.outbox if u]
            normal = [i for u, i in self.outbox if not u]
            take = (urgent + normal)[:self.cfg.max_items_per_turn]
            taken_ids = {id(i) for i in take}
            self.outbox = [(u, i) for u, i in self.outbox if id(i) not in taken_ids]
            waiting = len(self.outbox)
        user_lines = [i["text"] for i in take if i.get("type") == "user"]
        items = [i for i in take if i.get("type") != "user"]
        head = f"daemon batch · {now_str()} · {len(items)} item(s)" + (f" · {waiting} waiting" if waiting else "")
        lines = [head] + [f"USER: {t}" for t in user_lines] + [json.dumps(i, ensure_ascii=False, separators=(",", ":")) for i in items]
        return "\n".join(lines)

    def _sentinel_loop(self):
        self._system("daemon", f"sentinel daemon started on {sys.executable} (pid {self.self_pid}); mode "
                               f"{'dry-run' if self.dry_run else 'live'}; max investigators {self.cfg.max_investigators}")
        ctx = tools.ToolContext(self, self._control_conn, "sentinel")
        executor = tools.make_sentinel_executor(ctx)
        failures = 0
        while not self.stop.is_set():
            with self.outbox_cv:
                while not self.stop.is_set():
                    if self.outbox:
                        urgent = any(u for u, _ in self.outbox)
                        if urgent or time.time() - self.last_send >= self.cfg.batch_s:
                            break
                    self.outbox_cv.wait(1.0)
            if self.stop.is_set():
                break
            if not (self.stream.alive and self.stream.auth == "allowed") and not any(u for u, _ in self.outbox):
                self.stop.wait(2.0)
                continue
            text = self._build_batch()
            if not text:
                continue
            self.last_send = time.time()
            try:
                res = self.sentinel.run_turn(text, executor, max_tool_rounds=40, stop_event=self.stop)
                failures = 0
            except ModelError as e:
                failures += 1
                self._say(f"[sentinel] model error: {e}")
                if "authentication" in str(e) or "permission" in str(e):
                    self._say("[sentinel] models disabled: set ANTHROPIC_API_KEY (or log in with `ant auth login`) and restart")
                    self.models_enabled = False
                    return
                if "bad request" in str(e):
                    self.sentinel.rollover()     # a malformed history is the likeliest cause; start clean
                self.stop.wait(min(60.0 * failures, 300.0))
                continue
            self.stats["turns"] += 1
            if res.text:
                for line in res.text.strip().splitlines():
                    print(f"[sentinel] {line}", flush=True)
                last = res.text.strip().splitlines()[-1]
                if last.startswith("✅"):
                    self.last_status_line = last
            if res.status == "refusal":
                self._say("[sentinel] the model declined this batch; continuing with the next")
            if self.sentinel.needs_rollover():
                self.sentinel.rollover()
                self._system("daemon", "the conversation was restarted to keep its context small; the ledger kept every "
                                       "verdict. " + self._state_summary())

    def _state_summary(self):
        with self.lock:
            on_net = sum(1 for p in self.procs.values() if p.seen_network)
            open_cases = [f"{c.id} pid {c.pid} {c.name} ({c.priority})" for c in self.cases.values() if not c.closed]
        c = self.ledger.counts()
        return (f"state: {on_net} processes on the network since start, ledger known {c['known']} trusted {c['trusted']} "
                f"watch {c['watch']} hostile {c['hostile']} unvetted {c['unvetted']}, open cases {open_cases or 'none'}, "
                f"mode {'dry-run' if self.dry_run else 'live'}" + (f", last status: {self.last_status_line}" if self.last_status_line else ""))

    # ================================================================== ticker: first sights, heartbeat, tests, pruning
    def _ticker(self):
        next_heartbeat = time.time() + self.cfg.heartbeat_s
        next_prune = time.time() + 120
        while not self.stop.is_set():
            now = time.time()
            try:
                with self.lock:
                    for ps in list(self.procs.values()):
                        if ps.first_sight_due > 0 and now >= ps.first_sight_due:
                            ps.first_sight_due = -1
                            self._rescore(ps, force=True)
                            self.stats["first_sight"] += 1
                            self.ledger.add_hosts(ps.path, ps.hosts())
                            self.add_item({"type": "first_sight", **self.digest(ps)})
                            self._say(f"first sight: pid {ps.pid} {ps.name} — {ps.level} ({ps.score}) "
                                      f"{len([r for r in ps.remotes().values() if not r['local']])} remotes")
                    if self.capture["pid"] and self.capture["until"] < now - 30:
                        self.capture.update({"pid": 0, "score": 0, "until": 0.0})
                if self.test_cases:
                    self._run_test_cases()
                if now >= next_heartbeat:
                    next_heartbeat = now + self.cfg.heartbeat_s
                    self._heartbeat()
                if now >= next_prune:
                    next_prune = now + 120
                    self._prune()
            except Exception:
                log.exception("ticker failed")
            self.stop.wait(1.0)

    def _heartbeat(self):
        with self.lock:
            on_net = sum(1 for p in self.procs.values() if p.seen_network)
            running = len(self.running_cases)
            queued = len(self.case_queue)
            open_cases = sum(1 for c in self.cases.values() if not c.closed)
        c = self.ledger.counts()
        hs = self.hodometer_status
        self.add_item({"type": "heartbeat", "procs_on_network": on_net, "active_now": len(self.active_pids),
                       "ledger": c, "cases_open": open_cases, "investigators_running": running, "queued": queued,
                       "tx_mbps": hs.get("tx_mbps"), "rx_mbps": hs.get("rx_mbps"), "etw": hs.get("etw"), "audit": hs.get("audit"),
                       "capture_pid": self.capture["pid"] or None, "stream": self.stream.alive, "control": self.control.alive,
                       "uptime_s": int(time.time() - self.started), "stream_events": self.stats["events"],
                       "events_dropped": self.events_dropped, "unparseable_lines": self.stream.bad_lines,
                       "inspects": self.stats["inspects"]})

    def _prune(self):
        now = time.time()
        with self.lock:
            for pid, ps in list(self.procs.items()):
                if not ps.seen_network and now - ps.first_seen > 600 and not ps.case_id:
                    del self.procs[pid]
                elif ps.exited and now - ps.exit_t > 3600 and not ps.case_id:
                    del self.procs[pid]
            for cid, case in list(self.cases.items()):
                if case.closed and now - case.opened > 7200:
                    del self.cases[cid]

    def _run_test_cases(self):
        remaining = []
        for pid, level in self.test_cases:
            with self.lock:
                ps = self.procs.get(pid)
                if ps is None:
                    ps = self._proc(pid, "", "", network=True)
                    remaining.append((pid, level))
                    continue
                if not ps.inspected:
                    if not ps.inspect_scheduled:
                        ps.inspect_scheduled = True
                        self.inspect_q.put(pid)
                    remaining.append((pid, level))
                    continue
                if ps.inspect_failed and not ps.path:
                    self._say(f"test case for pid {pid} dropped: {ps.inspect_failed}")
                    continue
                self._rescore(ps, force=True)
                ps.score = max(ps.score, LEVEL_SCORE[level])
                ps.level = level
                ps.signals = ps.signals + [{"id": "TEST", "points": 0, "category": "test",
                                            "evidence": f"level forced to {level} for a daemon test (/case or --test-case)"}]
                ps.reported_level = level
                if level_index(level) >= 2:
                    self._ensure_capture(ps)
                self._emit_case(ps, urgent=True, forced=True)
        self.test_cases = remaining

    # ================================================================== console
    def _console(self):
        if not sys.stdin or not sys.stdin.readable():
            return
        while not self.stop.is_set():
            try:
                line = sys.stdin.readline()
            except (OSError, ValueError):
                return
            if not line:
                return
            line = line.strip()
            if not line:
                continue
            try:
                self._console_cmd(line)
            except Exception:
                log.exception("console command failed")

    def _console_cmd(self, line):
        if line.startswith("/"):
            parts = line.split()
            cmd = parts[0].lower()
            if cmd == "/quit":
                self.stop.set()
            elif cmd == "/case" and len(parts) >= 2 and parts[1].isdigit():
                level = parts[2].upper() if len(parts) > 2 else "SUSPECT"
                if level not in LEVEL_SCORE:
                    level = "SUSPECT"
                self.test_cases.append((int(parts[1]), level))
                self._say(f"test case queued: pid {parts[1]} at {level}")
            elif cmd == "/status":
                self._say(self._state_summary())
                if self.sentinel:
                    self._say("sentinel: " + self.sentinel.usage_line())
                self._say(f"stream alive {self.stream.alive} control alive {self.control.alive} events {self.stats['events']} "
                          f"inspects {self.stats['inspects']} first_sights {self.stats['first_sight']} cases {self.stats['cases']} "
                          f"reports {self.stats['reports']} turns {self.stats['turns']} outbox {len(self.outbox)}")
            elif cmd == "/procs":
                with self.lock:
                    rows = sorted((p for p in self.procs.values() if p.seen_network), key=lambda p: (-p.score, p.pid))[:25]
                    for p in rows:
                        self._say(f"  {p.pid:>6} {p.level:<7} {p.score:>2}  {p.name:<28} {p.signer_state:<9} "
                                  f"{len([r for r in p.remotes().values() if not r['local']]):>3} remotes  {';'.join(s['id'] for s in p.signals)}")
            elif cmd == "/help":
                self._say("/case <pid> [WATCH|SUSPECT|HOSTILE]  /status  /procs  /quit  — anything else goes to Sentinel as USER:")
            else:
                self._say("unknown command; /help")
            return
        if not self.models_enabled:
            self._say("models are off; nothing to tell")
            return
        self.add_item({"type": "user", "text": line}, urgent=True)
