"""Hodometer socket client: JSON lines over 127.0.0.1:48201, the auth flow and the denial rules.

One HodometerClient per connection (stream, control, one per investigator). An AuthGate shared by all of them
enforces the rules from SENTINEL.md: after a denial nothing reconnects for 10 minutes (every attempt during
Hodometer's cooldown counts as another denial, and three denials firewall the program), and attempts are spaced
so Hodometer never sees a connection flood (more than ten attempts in a minute suspends prompting).
"""
import json
import logging
import queue
import socket
import sys
import threading
import time

log = logging.getLogger("hodometer")


class AuthGate:
    COOLDOWN_S = 600.0      # Hodometer's denial cooldown
    MIN_SPACING_S = 3.0     # between connection attempts, all connections together

    def __init__(self):
        self._lock = threading.Lock()
        self.denied_until = 0.0
        self.denials = 0
        self.last_attempt = 0.0
        self.exe_path = sys.executable

    def seconds_to_wait(self):
        """0 when a connection may be attempted now, else how long to wait."""
        with self._lock:
            now = time.time()
            wait = max(self.denied_until - now, self.last_attempt + self.MIN_SPACING_S - now)
            return max(0.0, wait)

    def note_attempt(self):
        with self._lock:
            self.last_attempt = time.time()

    def note_denied(self, why):
        with self._lock:
            self.denials += 1
            self.denied_until = time.time() + self.COOLDOWN_S
            log.warning("auth denied (%s); no reconnect for %d s; denials so far: %d", why, int(self.COOLDOWN_S), self.denials)

    def note_allowed(self):
        with self._lock:
            self.denied_until = 0.0


class HodometerClient:
    """One connection. Replies are matched by their "reply" field (one command in flight at a time); events go to
    on_event(obj) from the reader thread, so that callback must only enqueue."""

    def __init__(self, label, port, gate, on_event=None, on_pending=None, auth_timeout=60.0):
        self.label = label
        self.port = port
        self.gate = gate
        self.on_event = on_event
        self.on_pending = on_pending
        self.auth_timeout = auth_timeout
        self._sock = None
        self._reader = None
        self._cmd_lock = threading.Lock()
        self._replies = queue.Queue()
        self._auth_event = threading.Event()
        self.alive = False
        self.auth = "none"          # none | pending | allowed | denied | closed
        self.auth_why = ""
        self.remembered = None
        self.hello = None
        self.lines_rx = 0
        self.events_rx = 0
        self.bad_lines = 0
        self.connected_at = 0.0

    # ------------------------------------------------------------------ connect / close
    def connect(self):
        """Returns allowed | cooldown | refused | denied | closed."""
        wait = self.gate.seconds_to_wait()
        if wait > 0:
            return "cooldown"
        self.gate.note_attempt()
        self._auth_event.clear()
        self.auth = "none"
        self.auth_why = ""
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        except OSError as e:
            log.info("[%s] connect failed: %s", self.label, e)
            return "refused"
        s.settimeout(1.0)
        self._sock = s
        self.alive = True
        self.connected_at = time.time()
        self._reader = threading.Thread(target=self._read_loop, name=f"hodometer-{self.label}", daemon=True)
        self._reader.start()
        if not self._auth_event.wait(self.auth_timeout + 5):
            # Hodometer's dialog denies by itself after 60 s, which is a denial with a cooldown.
            self.auth = "denied"
            self.auth_why = "no answer within %d s" % int(self.auth_timeout)
        if self.auth == "allowed":
            self.gate.note_allowed()
            return "allowed"
        if self.auth == "denied":
            self.gate.note_denied(self.auth_why or "denied")
            self.close()
            return "denied"
        self.close()
        return "closed"

    def close(self):
        self.alive = False
        s, self._sock = self._sock, None
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ reader
    def _read_loop(self):
        buf = b""
        sock = self._sock
        while self.alive and sock is self._sock:
            try:
                data = sock.recv(1 << 16)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    self._handle_line(line)
        was_alive = self.alive
        self.alive = False
        if self.auth in ("none", "pending"):
            self.auth = "closed"
        self._auth_event.set()
        if was_alive:
            log.info("[%s] connection closed", self.label)
        if self.on_event:
            try:
                self.on_event({"ev": "_closed", "label": self.label})
            except Exception:
                log.exception("on_event failed")

    def _handle_line(self, line):
        self.lines_rx += 1
        try:
            # strict=False: Hodometer can pass a raw control character through a decoded string (an HTTP line, say)
            obj = json.loads(line.decode("utf-8", "replace"), strict=False)
        except ValueError as e:
            self.bad_lines += 1
            log.warning("[%s] unparseable line (%s): %r", self.label, e, line[:300])
            return
        if not isinstance(obj, dict):
            return
        if "reply" in obj:
            self._replies.put(obj)
            return
        ev = obj.get("ev")
        if ev is None:
            return
        self.events_rx += 1
        if ev == "auth":
            status = obj.get("status")
            if status == "pending":
                self.auth = "pending"
                if self.on_pending:
                    try:
                        self.on_pending(self)
                    except Exception:
                        log.exception("on_pending failed")
            elif status == "allowed":
                self.auth = "allowed"
                self.remembered = obj.get("remembered")
                self._auth_event.set()
            elif status == "denied":
                self.auth = "denied"
                self.auth_why = obj.get("why", "denied")
                self._auth_event.set()
        elif ev == "hello":
            self.hello = obj
        if self.on_event:
            try:
                self.on_event(obj)
            except Exception:
                log.exception("on_event failed")

    # ------------------------------------------------------------------ commands
    @staticmethod
    def command_word(line):
        line = line.strip()
        if line.startswith("{"):
            try:
                return str(json.loads(line).get("cmd", "")).lower()
            except ValueError:
                return ""
        return line.split(" ", 1)[0].lower()

    def command(self, line, timeout=20.0):
        """Send one command and return its reply dict ({"reply":"error",...} on failure or timeout)."""
        line = line.strip()
        expected = self.command_word(line)
        with self._cmd_lock:
            if not self.alive or not self._sock:
                return {"reply": "error", "error": "not connected", "_daemon": True}
            while True:   # drop replies left over from a timed-out command
                try:
                    stale = self._replies.get_nowait()
                    log.debug("[%s] dropping stale reply %s", self.label, stale.get("reply"))
                except queue.Empty:
                    break
            try:
                self._sock.sendall((line + "\n").encode("utf-8"))
            except OSError as e:
                self.alive = False
                return {"reply": "error", "error": f"send failed: {e}", "_daemon": True}
            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return {"reply": "error", "error": f"timeout waiting for the reply to '{expected}'", "_daemon": True}
                try:
                    obj = self._replies.get(timeout=min(remaining, 1.0))
                except queue.Empty:
                    if not self.alive:
                        return {"reply": "error", "error": "connection lost", "_daemon": True}
                    continue
                if obj.get("reply") in (expected, "error"):
                    return obj
                log.debug("[%s] unexpected reply %s while waiting for %s", self.label, obj.get("reply"), expected)
