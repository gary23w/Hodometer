"""The tools both prompts assume, with the hard rules enforced in code as well.

Sentinel: hodometer, open_case, mark, notify_user. Investigator: hodometer, events, finish.
The hodometer tool refuses reset, pause, trust clear, threshold, local and audit auto off outright, refuses to kill
or block the never-kill list, the daemon and Hodometer, refuses to block anything under C:\\Windows, and in dry-run
mode logs kill and block instead of sending them.
"""
import json
import logging
import os
import queue
import time

log = logging.getLogger("tools")

HODOMETER_TOOL = {
    "name": "hodometer",
    "description": (
        "Send one command to Hodometer on this session's own connection and get its JSON reply. Commands: status, "
        "list, inspect <pid> [show], conns [pid], watch <pid|all> [packets], watch <pid> off, watch off, watch, "
        "capture <pid> [seconds], capture, capture stop, zoom, kill <pid>, block <pid|\"path\">, unblock <pid|\"path\">, "
        "blocks, resolve <ip>, history [minutes], snap. The daemon refuses reset, pause, trust clear, threshold, local "
        "and audit auto off, and in dry-run mode logs kill and block instead of sending them."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "The command line as Hodometer takes it, e.g. "
                                                                    "\"inspect 1234\" or \"block \\\"C:\\\\Users\\\\x\\\\y.exe\\\"\""}},
        "required": ["command"],
        "additionalProperties": False,
    },
    "strict": True,
}
OPEN_CASE_TOOL = {
    "name": "open_case",
    "description": "Hand a process to an investigator (Prompt B) on its own Hodometer connection. Returns JSON with the "
                   "case id and status started, queued or busy (busy only for HOSTILE priority when every investigator "
                   "is taken; then run the investigation yourself).",
    "input_schema": {
        "type": "object",
        "properties": {
            "pid": {"type": "integer"},
            "priority": {"type": "string", "enum": ["WATCH", "SUSPECT", "HOSTILE"]},
            "brief": {"type": "string", "description": "1 to 3 sentences: why it was raised and what to look at first"},
        },
        "required": ["pid", "priority", "brief"],
        "additionalProperties": False,
    },
    "strict": True,
}
MARK_TOOL = {
    "name": "mark",
    "description": "Record a verdict for a program in the daemon's ledger: known (benign, vetted), trusted (the user "
                   "said it is theirs; closes any open case), watch (raise again if it changes) or hostile (respawns "
                   "are reported at once). target is a path or a pid.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "program path, or a pid as digits"},
            "verdict": {"type": "string", "enum": ["known", "trusted", "watch", "hostile"]},
            "note": {"type": "string"},
        },
        "required": ["target", "verdict", "note"],
        "additionalProperties": False,
    },
    "strict": True,
}
NOTIFY_TOOL = {
    "name": "notify_user",
    "description": "Show the person a message now: level info for one-liners, alert for an ALERT (SUSPECT, needs "
                   "their answer), incident for an INCIDENT report. The text is shown as written.",
    "input_schema": {
        "type": "object",
        "properties": {
            "level": {"type": "string", "enum": ["info", "alert", "incident"]},
            "text": {"type": "string"},
        },
        "required": ["level", "text"],
        "additionalProperties": False,
    },
    "strict": True,
}
EVENTS_TOOL = {
    "name": "events",
    "description": "Return the events this connection received since your last call: pkt, flow, trace, capture, conn, "
                   "killed, blocked, unblocked, daemon. Waits up to wait_s seconds for the first one, then returns at "
                   "most max events, one JSON object per line, oldest first, with a count of what was dropped.",
    "input_schema": {
        "type": "object",
        "properties": {
            "kinds": {"type": "array", "items": {"type": "string"}, "description": "event kinds to return; empty = all"},
            "max": {"type": "integer", "description": "at most this many events (1 to 300)"},
            "wait_s": {"type": "number", "description": "seconds to wait for the first event (0 to 30)"},
        },
        "required": ["kinds", "max", "wait_s"],
        "additionalProperties": False,
    },
    "strict": True,
}
FINISH_TOOL = {
    "name": "finish",
    "description": "End the case with the verdict JSON object from <verdict>. Call it exactly once, after watch off.",
    "input_schema": {
        "type": "object",
        "properties": {"verdict": {"type": "object", "description": "the verdict object: case, pid, name, path, verdict "
                                                                    "(CLEAR|WATCH|SUSPECT|HOSTILE), score, categories, "
                                                                    "signals, talks_to, tree, actions, capture, unblock, "
                                                                    "summary, recommendation"}},
        "required": ["verdict"],
    },
}

SENTINEL_TOOLS = [HODOMETER_TOOL, OPEN_CASE_TOOL, MARK_TOOL, NOTIFY_TOOL]
INVESTIGATOR_TOOLS = [HODOMETER_TOOL, EVENTS_TOOL, FINISH_TOOL]

FORBIDDEN_WORDS = {"reset", "pause", "threshold", "local"}
NEVER_TOUCH = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "hodometer.exe",
    # antivirus / EDR agents
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "mssense.exe", "sensendr.exe",
    "csfalconservice.exe", "csfalconcontainer.exe", "sentinelagent.exe", "sentinelservicehost.exe", "cb.exe",
    "cbdefense.exe", "cylancesvc.exe", "mcshield.exe", "mfemms.exe", "avp.exe", "avgsvc.exe", "avastsvc.exe",
    "ekrn.exe", "bdservicehost.exe", "vsserv.exe", "sophosfs.exe", "savservice.exe", "mbamservice.exe", "mbam.exe",
    "nortonsecurity.exe", "ns.exe", "ccsvchst.exe", "tmbmsrv.exe", "elastic-agent.exe", "elastic-endpoint.exe",
    "xagt.exe", "cyserver.exe", "cytool.exe", "taniumclient.exe", "wazuh-agent.exe",
    # VPN clients
    "openvpn.exe", "openvpn-gui.exe", "openvpnserv.exe", "nordvpn.exe", "nordvpn-service.exe", "expressvpn.exe",
    "expressvpnd.exe", "wireguard.exe", "protonvpn.exe", "protonvpnservice.exe", "mullvad vpn.exe", "mullvad-daemon.exe",
    "surfshark.exe", "vpnagent.exe", "vpnui.exe", "pangps.exe", "pangpa.exe", "forticlient.exe", "fcconfig.exe",
    "tailscaled.exe", "tailscale-ipn.exe", "cloudflare warp.exe", "warp-svc.exe",
}


class ToolContext:
    """What a tool executor needs: the daemon, this session's Hodometer connection, and (investigators) the case."""

    def __init__(self, daemon, conn_getter, label, case=None):
        self.daemon = daemon
        self.conn_getter = conn_getter      # returns a HodometerClient (or None) when called
        self.label = label
        self.case = case


def _trim_reply(obj):
    """Keep tool results readable: large arrays are cut from the oldest end and say so."""
    reply = obj.get("reply")
    if reply == "inspect":
        for key, keep in (("conns", 60), ("timeline", 60), ("packets", 60)):
            arr = obj.get(key)
            if isinstance(arr, list) and len(arr) > keep:
                obj[key] = arr[-keep:] if key != "conns" else arr[:keep]
                obj[f"{key}_trimmed"] = len(arr) - keep
    elif reply == "list":
        arr = obj.get("procs")
        if isinstance(arr, list) and len(arr) > 150:
            arr.sort(key=lambda p: -(p.get("tx_total", 0) + p.get("rx_total", 0)))
            obj["procs"] = arr[:150]
            obj["procs_trimmed"] = len(arr) - 150
    elif reply == "conns":
        arr = obj.get("conns")
        if isinstance(arr, list) and len(arr) > 200:
            obj["conns"] = arr[:200]
            obj["conns_trimmed"] = len(arr) - 200
    elif reply == "history":
        arr = obj.get("minutes")
        if isinstance(arr, list) and len(arr) > 120:
            obj["minutes"] = arr[-120:]
            obj["minutes_trimmed"] = len(arr) - 120
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if len(text) > 60000:
        text = text[:60000] + "... (reply trimmed at 60000 characters)"
    return text


def _split_cmd(command):
    cmd = command.strip()
    word = cmd.split(" ", 1)[0].lower() if not cmd.startswith("{") else ""
    if cmd.startswith("{"):
        try:
            word = str(json.loads(cmd).get("cmd", "")).lower()
        except ValueError:
            word = ""
    rest = cmd[len(word):].strip() if not cmd.startswith("{") else ""
    return cmd, word, rest


def _forbidden(word, rest):
    if word in FORBIDDEN_WORDS:
        return f"{word} is never sent (hard rule 8)"
    r = rest.lower().strip()
    if word == "trust" and r.startswith("clear"):
        return "trust clear is never sent (hard rule 8)"
    if word == "audit" and r.replace("  ", " ").startswith("auto off"):
        return "audit auto off is never sent (hard rule 8)"
    return None


def exec_hodometer(ctx, command):
    daemon = ctx.daemon
    cmd, word, rest = _split_cmd(command)
    if not word:
        return "error: empty command", True
    why = _forbidden(word, rest)
    if why:
        daemon.log_action(ctx.label, cmd, "refused", why)
        return json.dumps({"reply": "error", "error": why}), True
    conn = ctx.conn_getter()
    if conn is None or not conn.alive:
        status = daemon.auth_status_json()
        return status, True
    if word in ("kill", "block", "unblock"):
        err = daemon.guard_action(ctx, word, rest)
        if err:
            daemon.log_action(ctx.label, cmd, "refused", err)
            return json.dumps({"reply": word, "ok": False, "error": err}), True
        if daemon.dry_run and word in ("kill", "block"):
            daemon.log_action(ctx.label, cmd, "dry-run", "logged, not sent")
            return json.dumps({"reply": word, "ok": False, "dry_run": True,
                               "error": f"dry-run mode: '{cmd}' was logged by the daemon and not sent to Hodometer"}), False
        reply = conn.command(cmd, timeout=30)
        daemon.log_action(ctx.label, cmd, "sent", json.dumps(reply)[:300])
        return _trim_reply(reply), not reply.get("ok", True)
    if word == "capture" and rest.lower().startswith("stop") and ctx.case is not None:
        if daemon.capture.get("pid") and daemon.capture.get("pid") != ctx.case.pid:
            return json.dumps({"reply": "error", "error": "that capture belongs to another pid; leave it"}), True
    timeout = 30 if word in ("inspect", "list", "history") else 20
    reply = conn.command(cmd, timeout=timeout)
    if word == "capture" and reply.get("ok"):
        daemon.note_capture_started(reply.get("pid", 0), reply.get("path", ""), reply.get("seconds", 0), by=ctx.label)
    return _trim_reply(reply), reply.get("reply") == "error"


def exec_events(ctx, kinds, max_n, wait_s):
    case = ctx.case
    if case is None or case.events is None:
        return "error: no event queue for this session", True
    kinds = {k.lower() for k in (kinds or []) if isinstance(k, str)}
    max_n = max(1, min(int(max_n or 100), 300))
    wait_s = max(0.0, min(float(wait_s or 0), 30.0))
    out = []
    deadline = time.time() + wait_s
    # wait for the first matching event, then drain what is there
    while True:
        try:
            ev = case.events.get(timeout=max(0.0, deadline - time.time()) if not out else 0.0)
        except queue.Empty:
            if out or time.time() >= deadline:
                break
            continue
        if ev.get("ev") == "_closed":
            out.append({"ev": "daemon", "kind": "connection_closed", "note": "your Hodometer connection dropped"})
            break
        if kinds and ev.get("ev") not in kinds:
            continue
        out.append(ev)
        if len(out) >= max_n:
            break
    dropped = case.events_dropped if hasattr(case, "events_dropped") else 0
    case.events_dropped = 0
    header = {"count": len(out), "dropped_before_this_call": dropped, "pending": case.events.qsize()}
    lines = [json.dumps(header)] + [json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in out]
    return "\n".join(lines), False


def exec_finish(ctx, verdict):
    case = ctx.case
    if case is None:
        return "error: finish is only for investigators", True
    if not isinstance(verdict, dict):
        return "error: verdict must be a JSON object (see <verdict>)", True
    level = str(verdict.get("verdict", "")).upper()
    if level not in ("CLEAR", "WATCH", "SUSPECT", "HOSTILE"):
        return "error: verdict.verdict must be CLEAR, WATCH, SUSPECT or HOSTILE", True
    verdict["verdict"] = level
    verdict.setdefault("case", case.id)
    verdict.setdefault("pid", case.pid)
    verdict.setdefault("name", case.name)
    verdict.setdefault("path", case.path)
    verdict.setdefault("summary", "")
    case.verdict = verdict
    return json.dumps({"ok": True, "case": case.id, "note": "verdict recorded; the case is closed"}), False, True


def make_sentinel_executor(ctx):
    daemon = ctx.daemon

    def execute(name, inp):
        n = name.lower()
        if n == "hodometer":
            return exec_hodometer(ctx, str(inp.get("command", "")))
        if n == "open_case":
            try:
                pid = int(inp.get("pid", 0))
            except (TypeError, ValueError):
                return "error: pid must be an integer", True
            return daemon.open_case(pid, str(inp.get("priority", "WATCH")).upper(), str(inp.get("brief", ""))), False
        if n == "mark":
            return daemon.mark(str(inp.get("target", "")), str(inp.get("verdict", "")).lower(), str(inp.get("note", "")))
        if n == "notify_user":
            daemon.notify_user(str(inp.get("level", "info")).lower(), str(inp.get("text", "")), source="sentinel")
            return json.dumps({"ok": True}), False
        return f"error: unknown tool '{name}' (expected hodometer, open_case, mark or notify_user)", True
    return execute


def make_investigator_executor(ctx):
    def execute(name, inp):
        n = name.lower()
        if ctx.case is not None and ctx.case.closed:
            return json.dumps({"error": f"this case was closed by Sentinel ({ctx.case.closed_why}); call finish now"}), True
        if n == "hodometer":
            ctx.case.tool_calls += 1
            return exec_hodometer(ctx, str(inp.get("command", "")))
        if n == "events":
            ctx.case.tool_calls += 1
            return exec_events(ctx, inp.get("kinds"), inp.get("max"), inp.get("wait_s"))
        if n == "finish":
            return exec_finish(ctx, inp.get("verdict"))
        return f"error: unknown tool '{name}' (expected hodometer, events or finish)", True
    return execute
