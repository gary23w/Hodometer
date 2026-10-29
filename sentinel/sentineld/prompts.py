"""System prompts, read from SENTINEL.md so the spec stays the single source of truth.

Sentinel's system prompt is Prompt A + Block R + Block H; each investigator's is Prompt B + R + H. A short
harness note is appended to each so the model knows the message format and whether kill/block are live.
"""
import re

HEADINGS = {
    "A": r"^## Prompt A\b",
    "B": r"^## Prompt B\b",
    "R": r"^## Block R\b",
    "H": r"^## Block H\b",
}


def load_blocks(path):
    """Return {"A": text, "B": text, "R": text, "H": text}: the first ```` fenced block after each heading."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    blocks = {}
    for key, pat in HEADINGS.items():
        rx = re.compile(pat)
        start = next((i for i, l in enumerate(lines) if rx.match(l)), None)
        if start is None:
            raise ValueError(f"{path}: heading for block {key} not found ({pat})")
        i = start + 1
        while i < len(lines) and not lines[i].startswith("````"):
            i += 1
        if i >= len(lines):
            raise ValueError(f"{path}: no fenced block after heading for {key}")
        j = i + 1
        while j < len(lines) and not lines[j].startswith("````"):
            j += 1
        blocks[key] = "\n".join(lines[i + 1:j]).strip("\n")
    return blocks


def _mode_note(dry_run):
    if dry_run:
        return ("Mode: DRY-RUN. The daemon logs kill and block and never sends them to Hodometer; their replies "
                "come back with \"ok\": false and a dry-run error. Every other command is live.")
    return "Mode: LIVE. kill and block are sent to Hodometer."


def sentinel_system(blocks, dry_run):
    note = (
        "<harness>\n"
        "You run inside the sentinel daemon. Each user turn is one batch of daemon items, one JSON object per line, "
        "each with a \"type\" field: first_sight, case, respawn, investigator_report, system or heartbeat. A line that "
        "starts with \"USER:\" is the person at the keyboard. Case ids look like C12-4567 (counter-pid). "
        "open_case returns JSON: status started, queued or busy. Tool results are Hodometer's JSON replies or the "
        "daemon's own JSON; long replies are trimmed and say so.\n"
        + _mode_note(dry_run) + "\n</harness>"
    )
    return "\n\n".join([blocks["A"], blocks["R"], blocks["H"], note])


def investigator_system(blocks, dry_run):
    note = (
        "<harness>\n"
        "You run inside the sentinel daemon on your own Hodometer connection. events(kinds, max, wait_s) returns the "
        "events your connection received since your last call (pkt, flow, trace, capture, conn, killed, blocked and "
        "daemon items such as {\"ev\":\"daemon\",\"kind\":\"score\"} when the daemon re-scores your pid); it waits "
        "up to wait_s seconds for the first event. finish(verdict) ends the case; verdict is the JSON object from "
        "<verdict>.\n"
        + _mode_note(dry_run) + "\n</harness>"
    )
    return "\n\n".join([blocks["B"], blocks["R"], blocks["H"], note])
