# Sentinel daemon

The daemon that `SENTINEL.md` specifies: code with no AI of its own that owns the Hodometer connections, follows the
whole stream, scores every process with the code-visible part of Block R, starts evidence capture at SUSPECT, sends
Sentinel (Prompt A) batched digests, and runs up to four investigators (Prompt B) in parallel, each on its own
Hodometer connection. The prompts are read from `../SENTINEL.md` at start, so the spec stays the single source.

```
Hodometer 127.0.0.1:48201 ──stream (watch all, list/conns/inspect polls)──┐
                          ──control (Sentinel's hodometer tool)───────────┤ sentineld (this folder)
                          ──one connection per investigator───────────────┘   │
                                                                   Claude API (Sonnet): Sentinel + investigators
```

## Layout

| file | what |
|---|---|
| `sentineld/hodometer.py` | socket client: JSON lines, reply matching, the auth flow and the denial rules (shared `AuthGate`) |
| `sentineld/daemon.py` | the daemon: polling, stream events, per-process state, scoring triggers, captures, cases, investigators, console |
| `sentineld/rubric.py` | Block R in code: I1-I4, L1-L3, D1-D3, D5, D6, P1-P3, B1 (cased pids), B2, T1-T3, with evidence per signal |
| `sentineld/state.py` | `ProcState`, `Flow`, `Case`, and the `Ledger` persisted in `state/ledger.json` |
| `sentineld/models.py` | Claude API sessions (Anthropic SDK): tool loop, caching, refusal fallback, context rollover |
| `sentineld/tools.py` | `hodometer`, `open_case`, `mark`, `notify_user`, `events`, `finish`, with the hard rules enforced in code |
| `sentineld/prompts.py` | extracts Prompt A/B and Block R/H from `SENTINEL.md` |
| `setup_runtime.ps1` | builds `runtime\`, the daemon's private Python copy |
| `sentinel.cmd` | starts the daemon from that copy |

## Why a private Python copy

Hodometer trusts a client by executable path and SHA-256. If the daemon ran from the shared `python.exe`, allowing it
would let every Python script on the machine control Hodometer. A venv does not help: on Windows a venv's `python.exe`
is only a launcher, the socket belongs to the base interpreter. So the daemon runs from `sentinel\runtime\python.exe`,
a real standalone CPython copied into this folder with the SDK installed inside it and nothing else. The user allows
that one program; a rebuilt or updated runtime changes the hash and asks again.

`setup_runtime.ps1` copies a uv-managed CPython (`%APPDATA%\uv\python\cpython-3.1x-...`) when one exists, or any
standalone folder you pass with `-Source` (python-build-standalone, or the python.org embeddable package), then runs
`pip install -r requirements.txt` in the copy and drops a `.pth` so `python -I -m sentineld` finds this folder.
`runtime\` and `state\` are git-ignored.

## Setup and run

```powershell
cd sentinel
.\setup_runtime.ps1                 # once; or -Source <standalone python folder>
$env:ANTHROPIC_API_KEY = "..."      # only in the environment, never in a file
.\sentinel.cmd                      # dry-run by default
```

On the first connection Hodometer shows its dialog for `sentinel\runtime\python.exe`; click **Allow always** (one
click covers the stream, the control connection and every investigator). **Allow once** works until the daemon
restarts but then every new connection, including each investigator, asks again.

`--live` turns dry-run off. In dry-run, `kill` and `block` are logged to `state\actions.log` and never sent; their
replies say so (`"ok": false, "dry_run": true`), so the models report that they could not act instead of believing
they did. Everything else (watch, inspect, capture, unblock...) is live in both modes.

| option | default | |
|---|---|---|
| `--dry-run` / `--live` | dry-run | whether kill and block reach Hodometer |
| `--model` | `claude-sonnet-5-5` | Sentinel and SUSPECT-or-higher investigators |
| `--watch-model` | same as `--model` | WATCH-level investigators (`claude-haiku-5-5` is the cheap option) |
| `--effort` | `medium` | `output_config.effort` for every session |
| `--max-investigators` | 4 | parallel investigators; the rest queue by score |
| `--heartbeat` | 60 s | heartbeat to Sentinel (one Sentinel turn each, so this sets the idle cost) |
| `--batch` | 5 s | how long non-urgent items wait to share a turn (SUSPECT+ cases go at once) |
| `--context-limit` | 100000 | tokens; above it Sentinel's conversation restarts with a state recap (the ledger holds every verdict) |
| `--capture` | 300 s | pcapng length started at SUSPECT |
| `--no-models` | | daemon only: scores, digests and cases are logged to `state\outbox.jsonl`, no API calls |
| `--no-fallback` | | do not send the server-side refusal fallback beta |
| `--test-case PID[:LEVEL]` | | force a case for a pid once it is inspected (testing) |
| `--popup` | | show alerts and incidents in a message box too |
| `--state`, `--prompts`, `--port` | | paths and port |

The console takes `/case <pid> [WATCH|SUSPECT|HOSTILE]` (force a case), `/status`, `/procs`, `/quit`; any other line
reaches Sentinel as a `USER:` message.

## What it does

- **Connections.** Stream: `watch all` (no packets) plus the polls; control: Sentinel's `hodometer` tool, opened
  lazily; one per investigator. Reconnects with backoff when Hodometer restarts (and re-issues `watch all`). On
  `{"ev":"auth","status":"pending"}` it prints the Allow instruction; after a denial, or 60 s without an answer, no
  connection is attempted for 10 minutes, on any of the connections, and after three denials it says how to unblock.
  Attempts are spaced 3 s apart so Hodometer never sees a flood.
- **Polling.** `list` every 10 s (new processes), `conns <pid>` every 3 s for every pid in the last tick (plus cased
  pids), `inspect <pid>` once per new process (again if the signer is still pending). The SHA-256 of the program file
  is computed by the daemon and cached.
- **Scoring.** `rubric.py` on every update, with hysteresis: a `case` item goes out when a process's level rises above
  what Sentinel was already told (at once for SUSPECT+, batched for WATCH); while a case is open the investigator gets
  the re-scores as `{"ev":"daemon","kind":"score"}` events instead. `capture <pid> 300` starts the moment a score
  reaches SUSPECT; one capture at a time goes to the highest score.
- **Messages.** `first_sight` 8 s after a program's first inspect (so the talks-to table has filled), one per path+hash
  per Hodometer run; `case`; `respawn` when a program marked hostile comes back (path, hash, or same signer with two
  shared hosts); `investigator_report` (the `finish()` JSON, or an `UNRESOLVED` report after 5 minutes, a model
  error, or a denied connection); `system` (auth, connection, etw, audit, daemon start, conversation restart);
  `heartbeat` with counts. Up to 15 items per turn, urgent ones first.
- **Investigators.** One thread and one Hodometer connection each, fresh conversation, `events()` served from that
  connection's own queue, hard close at 5 minutes, queue by score when four are running (`open_case` says `busy` only
  for HOSTILE, so Sentinel can take it itself). `mark(..., "trusted")` closes open cases on that program.
- **Guards in code.** `reset`, `pause`, `trust clear`, `threshold`, `local`, `audit auto off` are never sent. `kill`
  and `block` refuse the never-kill list, antivirus/EDR and VPN clients, Hodometer, the daemon and its parent, anything
  under `C:\Windows` for `block`; an investigator may only touch its own case tree as the daemon knows it (the pid, its
  children four levels down, a script-host parent). Investigators cannot stop a capture that is not theirs.

## Files in `state\`

`ledger.json` (per program: verdict, note, hash, signer, hosts, first/last seen), `sentinel.log`, `outbox.jsonl`
(every item sent to Sentinel), `actions.log` (every kill/block/unblock: refused, dry-run or sent, with the reply),
`notifications.log` (what `notify_user` showed), `transcripts\sentinel.jsonl` and `transcripts\C<n>-<pid>.jsonl`
(user turns, assistant text, tool calls and results, trimmed).

## Cost

Each heartbeat is one Sentinel turn, so an idle machine costs about one small turn a minute on a cached prompt
(~12 K tokens of system prompt, cached, plus the growing history until the rollover). Raise `--heartbeat` to spend
less. Investigators cost more (packets), bounded by their 30-call, 5-minute budget; WATCH cases can go to
`--watch-model claude-haiku-5-5`.

## Built against Hodometer 1.2.0

Everything above uses the 1.2.0 protocol. Hodometer 1.3's concurrent commands, several captures, `conns` paging and
packet filters are not required; when they arrive the daemon keeps working unchanged (one command in flight per
connection, one capture at a time).
