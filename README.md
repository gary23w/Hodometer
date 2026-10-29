# Hodometer 1.3

A single-file native Windows tray application (C, Win32, no runtime) that shows exactly which program is sending and
receiving bytes and to which host, keeps Windows connection auditing switched on, lets you or an AI agent kill a
process or block a program on the spot, and streams everything over a localhost socket that only programs you have
explicitly allowed can use.

1.2 adds the **Inspector**: zoom into one process and see its connections (state, RTT, retransmits, connect time),
its packets decoded on the wire (TLS SNI/ALPN, QUIC, DNS, HTTP), a process profile (CPU, memory, disk, GPU, user,
command line, signer) and a timeline (connects, failures, child processes, DLL loads), with pcapng export. All of it
comes from Windows' own kernel providers and `ndiscap.sys`; there is no driver to install.

1.3 makes the socket fit for many agents at once (the Sentinel design in `SENTINEL.md`): commands run on worker
threads, so a slow `inspect` from one client no longer stalls the others; up to four pcapng captures run at the same
time, one per process; `conns` pages through every flow and can filter to active flows or flows touched since a
timestamp; a watcher can ask for decoded handshakes only instead of every frame; a `flowinfo` event announces each
flow's SNI, ALPN, HTTP request or TLS version the moment it is decoded; each connection may watch 64 processes;
`inspect` reports the file's SHA-256 and caches signature checks.

## What it does

- **Exact per-process traffic.** Reads the kernel network ETW provider in real time (the same source Resource Monitor
  uses): bytes sent and received per process, with name, full path and the remote `address:port` that got the most bytes.
  Local and LAN traffic is hidden by default (toggle button, or `local on`).
- **Hostnames.** Learned live from the DNS client ETW provider (the name each program actually resolved), with a plain
  DNS PTR lookup as fallback. Shown in the table and in every event (`host`).
- **Odometers and sparkline.** Rolling-digit counters for bytes OUT and IN with live rates, and a five-minute graph.
- **Process table** sorted by current rate, 24 h of per-minute history per process in memory (`history`) and appended to
  `history.jsonl`.
- **Kill or block.** Select a row: **Kill selected process** (or Delete key, right-click), **Block program (firewall)**
  adds inbound and outbound Windows Firewall block rules for that program's path; unblock from the right-click menu. The
  app refuses to kill the processes Windows cannot live without and itself.
- **Audit keeper.** Every 30 s it checks the *Filtering Platform Connection* audit subcategory (what
  `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable` turns on). Off means it
  turns it back on, logs it and tells connected agents. A button does it immediately.
- **Connection events.** With auditing on, Windows writes Security event 5156 for every connection; the app forwards each
  outbound non-local one as a `conn` event with program path, destination, hostname and port.
- **Spikes.** Upload over 0.75 MB/s or download over 1.5 MB/s (configurable) emits a `spike` event, a line in
  `hodometer.log` and a tray notification (at most one per 5 minutes).
- **Tray.** Left-click the icon to show or hide the window; right-click for pause, audit repair, forget trusted programs,
  log folder, README, exit. Closing or minimising hides to the tray; Exit is in the tray menu.

## Inspector (zoom into a process)

Double-click a row, press **Inspect selected process**, use the right-click menu, or send `inspect <pid> show` over the
socket. Up to eight Inspector windows can be open; each follows one pid.

- **Header.** Name, pid, running/exited/blocked, Authenticode signer (embedded signature, or the Windows catalog that
  covers the file; "unsigned" and "signature not trusted" are called out), path, command line, user and integrity level,
  parent, start time, children, threads, handles; CPU %, memory (working set and private), disk read/write rate, GPU %
  (the per-process "GPU Engine" counters Task Manager uses), CPU time; bytes out/in with rates, active connections,
  retransmitted bytes, failed connection attempts, packets seen; a two-minute rate graph for this process alone.
- **Connections.** Every TCP connection and UDP flow of the process: remote host (DNS name, else the TLS SNI, else the
  address), port, protocol, state (connecting / established / closed / failed, or udp / quic), rates and totals each way,
  retransmitted bytes and packets, smoothed and minimum RTT, local port, age, and an info column with SNI, ALPN, TLS
  version, HTTP request, QUIC version, connect time, reconnects, timeouts and congestion signals, MSS. Lifecycle and
  retransmits come from the Kernel-Network provider (events 12-17 and their IPv6 twins), states are seeded from the TCP
  table, RTT and retransmit counters from TCP ESTATS (enabled per connection while it is inspected).
- **Packets.** Live list of the process's frames: time, direction, protocol, remote, length, TCP flags and a one-line
  decode: TLS ClientHello with SNI and ALPN (reassembled across segments), ServerHello with the negotiated version, TLS
  record types, plaintext HTTP request line and Host header, DNS queries and answers, QUIC version and packet type. For
  QUIC v1 the client Initial is decrypted (its keys derive from the connection id alone, RFC 9001 5.2), so HTTP/3
  connections show SNI and ALPN as well, even when Chrome scatters the ClientHello over many out-of-order CRYPTO
  fragments. Payloads stay encrypted; nothing beyond the handshake is read.
- **Timeline.** Connect / established (with connect latency) / closed / failed (with the Winsock error) / retransmit
  bursts, TLS hellos, DNS queries, HTTP requests, QUIC hellos, child processes the inspected process started, image (DLL)
  loads while inspected, process exit, finished captures.
- **Capture 30 s → pcapng.** Writes just this process's frames to `capture_<name>_<pid>_<time>.pcapng` next to the exe;
  opens in Wireshark. Up to four captures (one per process, or one for every process) can run at once; the header shows
  this process's capture and notes when others are running. **Copy JSON** puts the whole Inspector state on the clipboard
  (the `inspect` reply). **Kill** and **Block** act on this process.

How it works: frames come from Windows' own `ndiscap.sys` (the Microsoft-Windows-NDIS-PacketCapture provider behind
`netsh trace`) through a second ETW session, `HodometerZoom`, which runs only while an Inspector is open, a socket
client is watching, or a capture is running (plus a 30 s grace period). Frames carry no process id; Hodometer attributes
them by matching local and remote address and port against the connection table it builds from the kernel network
events. That is how it does per-process packets, which pktmon and Wireshark cannot. Names learned from SNI also fill the
main table's host column when DNS revealed nothing (browsers using DNS over HTTPS, for instance).

## Who may connect: the prompt

Every new socket client is identified by its owning process (via the TCP table), its executable path and the file's
SHA-256. Unless that program is already trusted, a **standard Windows task dialog** appears (shield icon, three
command-link buttons):

- **Allow always**: remembered in `trusted.jsonl` by path and hash; a changed file asks again.
- **Allow once**: this connection only.
- **Deny**: refused now and refused silently for the next 10 minutes. Three denials of the same program block its
  network access with firewall rules and raise an `intruder` event and a tray alert.

The dialog denies automatically after 60 s (`--auth-timeout N` to change) and closes by itself if the client gives up.
More than ten connection attempts within a minute suspend prompting for five minutes (everything unknown is denied).
Hodometer runs elevated, so Windows' integrity isolation (UIPI) stops non-elevated programs from clicking the dialog
for themselves. Until a client is allowed it receives only `{"ev":"auth","status":"pending"}` and its commands are
rejected. `pardon <substring>` clears a program's denial record and any firewall block it earned.

## Install / run

- `build.ps1` builds `Hodometer.exe` with MinGW-w64 (WinLibs gcc + windres); links ws2_32, iphlpapi, dnsapi, advapi32,
  shell32, user32, gdi32, comctl32, ole32, psapi, pdh, wintrust, crypt32 and bcrypt, statically. `build.ps1 -Out
  Hodometer-new.exe` builds under another name while `Hodometer.exe` is running (the running exe is locked).
- `install.ps1` (run as administrator once) registers the logon task **Hodometer** (elevated, no UAC prompt), puts a
  Desktop shortcut that starts that task, retires the older script watcher and starts the app.
- Options: `--port N` (default 48201), `--tx MBPS`, `--rx MBPS`, `--auth-timeout SECONDS`, `--show`, `--local`,
  `--no-audit-auto`.
- Uninstall: `Unregister-ScheduledTask -TaskName Hodometer -Confirm:$false`, delete the folder and the shortcut; firewall
  rules it created are named `Hodometer block: ...` and can be removed in Windows Firewall or with `unblock`.

## Socket protocol

TCP `127.0.0.1:48201`, newline-delimited JSON. Connect, wait for `auth` to say `allowed` (the user clicks the prompt),
then read events and write commands as plain words or JSON (`{"cmd":"kill","pid":123}`, `{"cmd":"block","path":"..."}`).
Commands run on four worker threads: different clients are served in parallel, each client's own commands run one at a
time in the order it sent them, so replies come back in command order (events interleave; match a reply by its `reply`
field). A client with more than 128 commands queued across all clients gets `{"reply":"error","error":"command queue
full, try again"}`. Up to 32 clients.

Events:

| ev | when | fields |
|---|---|---|
| `auth` | on connect and on decisions | `status`: `pending`, `allowed` (+`remembered`), `denied`, `asking`, `abandoned`, `suspended` |
| `hello` | once allowed | `version`, `port` |
| `tick` | every second | `t`, `tx_mbps`, `rx_mbps`, `tx_total`, `rx_total`, `audit`, `etw`, `procs[]` (top 25 active: `pid`, `name`, `tx_bps`, `rx_bps`, `tx_total`, `rx_total`, `remote`, `host`, `blocked`, `vm`, `conns`, `retx`, `fails`, `path`) |
| `spike` | burst over threshold (10 s hold) | `kind`, `tx_mbps`, `rx_mbps`, `top[]` |
| `conn` | each outbound connection (Security 5156) | `pid`, `app`, `path` (NT device path), `dst`, `host`, `port`, `proto` |
| `flow` | watched pid: connection lifecycle | `pid`, `kind` (`connect`, `established` +`connect_ms`, `closed` +`tx`/`rx`, `failed` +`error`, `retransmit` +`bytes`, `reconnect`), `proto`, `lport`, `remote`, `port`, `host` |
| `flowinfo` | watched pid: a flow's identity was just decoded (once per flow; twice at most) | the same fields as a `conns` entry: `pid`, `proto`, `lport`, `remote`, `port`, `host`, `state`, `sni`, `alpn`, `tls`, `quic`, `http`, bytes, RTT... Sent on a TLS or QUIC ClientHello with SNI or ALPN, on the first plaintext HTTP request, and on a TLS ServerHello when no ClientHello was seen (a TLS flow without SNI). Needs no `packets` and is not counted against the packet budget |
| `pkt` | watched pid with `packets` (every frame) or `handshakes` (only frames that decode to a TLS ClientHello/ServerHello, DNS query/answer, HTTP request/response or decoded QUIC hello): max 200/s per client | `pid`, `t`, `dir`, `proto`, `lport`, `remote`, `port`, `host`, `len`, `flags`, `info` (the decode) |
| `trace` | watched pid: process events | `kind` (`start` with `ppid`/`image`, `stop` with `exit_code`, `image` = DLL load) |
| `capture` | a pcapng was closed | `path`, `pid`, `packets`, `bytes`, `active` (captures still running) |
| `killed`, `blocked`, `unblocked` | actions taken | `pid` / `path`, `by` |
| `intruder` | a program was denied three times | `path`, `denials`, `firewall_blocked` |
| `audit` | policy changed or repaired | `enabled`, `action` |
| `client` | a client was dropped | `status`, `why` |
| `snap` | a window capture finished | `path`, `ok`, `window` (`main` or `inspector`) |

Commands:

| command | reply |
|---|---|
| `status` | totals, rates, audit, etw and zoom state, thresholds, clients, trusted, blocked, `captures` running (and `max_captures`, `max_watch`, `workers`), history minutes, uptime |
| `whoami` / `clients` | your own identity / all connected clients |
| `list` | every process seen with totals, rates, top remote, host, active connections, retransmitted bytes, failed connects, path |
| `inspect <pid> [show]` | everything the Inspector shows: profile, signer and `sha256` of the executable, `conns[]` (state, RTT, retransmits, SNI, ALPN, TLS, QUIC, HTTP, connect time), last 100 `timeline[]` entries, last 100 `packets[]`, zoom state. `show` also opens (or raises) the Inspector window. Takes 0.3 to 1 s but runs on its own worker, so other clients are not held up |
| `conns [pid\|all] [active] [since <now>] [cursor <n>] [limit <n>]` | connections of one process (seeded from the TCP table, with ESTATS) or of every process, up to 800 per reply. `active` drops closed and failed flows; `since <t>` keeps flows touched (bytes, connect, close) at or after `t`, where `t` is the `now` value of an earlier reply (a millisecond tick clock), so a poller sends `conns all since <last now>` and misses nothing; `cursor`/`limit` page: the reply carries `total` (flows that match), `count` (in this reply) and `next` (the cursor for the rest, or `null`). JSON form `{"cmd":"conns","pid":N,"active":true,"since":T,"cursor":N,"limit":N}` |
| `watch <pid\|all> [packets\|handshakes\|nopackets]` / `watch <pid> off` / `watch off` / `watch packets\|handshakes\|nopackets` / `watch` | stream `flow`, `trace` and `flowinfo` events for those processes (64 per connection); `packets` adds a `pkt` event per frame, `handshakes` only the frames that decode to TLS, QUIC, DNS or HTTP handshakes. The bare mode word changes the mode of an existing watch. Reply: `watching[]`, `count`, `max`, `mode`, `packets`. Watching starts the zoom session |
| `capture <pid\|all> [seconds] [file.pcapng]` / `capture stop [pid\|all]` / `capture` | write that process's frames to a pcapng (default 30 s, `capture_<pid>_<time>.pcapng` next to the exe; a bare file name lands there too); JSON form `{"cmd":"capture","pid":N,"seconds":S,"path":"..."}`. Up to four run at once, one per pid (`all` counts as one); starting one for a pid already being captured replaces that capture, a fifth is refused. `capture stop` ends every capture, `capture stop <pid>` one, `capture stop all` the `all` capture. `capture` shows the newest one in `active`/`pid`/`path`/`packets`/`bytes`/`seconds_left` and all of them in `captures[]` (`count`, `max`). A `capture` event follows each file that is closed |
| `zoom` | zoom session state, frames seen / matched / unmatched, interest set, `captures` running |
| `history [minutes]` | per-minute totals and top processes, up to 1440 minutes |
| `kill <pid>` | `{"reply":"kill","ok":true|false,"error":"..."}` |
| `block <pid|"path">` / `unblock <pid|"path">` / `blocks` | firewall block rules in and out for that program |
| `trust [list]` / `trust remove <substr>` / `trust clear` | the Allow-always list |
| `denials` / `pardon <substr>` | denial records (count, cooldown, blocked) / clear them |
| `resolve <ip>` | hostname from the DNS trace or PTR cache |
| `audit` / `audit on` / `audit auto on|off` | audit state; `on` re-enables immediately |
| `threshold <tx_mbps> [rx_mbps]`, `local on|off`, `pause on|off`, `reset`, `show` | settings and window |
| `snap [file.bmp] [pid]` | capture the main window, or the open Inspector of `pid`, to a bitmap (default `snapshot.bmp` next to the exe), so an agent can look at the GUI |
| `help` | the list above |

Example (PowerShell):

```powershell
$c = New-Object Net.Sockets.TcpClient('127.0.0.1', 48201); $s = $c.GetStream()
$r = New-Object IO.StreamReader($s); $w = New-Object IO.StreamWriter($s); $w.AutoFlush = $true
$r.ReadLine()                       # {"ev":"auth","status":"pending"...}  -> click Allow on the dialog
$r.ReadLine(); $r.ReadLine()        # hello, auth allowed
$w.WriteLine('status'); $r.ReadLine()
```

`test_client.py` is a minimal Python client that prints events and sends commands once allowed.

`SENTINEL.md` turns this socket into an always-on AI defense (written for Claude Sonnet): a non-AI daemon follows the
whole stream and scores every process, a Sentinel coordinator reviews every process that reaches the internet, and
parallel investigators hook suspicious processes, deep-dive their packets, and block or kill harmful process trees
under hard limits. It contains both system prompts, the shared threat rubric, the Hodometer reference and the daemon
specification.

## Files

`hodometer.log` (start/stop, spikes, kills, blocks, audit repairs, auth decisions, zoom session, captures), `history.jsonl`
(one line per minute), `trusted.jsonl`, `blocked.jsonl`, `install.log`, `snapshot.bmp` (on `snap`), `capture_*.pcapng`
(Inspector captures).

## Notes and limits

- Bytes are counted at the kernel socket layer, so they match what left the machine.
- Traffic from WSL or Hyper-V virtual machines is attributed to `System` or `vmmem` on the host (marked `vm`).
- Blocking is by program path through Windows Firewall; there is no throttling.
- The ETW sessions are `HodometerETW` (always) and `HodometerZoom` (while inspecting); a crashed instance's sessions are
  replaced on the next start.
- Packet zoom reads frames at the NDIS layer, so loopback (127.0.0.1) traffic is not visible there; it still appears in
  the connection list and byte counts. Native 802.11 frames are skipped (Wi-Fi adapters normally present Ethernet frames).
  Frames are matched to a connection only after the kernel has reported that connection, so the first packet of a brand
  new flow can be missed. On Hyper-V/WSL hosts the same frame can be seen on the virtual switch and the physical adapter;
  only the first interface a flow is seen on is counted.
- Decoding is handshake-only: TLS payloads and QUIC after the Initial are never decrypted. QUIC v2 and draft versions are
  recognised but not decrypted. ESTATS RTT and retransmit counters exist only for established TCP connections and start
  counting when the connection is first inspected.
- Signer: Authenticode (embedded) or the Windows security catalog; the check runs on a worker thread, so the header says
  "checking signature…" for a moment. Results are cached per path and SHA-256 (64 entries), so repeated `inspect`s of
  the same executable skip the catalog lookup; a changed file is checked again. GPU % needs the WDDM "GPU Engine"
  counters (Windows 10 1709+).
- Socket limits: 32 clients, 64 watched pids per client, 200 `pkt` events per second per client (use `handshakes` or
  `flowinfo` to stay under it), 4 captures, 800 flows per `conns` reply (page with `cursor`), 128 queued commands.
- The exe is linked statically (`-static`) so it needs no MinGW runtime DLLs; dark scrollbars and menus use the
  undocumented uxtheme dark-mode entry points (Windows 10 1809+; harmless if absent).
