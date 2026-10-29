# Hodometer 1.1

A single-file native Windows tray application (C, Win32, no runtime) that shows exactly which program is sending and
receiving bytes and to which host, keeps Windows connection auditing switched on, lets you or an AI agent kill a
process or block a program on the spot, and streams everything over a localhost socket that only programs you have
explicitly allowed can use.

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

- `build.ps1` builds `Hodometer.exe` with MinGW-w64 (WinLibs gcc + windres).
- `install.ps1` (run as administrator once) registers the logon task **Hodometer** (elevated, no UAC prompt), puts a
  Desktop shortcut that starts that task, retires the older script watcher and starts the app.
- Options: `--port N` (default 48201), `--tx MBPS`, `--rx MBPS`, `--auth-timeout SECONDS`, `--show`, `--local`,
  `--no-audit-auto`.
- Uninstall: `Unregister-ScheduledTask -TaskName Hodometer -Confirm:$false`, delete the folder and the shortcut; firewall
  rules it created are named `Hodometer block: ...` and can be removed in Windows Firewall or with `unblock`.

## Socket protocol

TCP `127.0.0.1:48201`, newline-delimited JSON. Connect, wait for `auth` to say `allowed` (the user clicks the prompt),
then read events and write commands as plain words or JSON (`{"cmd":"kill","pid":123}`, `{"cmd":"block","path":"..."}`).

Events:

| ev | when | fields |
|---|---|---|
| `auth` | on connect and on decisions | `status`: `pending`, `allowed` (+`remembered`), `denied`, `asking`, `abandoned`, `suspended` |
| `hello` | once allowed | `version`, `port` |
| `tick` | every second | `t`, `tx_mbps`, `rx_mbps`, `tx_total`, `rx_total`, `audit`, `etw`, `procs[]` (top 25 active: `pid`, `name`, `tx_bps`, `rx_bps`, `tx_total`, `rx_total`, `remote`, `host`, `blocked`, `vm`, `path`) |
| `spike` | burst over threshold (10 s hold) | `kind`, `tx_mbps`, `rx_mbps`, `top[]` |
| `conn` | each outbound connection (Security 5156) | `pid`, `app`, `path` (NT device path), `dst`, `host`, `port`, `proto` |
| `killed`, `blocked`, `unblocked` | actions taken | `pid` / `path`, `by` |
| `intruder` | a program was denied three times | `path`, `denials`, `firewall_blocked` |
| `audit` | policy changed or repaired | `enabled`, `action` |
| `client` | a client was dropped | `status`, `why` |
| `snap` | a window capture finished | `path`, `ok` |

Commands:

| command | reply |
|---|---|
| `status` | totals, rates, audit and capture state, thresholds, clients, trusted, blocked, history minutes, uptime |
| `whoami` / `clients` | your own identity / all connected clients |
| `list` | every process seen with totals, rates, top remote, host, path |
| `history [minutes]` | per-minute totals and top processes, up to 1440 minutes |
| `kill <pid>` | `{"reply":"kill","ok":true|false,"error":"..."}` |
| `block <pid|"path">` / `unblock <pid|"path">` / `blocks` | firewall block rules in and out for that program |
| `trust [list]` / `trust remove <substr>` / `trust clear` | the Allow-always list |
| `denials` / `pardon <substr>` | denial records (count, cooldown, blocked) / clear them |
| `resolve <ip>` | hostname from the DNS trace or PTR cache |
| `audit` / `audit on` / `audit auto on|off` | audit state; `on` re-enables immediately |
| `threshold <tx_mbps> [rx_mbps]`, `local on|off`, `pause on|off`, `reset`, `show` | settings and window |
| `snap [file.bmp]` | capture the window to a bitmap (default `snapshot.bmp` next to the exe), so an agent can look at the GUI |
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

## Files

`hodometer.log` (start/stop, spikes, kills, blocks, audit repairs, auth decisions), `history.jsonl` (one line per
minute), `trusted.jsonl`, `blocked.jsonl`, `install.log`, `snapshot.bmp` (on `snap`).

## Notes and limits

- Bytes are counted at the kernel socket layer, so they match what left the machine.
- Traffic from WSL or Hyper-V virtual machines is attributed to `System` or `vmmem` on the host (marked `vm`).
- Blocking is by program path through Windows Firewall; there is no throttling.
- The ETW session is `HodometerETW`; a crashed instance's session is replaced on the next start.
