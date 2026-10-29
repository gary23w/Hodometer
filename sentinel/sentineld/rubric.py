"""Block R, the part code can see: I1-I4, L1-L3, D1-D3, D5, D6, P1-P3, B1 (cased pids), B2 and the trust offsets.

Every signal carries its evidence so Sentinel can check the daemon's work; the models score the rest (D4, P4)
from the digests and their own packet dives.
"""
import ctypes
import ipaddress
import re
import statistics
import time

# names a dropper borrows (I3): core Windows binaries that only ever live under C:\Windows. Programs Microsoft
# legitimately installs elsewhere (Defender's platform under ProgramData, Store apps) are not in this list.
WINDOWS_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "explorer.exe", "runtimebroker.exe", "services.exe", "winlogon.exe",
    "wininit.exe", "smss.exe", "dwm.exe", "taskhostw.exe", "conhost.exe", "dllhost.exe", "spoolsv.exe", "sihost.exe",
    "ctfmon.exe", "fontdrvhost.exe", "wmiprvse.exe", "audiodg.exe", "lsm.exe", "userinit.exe", "cmd.exe",
    "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe",
}
SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "curl.exe", "wget.exe",
}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
            "iexplore.exe", "chromium.exe", "arc.exe", "waterfox.exe", "librewolf.exe", "tor.exe"}
L1_PARENTS = BROWSERS | {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
    "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe", "sumatrapdf.exe", "nitro_pro.exe",
    "7zfm.exe", "7zg.exe", "winrar.exe", "winzip64.exe", "winzip32.exe", "peazip.exe", "bandizip.exe",
    "thunderbird.exe", "discord.exe", "telegram.exe", "slack.exe", "teams.exe", "ms-teams.exe", "whatsapp.exe",
}
KNOWN_PUBLISHERS = [
    "microsoft", "google", "mozilla", "apple", "valve", "adobe", "nvidia", "intel", "advanced micro devices", "amd",
    "discord", "slack", "zoom", "spotify", "dropbox", "epic games", "electronic arts", "ubisoft", "logitech",
    "realtek", "oracle", "amazon", "cisco", "citrix", "autodesk", "jetbrains", "github", "anthropic", "brave",
    "opera", "vivaldi", "notion", "figma", "openai", "python software foundation", "docker", "razer", "corsair",
    "samsung", "dell", "hp inc", "hewlett", "lenovo", "asus", "steam", "riot games", "blizzard", "activision",
    "rockstar", "roblox", "unity", "epic", "1password", "bitwarden", "agilebits", "proton", "nordvpn", "nord security",
    "expressvpn", "mullvad", "telegram", "whatsapp", "signal", "vmware", "broadcom", "obs", "videolan", "7-zip",
    "igor pavlov", "win.rar", "piriform", "malwarebytes", "bitdefender", "kaspersky", "eset", "avast", "avg",
    "norton", "gen digital", "mcafee", "sophos", "crowdstrike", "sentinelone", "trend micro", "canonical", "tailscale",
    "cloudflare", "node.js", "nodejs", "git for windows", "johannes schindelin", "the git development community",
    "rust foundation", "golang", "elgato", "stream deck", "plex", "twitch", "teamviewer", "anydesk", "parsec",
]
STANDARD_PORTS = {80, 443, 853, 53}
COMMON_PORTS = {
    22, 25, 110, 123, 143, 465, 500, 587, 993, 995, 1194, 1701, 3478, 3479, 3480, 3481, 4500, 5060, 5061, 5222,
    5223, 5228, 5229, 5230, 8080, 8443, 8801, 8802, 51820, 7680, 2049, 139, 445, 1900, 5353, 67, 68, 161, 162,
}
APP_PORTS = {
    "steam.exe": range(27000, 27101), "steamwebhelper.exe": range(27000, 27101),
    "discord.exe": range(50000, 65536), "zoom.exe": range(8801, 8811), "teams.exe": range(50000, 50100),
    "ms-teams.exe": range(50000, 50100), "ssh.exe": [22], "git.exe": [22, 9418], "putty.exe": [22, 23],
    "winscp.exe": [21, 22], "filezilla.exe": [21, 22, 990], "outlook.exe": [25, 110, 143, 465, 587, 993, 995],
    "thunderbird.exe": [25, 110, 143, 465, 587, 993, 995], "code.exe": [22], "vmmem": range(1, 65536),
    "vmmemwsl": range(1, 65536), "system": range(1, 65536),
}
D5_SUFFIXES = (
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co", "rentry.co", "rentry.org", "gist.githubusercontent.com",
    "gist.github.com", "transfer.sh", "file.io", "anonfiles.com", "anonfile.com", "gofile.io", "catbox.moe",
    "litterbox.catbox.moe", "pixeldrain.com", "uploadfiles.io", "bashupload.com", "temp.sh", "0x0.st",
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "goo.gl", "t.ly", "rebrand.ly", "v.gd",
    "no-ip.com", "no-ip.org", "ddns.net", "duckdns.org", "dyndns.org", "hopto.org", "zapto.org", "sytes.net",
    "myftp.org", "myftp.biz", "serveftp.com", "servehttp.com", "servegame.com", "redirectme.net", "freedns.afraid.org",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "localhost.run",
    "onion", "i2p", "torproject.org", "torrelay", ".exit",
)
UPDATER_NAMES = {
    "mousocoreworker.exe", "usoclient.exe", "wuauclt.exe", "officeclicktorun.exe", "googleupdate.exe",
    "microsoftedgeupdate.exe", "googleupdater.exe", "updater.exe", "svchost.exe", "dosvc", "setup.exe",
    "nvcontainer.exe", "nvdisplay.container.exe", "nvbackend.exe", "steam.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe", "discord.exe", "update.exe", "squirrel.exe", "ccmexec.exe", "msiexec.exe",
}
BACKUP_TOOLS = {
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe", "backblaze.exe", "bzbackup.exe", "bztransmit.exe",
    "icloud.exe", "icloudservices.exe", "megasync.exe", "syncthing.exe", "rclone.exe", "restic.exe", "duplicati.exe",
    "acronis.exe", "macrium.exe", "veeam.exe", "idrive.exe", "carbonite.exe", "crashplan.exe", "pcloud.exe",
    "nextcloud.exe", "boxsync.exe", "box.exe", "mobilebackup.exe", "itunes.exe", "obs64.exe", "streamlabs obs.exe",
    "git.exe", "git-remote-https.exe", "aws.exe", "gsutil.exe", "azcopy.exe", "rsync.exe", "scp.exe", "sftp.exe",
    "winscp.exe", "filezilla.exe", "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe", "teams.exe",
    "zoom.exe", "chrome.exe", "msedge.exe", "firefox.exe", "python.exe", "claude.exe", "code.exe",
}
USER_WRITABLE_RX = re.compile(r"\\(AppData|Temp|Tmp|Downloads|Users\\Public|ProgramData)\\", re.I)
L2_PATTERNS = [
    (re.compile(r"(^|\s)-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s", re.I), "-enc"),
    (re.compile(r"FromBase64String", re.I), "FromBase64String"),
    (re.compile(r"(^|[\s;(|])IEX([\s(]|$)", re.I), "IEX"),
    (re.compile(r"Invoke-Expression", re.I), "Invoke-Expression"),
    (re.compile(r"DownloadString|DownloadFile|DownloadData", re.I), "DownloadString"),
    (re.compile(r"Invoke-WebRequest|(^|\s)iwr\s|Invoke-RestMethod|(^|\s)irm\s", re.I), "Invoke-WebRequest"),
    (re.compile(r"https?://\S+", re.I), "URL in arguments"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), "-w hidden"),
    (re.compile(r"\\(Temp|Downloads|AppData\\Local\\Temp)\\[^\s\"']*\.(ps1|vbs|hta|js|jse|wsf|bat|cmd)\b", re.I),
     "script from Temp/Downloads"),
    (re.compile(r"-nop\s|-noprofile\s|-ExecutionPolicy\s+Bypass", re.I), "-nop/-ExecutionPolicy Bypass"),
]
DRIVE_REMOVABLE = 2

_drive_type_cache = {}


def drive_is_removable(path):
    if len(path) < 2 or path[1] != ":":
        return False
    root = path[:2].upper() + "\\"
    if root not in _drive_type_cache:
        try:
            _drive_type_cache[root] = ctypes.windll.kernel32.GetDriveTypeW(root) == DRIVE_REMOVABLE
        except Exception:
            _drive_type_cache[root] = False
    return _drive_type_cache[root]


def is_internet(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
                or a.is_unspecified)


def known_publisher(signer_name):
    s = (signer_name or "").lower()
    return bool(s) and any(p in s for p in KNOWN_PUBLISHERS)


def under_windows(path):
    p = (path or "").lower()
    return p.startswith("c:\\windows\\")


def under_program_files(path):
    p = (path or "").lower()
    return p.startswith("c:\\program files\\") or p.startswith("c:\\program files (x86)\\")


def registered_domain(name):
    parts = name.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


def d5_match(name):
    n = (name or "").lower().strip(".")
    for suf in D5_SUFFIXES:
        if n == suf or n.endswith("." + suf) or (suf.startswith(".") and n.endswith(suf)):
            return suf
    return ""


def _level(score, ncat):
    if score <= 2:
        return "CLEAR"
    if score <= 4:
        return "WATCH"
    if score <= 6:
        return "SUSPECT"
    return "HOSTILE" if ncat >= 3 else "SUSPECT"


def score_process(ps, ledger_entry, now=None, cased=False):
    """Return {"score", "level", "signals": [{"id","points","category","evidence"}], "categories": [...]}."""
    now = now or time.time()
    sig = []
    name = (ps.name or "").lower()
    path = ps.path or ""
    signed_known = ps.signer_state == "signed" and known_publisher(ps.signer_name)
    verdict = (ledger_entry or {}).get("verdict")

    def add(sid, pts, cat, evidence):
        sig.append({"id": sid, "points": pts, "category": cat, "evidence": evidence[:300]})

    # ---- Identity
    if ps.signer_state in ("unsigned", "untrusted"):
        add("I1", 2, "identity", f"signer: {ps.signer_state}" + (f" ({ps.signer_name})" if ps.signer_name else ""))
    if path and (USER_WRITABLE_RX.search(path) or drive_is_removable(path)):
        add("I2", 1, "identity", f"runs from a user-writable place: {path}")
    signed_microsoft = ps.signer_state == "signed" and "microsoft" in (ps.signer_name or "").lower()
    if name in WINDOWS_NAMES and path and not under_windows(path) and not signed_microsoft:
        add("I3", 3, "identity", f"{ps.name} outside C:\\Windows: {path}")
    if ps.integrity.lower() in ("high", "system") and path and not under_windows(path) and not under_program_files(path) \
            and not signed_known:
        add("I4", 1, "identity", f"integrity {ps.integrity} for {path}")

    # ---- Lineage
    if name in SCRIPT_HOSTS and ps.inspected:
        parent = (ps.parent_name or "").lower()
        # an empty parent name on a process that had already exited when it was inspected tells us nothing
        if parent in L1_PARENTS or (not parent and ps.alive_at_inspect):
            add("L1", 3, "lineage", f"{ps.name} started by {ps.parent_name or 'an unknown program'} (pid {ps.parent_pid})")
    if ps.cmdline:
        hits = [label for rx, label in L2_PATTERNS if rx.search(ps.cmdline)]
        if hits:
            add("L2", 3, "lineage", f"command line has {', '.join(hits)}: {ps.cmdline[:160]}")
    if ps.child_connected:
        kids = [f"{c['pid']} {c['image'].rsplit(chr(92), 1)[-1]}" for c in ps.children if c.get("connected")][:4]
        add("L3", 2, "lineage", "children that connected out within 60 s: " + ", ".join(kids))

    # ---- Destinations
    table = ps.remotes()
    internet_rows = {k: r for k, r in table.items() if not r["local"] and is_internet(r["ip"])}
    nameless = [r for r in internet_rows.values() if not r["names"] and not r["sni"] and r["port"] not in (53, 853, 123)]
    if nameless:
        ex = ", ".join(f"{r['ip']}:{r['port']}/{r['proto']}" for r in nameless[:3])
        add("D1", 2, "destinations", f"{len(nameless)} internet remote(s) with no DNS name and no SNI: {ex}")
    mismatch = []
    for r in internet_rows.values():
        if r["names"] and r["sni"]:
            doms = {registered_domain(n) for n in r["names"]}
            for s in r["sni"]:
                if registered_domain(s) not in doms:
                    mismatch.append(f"SNI {s} vs DNS {sorted(r['names'])[0]} ({r['ip']})")
    if mismatch:
        add("D2", 1, "destinations", "; ".join(mismatch[:3]))
    odd_ports = []
    app_ports = APP_PORTS.get(name, ())
    for r in internet_rows.values():
        p = r["port"]
        if p in STANDARD_PORTS or p in COMMON_PORTS or p in app_ports:
            continue
        if r["proto"].startswith("udp") and p >= 10000 and signed_known:
            continue
        odd_ports.append(f"{r['ip']}:{p}/{r['proto']}")
    if odd_ports:
        add("D3", 1, "destinations", f"remote ports outside the usual set: {', '.join(odd_ports[:4])}")
    if not signed_known and verdict not in ("trusted", "known"):
        d5 = []
        for r in internet_rows.values():
            for n in list(r["names"]) + list(r["sni"]):
                m = d5_match(n)
                if m:
                    d5.append(f"{n} ({m})")
        if d5:
            add("D5", 2, "destinations", "paste/drop/shortener/relay/dynamic-DNS host: " + ", ".join(sorted(set(d5))[:3]))
    if name not in UPDATER_NAMES and not under_windows(path) and not (signed_known and under_program_files(path)):
        posts = []
        for r in internet_rows.values():
            for h in r["http"]:
                if h.upper().startswith(("POST", "PUT")):
                    posts.append(f"{h[:80]} -> {r['ip']}:{r['port']}")
        if posts:
            add("D6", 2, "destinations", "plaintext HTTP upload: " + "; ".join(posts[:2]))

    # ---- Pattern
    beacon = None
    for key, contacts in ps.contacts.items():
        if not is_internet(key[0]):
            continue
        recent = [c for c in contacts if now - c[0] <= 900]
        if len(recent) < 5:
            continue
        times = sorted(c[0] for c in recent)
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < 4:
            continue
        mean = statistics.fmean(gaps)
        if mean < 2:
            continue
        jitter = (statistics.pstdev(gaps) / mean) if mean else 1
        payload = [c[1] + c[2] for c in recent if (c[1] + c[2]) > 0]
        small = (not payload) or statistics.fmean(payload) < 16384
        if jitter < 0.2 and small:
            beacon = f"{len(recent)} contacts to {key[0]}:{key[1]} every {mean:.0f} s (jitter {jitter * 100:.0f} %)"
            break
    if beacon:
        add("P1", 3, "pattern", "beaconing: " + beacon)
    recent_remotes = {k[0] for k, cs in ps.contacts.items() if is_internet(k[0]) and any(now - c[0] <= 60 for c in cs)}
    recent_fails = sum(1 for t in ps.fail_times if now - t <= 60)
    if len(recent_remotes) >= 20:
        add("P2", 2, "pattern", f"{len(recent_remotes)} distinct remotes in the last minute")
    elif recent_fails >= 10:
        add("P2", 2, "pattern", f"{recent_fails} failed connects in the last minute")
    if name not in BACKUP_TOOLS and ps.disk_read_bps >= 512 * 1024:
        big = [r for r in internet_rows.values() if not r["names"] and r["tx"] >= 5 * 1024 * 1024]
        if big:
            r = big[0]
            add("P3", 3, "pattern", f"disk reads {ps.disk_read_bps / 1048576:.1f} MB/s then {r['tx'] / 1048576:.1f} MB "
                                     f"uploaded to {r['ip']}:{r['port']} (no name)")

    # ---- Behaviour
    if cased and ps.dll_loads:
        bad = [d for d in ps.dll_loads if USER_WRITABLE_RX.search(d)]
        if bad:
            add("B1", 2, "behaviour", "DLLs from a user-writable place: " + ", ".join(bad[:3]))
    if ps.exited and ps.inspect_t and 0 <= ps.exit_t - ps.inspect_t <= 10 and ps.inspect_t - ps.first_seen >= 20:
        add("B2", 3, "behaviour", f"exited {ps.exit_t - ps.inspect_t:.0f} s after being inspected")
    elif getattr(ps, "respawned_after_kill", False):
        add("B2", 3, "behaviour", "came back after being killed")

    # ---- Trust offsets
    if signed_known and (under_program_files(path) or under_windows(path)):
        add("T1", -3, "trust", f"signed by {ps.signer_name}, installed under {path.split(chr(92))[1] if chr(92) in path else path}")
    if verdict == "trusted":
        add("T2", -5, "trust", "the user said it is theirs" + (f": {ledger_entry.get('note')}" if ledger_entry.get("note") else ""))
    elif ledger_entry and now - float(ledger_entry.get("first_seen", now)) >= 2 * 86400:
        known_hosts = set(ledger_entry.get("hosts", []))
        hosts = ps.hosts()
        if hosts and known_hosts and len(hosts & known_hosts) >= 0.8 * len(hosts):
            days = (now - float(ledger_entry["first_seen"])) / 86400
            add("T3", -2, "trust", f"known to the baseline for {days:.0f} days with the same hosts")

    score = sum(s["points"] for s in sig)
    cats = sorted({s["category"] for s in sig if s["points"] > 0})
    return {"score": score, "level": _level(score, len(cats)), "signals": sig, "categories": cats}
