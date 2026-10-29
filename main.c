/*  Hodometer 1.3  -  system-tray network monitor for Windows 10/11 (x64). Single C file, Win32 only, no runtime.
 *  1.2 adds the Inspector ("zoom"): per-process connections with lifecycle, retransmits and TCP ESTATS RTT, a process profile
 *  (CPU, memory, disk, GPU, signer), a second ETW session that reads raw frames from Windows' own ndiscap.sys and decodes
 *  TLS SNI / DNS / HTTP / QUIC per connection, pcapng export, and a process timeline (spawns, image loads, flows).
 *  1.3 scales the socket for many agents at once: commands run on worker threads (ordered per client), up to four pcapng
 *  captures at a time, a cursor / active / since filter on conns, a per-client handshake-only packet filter, a flowinfo
 *  event when a flow's SNI / ALPN / HTTP / QUIC identity is first decoded, 64 watch slots and a signer cache.
 */
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#define _WIN32_IE 0x0A00
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#define __USE_MINGW_ANSI_STDIO 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <windns.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tcpestats.h>
#include <pdh.h>
#include <pdhmsg.h>
#define PSAPI_VERSION 1
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <wchar.h>

#define APP_VERSION      "1.3.0"
#define APP_CLASS        L"HodometerMain"
#define INSPECT_CLASS    L"HodometerInspect"
#define ZOOM_SESSION     L"HodometerZoom"
#define MAX_CONNS        4096
#define CONN_HASH        8192
#define PID_HASH         4096
#define PKT_RING         2048
#define TRACE_RING       4096
#define MAX_INSPECT      8
#define MAX_ZOOM_PIDS    256
#define MAX_WATCH        64
#define MAX_CAPS         4
#define CMD_WORKERS      4
#define JOB_RING         128
#define CMD_BIG          (640 * 1024)
#define CONNS_PAGE       800
#define PKT_BUDGET       200
#define SIG_CACHE        64
#define REASM_SLOTS      32
#define REASM_MAX        4096
#define ISPARK_N         120
#define WM_SIGNER        (WM_APP + 6)
#define WM_INSPECT       (WM_APP + 7)
#define IDC_BTN_INSPECT  1012
#define IDM_INSPECT      2013
#define IDC_I_LIST0      1301
#define IDC_I_LIST1      1302
#define IDC_I_LIST2      1303
#define IDC_I_TAB0       1311
#define IDC_I_TAB1       1312
#define IDC_I_TAB2       1313
#define IDC_I_CAP        1321
#define IDC_I_COPY       1322
#define IDC_I_KILL       1323
#define IDC_I_BLOCK      1324
#define IDM_I_COPYADDR   2101
#define IDM_I_COPYINFO   2102
#define IDM_I_COPYLINE   2103
#define ODO_CLASS        L"HodometerOdo"
#define SPARK_CLASS      L"HodometerSpark"
#define STATUS_CLASS     L"HodometerStatus"
#define AUTH_CLASS       L"HodometerAuth"
#define SESSION_NAME     L"HodometerETW"
#define MUTEX_NAME       L"Local\\HodometerSingleton"
#define DEFAULT_PORT     48201
#define MAX_PROCS        2048
#define MAX_CLIENTS      32
#define MAX_REMOTES      8
#define MAX_TRUST        256
#define MAX_DENY         128
#define MAX_BLOCKED      128
#define HOST_SLOTS       8192
#define HIST_MIN         1440
#define HIST_PROCS       16
#define SPARK_N          300
#define CLIENT_LINE_MAX  4096
#define WM_TRAY          (WM_APP + 1)
#define WM_SHOWME        (WM_APP + 2)
#define WM_ODO_SET       (WM_APP + 3)
#define WM_AUTHREQ       (WM_APP + 4)
#define WM_SNAP          (WM_APP + 5)
#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 2
#endif
#define ID_TIMER_TICK    1
#define ID_TIMER_AUDIT   2
#define ID_TIMER_TIP     3
#define IDC_LIST         1001
#define IDC_BTN_KILL     1002
#define IDC_BTN_AUDIT    1003
#define IDC_BTN_LOCAL    1004
#define IDC_BTN_COPY     1005
#define IDC_BTN_HIDE     1006
#define IDC_BTN_BLOCK    1007
#define IDC_STATUS       1008
#define IDC_ODO_TX       1009
#define IDC_ODO_RX       1010
#define IDC_SPARK        1011
#define IDC_AUTH_ALWAYS  1101
#define IDC_AUTH_ONCE    1102
#define IDC_AUTH_DENY    1103
#define IDM_SHOW 2001
#define IDM_AUDIT 2002
#define IDM_LOGDIR 2003
#define IDM_COPYADDR 2004
#define IDM_EXIT 2005
#define IDM_KILL 2006
#define IDM_COPYPID 2007
#define IDM_PAUSE 2008
#define IDM_BLOCK 2009
#define IDM_UNBLOCK 2010
#define IDM_TRUSTCLEAR 2011
#define IDM_OPENREADME 2012

/* palette */
#define C_BG      RGB(18, 19, 24)
#define C_PANEL   RGB(27, 29, 36)
#define C_CELL    RGB(30, 32, 40)
#define C_BORDER  RGB(46, 50, 64)
#define C_TEXT    RGB(228, 230, 234)
#define C_MUTED   RGB(138, 143, 155)
#define C_GREEN   RGB(90, 200, 120)
#define C_BLUE    RGB(90, 160, 230)
#define C_RED     RGB(224, 90, 90)
#define C_AMBER   RGB(230, 180, 80)
#define C_SEL     RGB(44, 62, 90)

/* ------------------------------------------------------------------ data ------------------------------------------------------------------ */
typedef struct { char addr[48]; uint16_t port; uint64_t tx, rx; } Remote;
typedef struct {
    int used, dead, blocked, vm;
    DWORD pid, ppid;
    wchar_t name[64];
    wchar_t path[MAX_PATH];
    uint64_t tx_total, rx_total, tx_win, rx_win, tx_min, rx_min, retx;
    double tx_rate, rx_rate;
    Remote rem[MAX_REMOTES]; int nrem;
    ULONGLONG last_seen, last_alive_check;
    DWORD nconn, fails;
} Proc;
/* one socket-level flow: TCP connection or UDP 4-tuple, keyed by local+remote address/port (the join key between the
   kernel network events, the TCP table, ESTATS and raw frames from ndiscap) */
typedef struct {
    int used; DWORD pid; BYTE v6, udp, local, state;                   /* state 0 seen, 1 connecting, 2 established, 3 closed, 4 failed */
    BYTE laddr[16], raddr[16]; uint16_t lport, rport; DWORD ifidx, stamp;
    ULONGLONG first_seen, last_seen, t_attempt, t_est, t_close;
    uint64_t tx, rx, tx_win, rx_win, retx, pkts_out, pkts_in; double tx_rate, rx_rate;
    DWORD retx_events, reconnects; uint16_t mss; int connect_ms;
    int estats; ULONG srtt, minrtt, maxrtt, rto, pretrans, timeouts, cong, cur_mss, dupacks;
    char sni[96], alpn[24], http[96]; uint16_t tls_ver; BYTE tls_hello, quic, announced; uint32_t quic_ver;   /* announced: a flowinfo event went out for this flow */
    int hnext;
} Conn;
typedef struct { ULONGLONG t; DWORD pid; int conn; BYTE out, v6, udp, flags; uint16_t len, lport, rport; BYTE raddr[16]; char info[112]; } Pkt;
/* kinds: 1 process start, 2 process stop, 3 image load, 4 connect, 5 established, 6 closed, 7 failed, 8 retransmit, 9 reconnect,
          10 TLS hello, 11 DNS, 12 HTTP, 13 QUIC, 14 capture */
typedef struct { ULONGLONG t; DWORD pid, ppid; BYTE kind; wchar_t detail[120]; } TraceEv;
typedef struct { char ip[48]; wchar_t host[128]; int src; ULONGLONG when; } HostEnt;         /* src 1 dns, 2 ptr, 3 negative */
typedef struct { wchar_t path[MAX_PATH]; char sha[65]; char since[24]; } Trust;
typedef struct { wchar_t path[MAX_PATH]; int count; ULONGLONG last; int blocked; } Deny;
typedef struct { wchar_t path[MAX_PATH]; char since[24]; } Blocked;
typedef struct { char t[20]; uint64_t tx, rx; int n; struct { DWORD pid; wchar_t name[48]; uint64_t tx, rx; } p[HIST_PROCS]; } Minute;
#define OUTBUF_MAX (512 * 1024)
/* watch_pkts: 0 flow/trace/flowinfo only, 1 every frame (pkt), 2 decoded handshakes only (TLS hellos, QUIC hellos, DNS, HTTP). gen tells a queued command from a client that has since been replaced in the slot */
typedef struct { SOCKET s; int state; /* 0 free 1 pending 2 allowed 3 deny-close */ int greeted; DWORD pid, ppid, gen; wchar_t path[MAX_PATH]; wchar_t name[64]; char sha[65]; char buf[CLIENT_LINE_MAX]; int len; ULONGLONG since; int once; char *outbuf; int outlen; int overflow; DWORD watch[MAX_WATCH]; int nwatch, watch_pkts; LONG pkt_budget; } Client;
typedef struct { int used; int ci; DWORD gen; ULONGLONG seq; char line[CLIENT_LINE_MAX]; } Job;   /* one queued socket command */
typedef struct { FILE *f; DWORD pid; ULONGLONG started, until; uint64_t pkts, bytes; wchar_t path[MAX_PATH]; } Cap;   /* one running pcapng capture (pid 0 = every process the zoom is interested in) */
typedef struct { wchar_t path[MAX_PATH]; DWORD pid; uint64_t pkts, bytes; } CapDone;
typedef struct { wchar_t path[MAX_PATH]; char sha[65]; int sig; wchar_t name[160]; ULONGLONG when; } SigEnt;

static Proc g_procs[MAX_PROCS]; static int g_pidx[PID_HASH];   /* pid -> index+1 (open addressing) */
static Conn g_conns[MAX_CONNS]; static int g_chash[CONN_HASH];
static Pkt g_pkts[PKT_RING]; static unsigned g_pkt_head;
static TraceEv g_trace[TRACE_RING]; static unsigned g_trace_head;
static CRITICAL_SECTION g_zlock;                                           /* rings, interest set, capture file; never take g_lock while holding it */
static DWORD g_zoom_pids[MAX_ZOOM_PIDS]; static int g_nzoom, g_zoom_all;
static volatile LONG g_zoom_state;                                         /* 0 off, 1 starting, 2 running, -1 error */
static ULONG g_zoom_err; static TRACEHANDLE g_zoom_session; static ULONGLONG g_zoom_idle_since, g_zoom_fail_tick;
static volatile LONGLONG g_zoom_frames, g_zoom_matched, g_zoom_unmatched, g_zoom_bytes;
static Cap g_caps[MAX_CAPS]; static CapDone g_cap_last;                    /* under g_zlock; g_cap_last = the capture closed most recently (Inspector header) */
static Job g_jobs[JOB_RING]; static ULONGLONG g_job_seq; static volatile BYTE g_cmd_busy[MAX_CLIENTS]; static CRITICAL_SECTION g_jlock; static CONDITION_VARIABLE g_jcv; static DWORD g_client_gen;   /* g_cmd_busy: written under g_jlock; the socket thread reads it to keep a slot out of reuse while a command of its old client still runs */
static SigEnt g_sigc[SIG_CACHE]; static int g_sigc_n; static CRITICAL_SECTION g_slock;
static BCRYPT_ALG_HANDLE g_alg_hmac, g_alg_ecb, g_alg_gcm;
static Proc g_snap[MAX_PROCS]; static int g_snap_n;
static CRITICAL_SECTION g_lock, g_clock, g_hlock, g_tlock;
static uint64_t g_tx_total, g_rx_total, g_tx_win, g_rx_win;
static double g_tx_rate, g_rx_rate;
static double g_spark_tx[SPARK_N], g_spark_rx[SPARK_N]; static int g_spark_i;
static volatile LONG g_include_local = 0, g_paused = 0;
static double g_tx_thresh = 0.75, g_rx_thresh = 1.5;
static int g_audit_auto = 1;
static volatile LONG g_audit_ok = -1, g_etw_state = 0;
static ULONG g_etw_err = 0;
static TRACEHANDLE g_session = 0;
static int g_port = DEFAULT_PORT, g_auth_timeout = 60, g_quitting = 0;
static ULONGLONG g_start_tick, g_last_balloon, g_spike_until_tx, g_spike_until_rx, g_auth_suspended_until;
static uint64_t g_conn_events; static volatile LONG g_conn_this_sec;
static wchar_t g_exe_dir[MAX_PATH], g_log_path[MAX_PATH], g_hist_path[MAX_PATH], g_trust_path[MAX_PATH], g_block_path[MAX_PATH];
static HWND g_main, g_list, g_status, g_odo_tx, g_odo_rx, g_spark, g_btn_audit, g_auth_dlg;
static HINSTANCE g_inst; static HICON g_icon_small, g_icon_big; static NOTIFYICONDATAW g_nid;
static HFONT g_font, g_font_b, g_font_small, g_font_big;
static HostEnt g_hosts[HOST_SLOTS];
static Trust g_trust[MAX_TRUST]; static int g_ntrust;
static Deny g_deny[MAX_DENY]; static int g_ndeny;
static Blocked g_blocked[MAX_BLOCKED]; static int g_nblocked;
static Minute g_hist[HIST_MIN]; static int g_hist_n, g_hist_i; static int g_cur_minute = -1;
static Client g_clients[MAX_CLIENTS];
static int g_auth_queue[MAX_CLIENTS], g_auth_qn, g_auth_current = -1;
static ULONGLONG g_attempts[32]; static int g_attempt_i;
static char g_ptr_queue[64][48]; static int g_ptr_head, g_ptr_tail; static HANDLE g_ptr_event;

static const GUID KernelNetworkGuid = { 0x7DD42A49, 0x5329, 0x4832, { 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 } };
static const GUID DnsClientGuid     = { 0x1C95126E, 0x7EEA, 0x49A9, { 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D } };
static const GUID AuditFpConnGuid   = { 0x0CCE9226, 0x69AE, 0x11D9, { 0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30 } };
static const GUID NdisCapGuid       = { 0x2ED6006E, 0x4729, 0x4609, { 0xB4, 0x23, 0x3E, 0xE7, 0xBC, 0xD6, 0x78, 0xEF } };   /* Microsoft-Windows-NDIS-PacketCapture (ndiscap.sys) */
static const GUID KernelProcessGuid = { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };   /* Microsoft-Windows-Kernel-Process */

/* ------------------------------------------------------------------ helpers ------------------------------------------------------------------ */
static void now_iso(char *out, int n) { SYSTEMTIME st; GetLocalTime(&st); snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond); }
static void to_utf8(const wchar_t *w, char *out, int n) { if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL)) out[0] = 0; }
static void to_wide(const char *s, wchar_t *out, int n) { if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, out, n)) out[0] = 0; }
static void json_escape(const char *in, char *out, int n) {
    int o = 0;
    for (; *in && o < n - 7; in++) { unsigned char c = (unsigned char)*in; if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; } else if (c < 0x20) o += snprintf(out + o, n - o, "\\u%04x", c); else out[o++] = (char)c; }
    out[o] = 0;
}
static void jw(const wchar_t *w, char *out, int n) { char tmp[2048]; to_utf8(w, tmp, sizeof tmp); json_escape(tmp, out, n); }   /* wide -> escaped utf8 */
static void fmt_bytes_w(uint64_t b, wchar_t *out, int n) {
    if (b < 1024) _snwprintf(out, n, L"%I64u B", (unsigned long long)b); else if (b < 1048576ULL) _snwprintf(out, n, L"%.1f KB", b / 1024.0);
    else if (b < 1073741824ULL) _snwprintf(out, n, L"%.1f MB", b / 1048576.0); else _snwprintf(out, n, L"%.2f GB", b / 1073741824.0);
}
static void fmt_rate_w(double bps, wchar_t *out, int n) { if (bps < 1024) _snwprintf(out, n, L"%.0f B/s", bps); else if (bps < 1048576) _snwprintf(out, n, L"%.0f KB/s", bps / 1024.0); else _snwprintf(out, n, L"%.2f MB/s", bps / 1048576.0); }
static void log_json(const char *json) { FILE *f = _wfopen(g_log_path, L"ab"); if (!f) return; char ts[32]; now_iso(ts, sizeof ts); fprintf(f, "{\"t\":\"%s\",%s\n", ts, json + 1); fclose(f); }
static int is_local4(const BYTE *a) { if (a[0] == 127 || a[0] == 10 || a[0] == 0 || a[0] >= 224) return 1; if (a[0] == 192 && a[1] == 168) return 1; if (a[0] == 172 && a[1] >= 16 && a[1] <= 31) return 1; if (a[0] == 169 && a[1] == 254) return 1; return 0; }
static int is_local6(const BYTE *a) { static const BYTE loop[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; static const BYTE zero[16] = { 0 }; if (!memcmp(a, loop, 16) || !memcmp(a, zero, 16)) return 1; if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1; if (a[0] == 0xff) return 1; if ((a[0] & 0xfe) == 0xfc) return 1; return 0; }
static int is_local_str(const char *s) { BYTE b[16]; if (inet_pton(AF_INET, s, b) == 1) return is_local4(b); if (inet_pton(AF_INET6, s, b) == 1) return is_local6(b); return 0; }
static void enable_privilege(const wchar_t *name) { HANDLE tok; TOKEN_PRIVILEGES tp; LUID luid; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return; if (LookupPrivilegeValueW(NULL, name, &luid)) { tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL); } CloseHandle(tok); }
static int is_elevated(void) { HANDLE tok; TOKEN_ELEVATION te; DWORD n; int r = 0; if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) r = te.TokenIsElevated != 0; CloseHandle(tok); } return r; }
static int pid_path(DWORD pid, wchar_t *path, int n) { path[0] = 0; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (!h) return 0; DWORD len = n; int ok = QueryFullProcessImageNameW(h, 0, path, &len); CloseHandle(h); return ok; }
static DWORD parent_pid(DWORD pid) { DWORD pp = 0; HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (s == INVALID_HANDLE_VALUE) return 0; PROCESSENTRY32W e = { sizeof e }; if (Process32FirstW(s, &e)) do { if (e.th32ProcessID == pid) { pp = e.th32ParentProcessID; break; } } while (Process32NextW(s, &e)); CloseHandle(s); return pp; }
static const wchar_t *basename_w(const wchar_t *p) { const wchar_t *b = wcsrchr(p, L'\\'); return b ? b + 1 : p; }
static int sha256_file(const wchar_t *path, char out[65]) {
    out[0] = 0; HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    HCRYPTPROV pv = 0; HCRYPTHASH hh = 0; int ok = 0;
    if (CryptAcquireContextW(&pv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) && CryptCreateHash(pv, CALG_SHA_256, 0, 0, &hh)) {
        static BYTE buf[1 << 16]; DWORD n;
        while (ReadFile(f, buf, sizeof buf, &n, NULL) && n) CryptHashData(hh, buf, n, 0);
        BYTE h[32]; DWORD hl = 32;
        if (CryptGetHashParam(hh, HP_HASHVAL, h, &hl, 0)) { for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", h[i]); ok = 1; }
    }
    if (hh) CryptDestroyHash(hh); if (pv) CryptReleaseContext(pv, 0); CloseHandle(f); return ok;
}
static DWORD run_hidden(const wchar_t *cmdline) {
    STARTUPINFOW si; PROCESS_INFORMATION pi; memset(&si, 0, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    wchar_t cmd[2048]; wcsncpy(cmd, cmdline, 2047); cmd[2047] = 0;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return (DWORD)-1;
    WaitForSingleObject(pi.hProcess, 15000); DWORD rc = (DWORD)-1; GetExitCodeProcess(pi.hProcess, &rc); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return rc;
}
static int json_get_str(const char *js, const char *key, char *out, int n) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key); const char *p = strstr(js, pat); if (!p) return 0;
    p = strchr(p + strlen(pat), ':'); if (!p) return 0; while (*++p == ' ');
    int o = 0;
    if (*p == '"') { p++; while (*p && *p != '"' && o < n - 1) { if (*p == '\\' && p[1]) p++; out[o++] = *p++; } out[o] = 0; return 1; }
    while (*p && *p != ',' && *p != '}' && *p != ' ' && o < n - 1) out[o++] = *p++; out[o] = 0; return o > 0;
}

/* ------------------------------------------------------------------ hostnames (DNS ETW + PTR) ------------------------------------------------------------------ */
static unsigned host_hash(const char *s) { unsigned h = 2166136261u; for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u; return h; }
static HostEnt *host_slot(const char *ip, int create) {
    unsigned h = host_hash(ip) % HOST_SLOTS; HostEnt *oldest = NULL;
    for (int k = 0; k < 16; k++) { HostEnt *e = &g_hosts[(h + k) % HOST_SLOTS]; if (!e->ip[0]) { if (create) { strncpy(e->ip, ip, 47); e->ip[47] = 0; e->host[0] = 0; e->src = 0; e->when = GetTickCount64(); return e; } return NULL; } if (!strcmp(e->ip, ip)) return e; if (!oldest || e->when < oldest->when) oldest = e; }
    if (create && oldest) { memset(oldest, 0, sizeof *oldest); strncpy(oldest->ip, ip, 47); oldest->when = GetTickCount64(); return oldest; }
    return NULL;
}
static int host_lookup(const char *ip, wchar_t *out, int n) {   /* returns src or 0 */
    out[0] = 0; if (!ip[0]) return 0;
    EnterCriticalSection(&g_hlock); HostEnt *e = host_slot(ip, 0); int src = 0;
    if (e && e->host[0]) { wcsncpy(out, e->host, n - 1); out[n - 1] = 0; src = e->src; }
    LeaveCriticalSection(&g_hlock);
    if (!e && !is_local_str(ip)) { EnterCriticalSection(&g_hlock); e = host_slot(ip, 1); if (e) e->src = -1; LeaveCriticalSection(&g_hlock);   /* queue PTR */
        if (e) { int next = (g_ptr_tail + 1) % 64; if (next != g_ptr_head) { strncpy(g_ptr_queue[g_ptr_tail], ip, 47); g_ptr_queue[g_ptr_tail][47] = 0; g_ptr_tail = next; SetEvent(g_ptr_event); } } }
    return src;
}
static void host_learn(const char *ip, const wchar_t *name, int src) {
    if (!ip[0] || !name[0]) return;
    EnterCriticalSection(&g_hlock); HostEnt *e = host_slot(ip, 1);
    if (e && (src == 1 || !e->host[0] || e->src <= 0 || (src == 4 && e->src != 1))) { wcsncpy(e->host, name, 127); e->host[127] = 0; e->src = src; e->when = GetTickCount64(); }   /* DNS wins; an SNI (4) beats a PTR (2) */
    LeaveCriticalSection(&g_hlock);
}
static DWORD WINAPI ptr_thread(LPVOID a) {
    (void)a;
    while (!g_quitting) {
        WaitForSingleObject(g_ptr_event, 2000);
        while (g_ptr_head != g_ptr_tail) {
            char ip[48]; strcpy(ip, g_ptr_queue[g_ptr_head]); g_ptr_head = (g_ptr_head + 1) % 64;
            /* plain DNS PTR query (DnsQuery), not GetNameInfo: the latter also fires NetBIOS probes at the remote host */
            wchar_t rev[200] = L""; BYTE b[16];
            if (inet_pton(AF_INET, ip, b) == 1) _snwprintf(rev, 200, L"%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
            else if (inet_pton(AF_INET6, ip, b) == 1) { int o = 0; for (int k = 15; k >= 0; k--) o += _snwprintf(rev + o, 200 - o, L"%x.%x.", b[k] & 15, b[k] >> 4); wcscat(rev, L"ip6.arpa"); }
            else continue;
            DNS_RECORDW *rec = NULL; wchar_t host[256] = L"";
            if (DnsQuery_W(rev, DNS_TYPE_PTR, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *)&rec, NULL) == 0 && rec) { for (DNS_RECORDW *rr = rec; rr; rr = rr->pNext) if (rr->wType == DNS_TYPE_PTR) { wcsncpy(host, rr->Data.PTR.pNameHost, 255); break; } DnsRecordListFree(rec, DnsFreeRecordList); }
            if (host[0]) host_learn(ip, host, 2);
            else { EnterCriticalSection(&g_hlock); HostEnt *e = host_slot(ip, 0); if (e && !e->host[0]) e->src = 3; LeaveCriticalSection(&g_hlock); }
        }
    }
    return 0;
}
static void dns_event(const BYTE *d, ULONG n) {   /* Microsoft-Windows-DNS-Client 3008: QueryName, QueryType, QueryOptions, QueryStatus, QueryResults */
    const wchar_t *name = (const wchar_t *)d; size_t off = 0; while (off + 2 <= n && *(const wchar_t *)(d + off)) off += 2; off += 2;
    if (off + 16 > n) return; off += 16;
    const wchar_t *res = (const wchar_t *)(d + off); size_t rl = 0; while (off + rl + 2 <= n && res[rl / 2]) rl += 2;
    wchar_t buf[2048]; size_t cnt = rl / 2; if (cnt > 2047) cnt = 2047; wcsncpy(buf, res, cnt); buf[cnt] = 0;
    wchar_t *ctx = NULL;
    for (wchar_t *tok = wcstok(buf, L";", &ctx); tok; tok = wcstok(NULL, L";", &ctx)) {
        while (*tok == L' ') tok++;
        if (!wcsncmp(tok, L"type:", 5)) continue;
        if (!wcsncmp(tok, L"::ffff:", 7)) tok += 7;
        char ip[48]; to_utf8(tok, ip, 48); BYTE b[16];
        if (inet_pton(AF_INET, ip, b) == 1 || inet_pton(AF_INET6, ip, b) == 1) host_learn(ip, name, 1);
    }
}

/* ------------------------------------------------------------------ process table, kill, block ------------------------------------------------------------------ */
static unsigned pid_h(DWORD pid) { return (pid * 2654435761u) >> 20; }   /* 12 bits */
static void pidx_add(int i) { unsigned h = pid_h(g_procs[i].pid); for (int k = 0; k < PID_HASH; k++) { unsigned s = (h + k) & (PID_HASH - 1); if (!g_pidx[s]) { g_pidx[s] = i + 1; return; } } }
static void pidx_rebuild(void) { memset(g_pidx, 0, sizeof g_pidx); for (int i = 0; i < MAX_PROCS; i++) if (g_procs[i].used) pidx_add(i); }
static Proc *proc_find(DWORD pid) { unsigned h = pid_h(pid); for (int k = 0; k < PID_HASH; k++) { int i = g_pidx[(h + k) & (PID_HASH - 1)]; if (!i) return NULL; if (g_procs[i - 1].used && g_procs[i - 1].pid == pid) return &g_procs[i - 1]; } return NULL; }
static Proc *proc_get(DWORD pid) {
    Proc *p = proc_find(pid); ULONGLONG now = GetTickCount64();
    if (!p) { int best = -1; ULONGLONG oldest = ~0ULL; for (int i = 0; i < MAX_PROCS; i++) { if (!g_procs[i].used) { best = i; break; } if (g_procs[i].tx_rate == 0 && g_procs[i].rx_rate == 0 && g_procs[i].last_seen < oldest) { oldest = g_procs[i].last_seen; best = i; } } if (best < 0) return NULL; p = &g_procs[best]; int evicted = p->used; memset(p, 0, sizeof *p); p->used = 1; p->pid = pid; if (evicted) pidx_rebuild(); else pidx_add(best); }
    else if (p->dead) { memset(p, 0, sizeof *p); p->used = 1; p->pid = pid; }   /* same slot, same pid: hash entry stays valid */
    p->last_seen = now; return p;
}
static int path_blocked(const wchar_t *path) { for (int i = 0; i < g_nblocked; i++) if (!_wcsicmp(g_blocked[i].path, path)) return 1; return 0; }
static int trace_find_start(DWORD pid, wchar_t *out, int n);
static int nt_to_dos(const wchar_t *nt, wchar_t *out, int n) {   /* \Device\HarddiskVolume3\x -> C:\x */
    out[0] = 0; if (_wcsnicmp(nt, L"\\Device\\", 8)) return 0;
    for (wchar_t dl = L'A'; dl <= L'Z'; dl++) { wchar_t drv[3] = { dl, L':', 0 }, target[512]; if (!QueryDosDeviceW(drv, target, 512)) continue; size_t tl = wcslen(target); if (tl && !_wcsnicmp(nt, target, tl) && nt[tl] == L'\\') { _snwprintf(out, n, L"%ls%ls", drv, nt + tl); return 1; } }
    return 0;
}
static void proc_resolve(Proc *p) {
    if (p->pid == 0) { wcscpy(p->name, L"Idle"); return; }
    if (p->pid == 4) { wcscpy(p->name, L"System"); p->vm = 1; return; }
    if (pid_path(p->pid, p->path, MAX_PATH)) { wcsncpy(p->name, basename_w(p->path), 63); p->name[63] = 0; }
    else if (!p->name[0] || !wcsncmp(p->name, L"pid ", 4)) {   /* already gone: the Kernel-Process start event remembers its image */
        wchar_t nt[MAX_PATH]; if (trace_find_start(p->pid, nt, MAX_PATH)) { wcsncpy(p->name, basename_w(nt), 63); p->name[63] = 0; if (!p->path[0]) nt_to_dos(nt, p->path, MAX_PATH); }
        else if (!p->name[0]) _snwprintf(p->name, 64, L"pid %lu", (unsigned long)p->pid);
    }
    if (!_wcsnicmp(p->name, L"vmmem", 5) || !_wcsicmp(p->name, L"vmwp.exe")) p->vm = 1;
    p->blocked = p->path[0] ? path_blocked(p->path) : 0;
}
static int proc_alive(DWORD pid) { if (pid == 0 || pid == 4) return 1; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid); if (!h) return GetLastError() == ERROR_ACCESS_DENIED; int alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT; CloseHandle(h); return alive; }
static void remote_add(Proc *p, const char *addr, uint16_t port, uint64_t tx, uint64_t rx) {
    for (int i = 0; i < p->nrem; i++) if (p->rem[i].port == port && !strcmp(p->rem[i].addr, addr)) { p->rem[i].tx += tx; p->rem[i].rx += rx; return; }
    int slot = p->nrem;
    if (slot >= MAX_REMOTES) { slot = 0; uint64_t least = ~0ULL; for (int i = 0; i < MAX_REMOTES; i++) if (p->rem[i].tx + p->rem[i].rx < least) { least = p->rem[i].tx + p->rem[i].rx; slot = i; } if (tx + rx < least) return; } else p->nrem++;
    strncpy(p->rem[slot].addr, addr, 47); p->rem[slot].addr[47] = 0; p->rem[slot].port = port; p->rem[slot].tx = tx; p->rem[slot].rx = rx;
}
static const Remote *proc_top_remote(const Proc *p) { const Remote *best = NULL; uint64_t most = 0; for (int i = 0; i < p->nrem; i++) if (p->rem[i].tx + p->rem[i].rx >= most) { most = p->rem[i].tx + p->rem[i].rx; best = &p->rem[i]; } return best; }

/* ------------------------------------------------------------------ connections (flows) ------------------------------------------------------------------ */
static void send_line(int i, const char *s);
static void bcast(const char *s);
static void zoom_recalc(void);
static int build_inspect_json(DWORD pid, char *out, int n, int live_ok);
static void append_conn_json(char **cur, char *end, const Conn *c);
static HWND insp_hwnd(DWORD pid);
static volatile LONG g_watch_dirty;
static void addr_str(int v6, const BYTE *a, char *out, int n) { if (!inet_ntop(v6 ? AF_INET6 : AF_INET, (void *)a, out, n)) { strncpy(out, "?", n); out[n - 1] = 0; } }
static ULONGLONG now_ft(void) { FILETIME ft; GetSystemTimeAsFileTime(&ft); return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime; }
static void ft_clock(ULONGLONG t, wchar_t *out, int n) { FILETIME ft, lt; SYSTEMTIME st; ft.dwLowDateTime = (DWORD)t; ft.dwHighDateTime = (DWORD)(t >> 32); FileTimeToLocalFileTime(&ft, &lt); FileTimeToSystemTime(&lt, &st); _snwprintf(out, n, L"%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
static void ft_iso(ULONGLONG t, char *out, int n) { FILETIME ft, lt; SYSTEMTIME st; ft.dwLowDateTime = (DWORD)t; ft.dwHighDateTime = (DWORD)(t >> 32); FileTimeToLocalFileTime(&ft, &lt); FileTimeToSystemTime(&lt, &st); snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
static unsigned conn_hash(int v6, int udp, const BYTE *la, uint16_t lp, const BYTE *ra, uint16_t rp) {
    unsigned h = 2166136261u; int n = v6 ? 16 : 4;
    for (int i = 0; i < n; i++) h = (h ^ la[i]) * 16777619u; for (int i = 0; i < n; i++) h = (h ^ ra[i]) * 16777619u;
    h = (h ^ (lp & 255)) * 16777619u; h = (h ^ (lp >> 8)) * 16777619u; h = (h ^ (rp & 255)) * 16777619u; h = (h ^ (rp >> 8)) * 16777619u; h = (h ^ (unsigned)(v6 | udp << 1)) * 16777619u;
    return h & (CONN_HASH - 1);
}
static int conn_eq(const Conn *c, int v6, int udp, const BYTE *la, uint16_t lp, const BYTE *ra, uint16_t rp) { return c->used && c->v6 == v6 && c->udp == udp && c->lport == lp && c->rport == rp && !memcmp(c->laddr, la, v6 ? 16 : 4) && !memcmp(c->raddr, ra, v6 ? 16 : 4); }
static Conn *conn_find(int v6, int udp, const BYTE *la, uint16_t lp, const BYTE *ra, uint16_t rp) { for (int i = g_chash[conn_hash(v6, udp, la, lp, ra, rp)]; i; i = g_conns[i - 1].hnext) if (conn_eq(&g_conns[i - 1], v6, udp, la, lp, ra, rp)) return &g_conns[i - 1]; return NULL; }
static void conn_unlink(int idx) { Conn *c = &g_conns[idx]; int *pp = &g_chash[conn_hash(c->v6, c->udp, c->laddr, c->lport, c->raddr, c->rport)]; while (*pp) { if (*pp == idx + 1) { *pp = c->hnext; return; } pp = &g_conns[*pp - 1].hnext; } }
static void conn_remove(int idx) { conn_unlink(idx); g_conns[idx].used = 0; }
static void conn_reset(Conn *c, DWORD pid, ULONGLONG now) {   /* same 4-tuple reused by a new connection: keep key + hash link, drop everything else */
    int hn = c->hnext; BYTE la[16], ra[16]; memcpy(la, c->laddr, 16); memcpy(ra, c->raddr, 16); uint16_t lp = c->lport, rp = c->rport; BYTE v6 = c->v6, udp = c->udp, local = c->local;
    memset(c, 0, sizeof *c); c->used = 1; c->pid = pid; c->v6 = v6; c->udp = udp; c->local = local; memcpy(c->laddr, la, 16); memcpy(c->raddr, ra, 16); c->lport = lp; c->rport = rp; c->first_seen = c->last_seen = now; c->hnext = hn;
}
static Conn *conn_get(DWORD pid, int v6, int udp, const BYTE *la, uint16_t lp, const BYTE *ra, uint16_t rp) {   /* under g_lock */
    Conn *c = conn_find(v6, udp, la, lp, ra, rp); ULONGLONG now = GetTickCount64();
    if (c) { if (pid && c->pid != pid) c->pid = pid; c->last_seen = now; return c; }
    static int rover; int slot = -1;
    for (int k = 0; k < MAX_CONNS; k++) { int i = (rover + k) % MAX_CONNS; if (!g_conns[i].used) { slot = i; break; } }
    if (slot < 0) { ULONGLONG oldest = ~0ULL; for (int i = 0; i < MAX_CONNS; i++) { const Conn *x = &g_conns[i]; ULONGLONG age = x->last_seen + ((x->state == 3 || x->state == 4) ? 0 : x->udp ? 300000ULL : 1800000ULL); if (age < oldest) { oldest = age; slot = i; } } if (slot < 0) return NULL; conn_unlink(slot); }
    rover = slot + 1; c = &g_conns[slot]; memset(c, 0, sizeof *c); c->used = 1; c->pid = pid; c->v6 = (BYTE)v6; c->udp = (BYTE)udp; memcpy(c->laddr, la, v6 ? 16 : 4); memcpy(c->raddr, ra, v6 ? 16 : 4); c->lport = lp; c->rport = rp;
    c->local = (BYTE)(v6 ? is_local6(ra) : is_local4(ra)); c->first_seen = c->last_seen = now; c->connect_ms = -1;
    unsigned h = conn_hash(v6, udp, la, lp, ra, rp); c->hnext = g_chash[h]; g_chash[h] = slot + 1; return c;
}
static const char *conn_state_str(const Conn *c) { if (c->udp) return c->quic ? "quic" : "udp"; switch (c->state) { case 1: return "connecting"; case 2: return "established"; case 3: return "closed"; case 4: return "failed"; default: return "active"; } }

/* ------------------------------------------------------------------ timeline ring, zoom interest, watchers ------------------------------------------------------------------ */
static void trace_add(DWORD pid, DWORD ppid, int kind, const wchar_t *detail) {
    EnterCriticalSection(&g_zlock); TraceEv *t = &g_trace[g_trace_head % TRACE_RING]; g_trace_head++; t->t = now_ft(); t->pid = pid; t->ppid = ppid; t->kind = (BYTE)kind;
    size_t L = wcslen(detail); if (L < 120) wcscpy(t->detail, detail); else { t->detail[0] = 0x2026; wcscpy(t->detail + 1, detail + L - 118); }   /* keep the tail: file names live there */
    LeaveCriticalSection(&g_zlock);
}
static const char *trace_kind_str(int k) { static const char *n[] = { "?", "start", "stop", "image", "connect", "established", "closed", "failed", "retransmit", "reconnect", "tls", "dns", "http", "quic", "capture" }; return k >= 0 && k <= 14 ? n[k] : "?"; }
static int trace_find_start(DWORD pid, wchar_t *out, int n) {   /* newest start event for pid (NT image path) */
    int ok = 0; EnterCriticalSection(&g_zlock); unsigned cnt = g_trace_head < TRACE_RING ? g_trace_head : TRACE_RING;
    for (unsigned k = 1; k <= cnt; k++) { const TraceEv *t = &g_trace[(g_trace_head - k) % TRACE_RING]; if (t->kind == 1 && t->pid == pid) { wcsncpy(out, t->detail, n - 1); out[n - 1] = 0; ok = 1; break; } }
    LeaveCriticalSection(&g_zlock); return ok;
}
static int zoom_interested(DWORD pid) { if (g_zoom_all) return 1; int r = 0; EnterCriticalSection(&g_zlock); for (int i = 0; i < g_nzoom; i++) if (g_zoom_pids[i] == pid) { r = 1; break; } LeaveCriticalSection(&g_zlock); return r; }
static void send_watchers(DWORD pid, const char *s, int is_pkt) {   /* is_pkt 0 flow/trace/flowinfo, 1 a frame, 2 a frame whose decode is a handshake (TLS/QUIC hello, DNS, HTTP) */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        int on = 0; EnterCriticalSection(&g_clock); Client *c = &g_clients[i];
        if (c->s != INVALID_SOCKET && c->state == 2) for (int k = 0; k < c->nwatch; k++) if (c->watch[k] == pid || c->watch[k] == 0xFFFFFFFFu) { on = !is_pkt || ((c->watch_pkts == 1 || (c->watch_pkts == 2 && is_pkt == 2)) && c->pkt_budget-- > 0); break; }
        LeaveCriticalSection(&g_clock); if (on) send_line(i, s);
    }
}
static const char *wsa_name(DWORD c) { switch (c) { case 10060: return "timed out"; case 10061: return "refused"; case 10065: return "host unreachable"; case 10051: return "network unreachable"; case 10054: return "reset by peer"; case 10013: return "blocked (permission)"; case 10050: return "network down"; case 10064: return "host down"; default: return ""; } }
static void flow_report(DWORD pid, int kind, int v6, int udp, uint16_t lport, const char *raddr, uint16_t rport, int connect_ms, uint64_t size, uint64_t tx, uint64_t rx) {
    static const char *kn[] = { "", "", "", "", "connect", "established", "closed", "failed", "retransmit", "reconnect" };
    wchar_t host[128] = L""; char hostu[300] = ""; if (host_lookup(raddr, host, 128)) jw(host, hostu, sizeof hostu); else host[0] = 0;
    char js[800], extra[160] = "";
    if (kind == 5 && connect_ms >= 0) snprintf(extra, sizeof extra, ",\"connect_ms\":%d", connect_ms); else if (kind == 8) snprintf(extra, sizeof extra, ",\"bytes\":%llu", (unsigned long long)size); else if (kind == 6) snprintf(extra, sizeof extra, ",\"tx\":%llu,\"rx\":%llu", (unsigned long long)tx, (unsigned long long)rx);
    snprintf(js, sizeof js, "{\"ev\":\"flow\",\"pid\":%lu,\"kind\":\"%s\",\"proto\":\"%s%s\",\"lport\":%u,\"remote\":\"%s\",\"port\":%u,\"host\":\"%s\"%s}", (unsigned long)pid, kn[kind], udp ? "udp" : "tcp", v6 ? "6" : "", lport, raddr, rport, hostu, extra);
    send_watchers(pid, js, 0);
    wchar_t det[120], ex[64] = L"";
    if (kind == 5 && connect_ms >= 0) _snwprintf(ex, 64, L"  in %d ms", connect_ms); else if (kind == 8) { wchar_t b[32]; fmt_bytes_w(size, b, 32); _snwprintf(ex, 64, L"  %ls", b); } else if (kind == 6) { wchar_t a[32], b[32]; fmt_bytes_w(tx, a, 32); fmt_bytes_w(rx, b, 32); _snwprintf(ex, 64, L"  out %ls  in %ls", a, b); }
    _snwprintf(det, 120, L"%ls%ls%hs:%u%ls%ls", host, host[0] ? L"  " : L"", raddr, rport, udp ? L" udp" : L"", ex); trace_add(pid, 0, kind, det);
}
static void net_fail(DWORD pid, int udp, DWORD code) {
    if (pid > 4) { EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) p->fails++; LeaveCriticalSection(&g_lock); }
    wchar_t det[120]; _snwprintf(det, 120, L"%ls connection attempt failed, error %lu %hs", udp ? L"UDP" : L"TCP", (unsigned long)code, wsa_name(code)); trace_add(pid, 0, 7, det);
    if (pid > 4 && zoom_interested(pid)) { char js[256]; snprintf(js, sizeof js, "{\"ev\":\"flow\",\"pid\":%lu,\"kind\":\"failed\",\"proto\":\"%s\",\"error\":%lu,\"text\":\"%s\"}", (unsigned long)pid, udp ? "udp" : "tcp", (unsigned long)code, wsa_name(code)); send_watchers(pid, js, 0); }
}
static void kproc_event(PEVENT_RECORD r) {   /* Microsoft-Windows-Kernel-Process: 1 start, 2 stop (main session), 5 image load (zoom session) */
    USHORT id = r->EventHeader.EventDescriptor.Id; UCHAR ver = r->EventHeader.EventDescriptor.Version; const BYTE *d = (const BYTE *)r->UserData; ULONG n = r->UserDataLength;
    if (id == 1) {
        if (n < 22) return; DWORD pid, ppid; size_t off; memcpy(&pid, d, 4);
        if (ver == 0) { memcpy(&ppid, d + 12, 4); off = 20; } else if (ver <= 2) { memcpy(&ppid, d + 12, 4); off = 24; } else { if (n < 50) return; memcpy(&ppid, d + 20, 4); off = 48; off += 8 + 4 * (size_t)d[off + 1]; }   /* v3+: MandatoryLabel SID precedes ImageName */
        if (off + 2 > n) return; const wchar_t *img = (const wchar_t *)(d + off); size_t maxc = (n - off) / 2, L = 0; while (L < maxc && img[L]) L++; if (L > MAX_PATH - 1) L = MAX_PATH - 1; wchar_t name[MAX_PATH]; wmemcpy(name, img, L); name[L] = 0;
        EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) { if (!p->name[0] || !wcsncmp(p->name, L"pid ", 4)) { wcsncpy(p->name, basename_w(name), 63); p->name[63] = 0; } p->ppid = ppid; } LeaveCriticalSection(&g_lock);
        trace_add(pid, ppid, 1, name);
        if (zoom_interested(ppid) || zoom_interested(pid)) { char nm[700]; jw(name, nm, sizeof nm); char js[900]; snprintf(js, sizeof js, "{\"ev\":\"trace\",\"kind\":\"start\",\"pid\":%lu,\"ppid\":%lu,\"image\":\"%s\"}", (unsigned long)pid, (unsigned long)ppid, nm); send_watchers(ppid, js, 0); if (ppid != pid) send_watchers(pid, js, 0); }
    } else if (id == 2) {
        if (n < 4) return; DWORD pid, code = 0; memcpy(&pid, d, 4); size_t noff = ver == 0 ? 48 : ver == 1 ? 76 : 84;
        if (ver <= 1 && n >= 24) memcpy(&code, d + 20, 4); else if (ver >= 2 && n >= 32) memcpy(&code, d + 28, 4);
        wchar_t nm[64] = L""; if (noff < n) { const char *a = (const char *)(d + noff); size_t L = 0; while (noff + L < n && a[L] && L < 63) L++; for (size_t i = 0; i < L; i++) nm[i] = (wchar_t)(unsigned char)a[i]; nm[L] = 0; }
        EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) { p->dead = 1; if (nm[0] && (!p->name[0] || !wcsncmp(p->name, L"pid ", 4))) wcscpy(p->name, nm); } LeaveCriticalSection(&g_lock);
        wchar_t det[120]; _snwprintf(det, 120, L"%ls%lsexit code %lu", nm, nm[0] ? L"  " : L"", (unsigned long)code); trace_add(pid, 0, 2, det);
        if (zoom_interested(pid)) { char js[200]; snprintf(js, sizeof js, "{\"ev\":\"trace\",\"kind\":\"stop\",\"pid\":%lu,\"exit_code\":%lu}", (unsigned long)pid, (unsigned long)code); send_watchers(pid, js, 0); }
    } else if (id == 5) {
        if (n < 38) return; DWORD pid; memcpy(&pid, d + 16, 4); if (!zoom_interested(pid)) return;
        const wchar_t *img = (const wchar_t *)(d + 36); size_t maxc = (n - 36) / 2, L = 0; while (L < maxc && img[L]) L++; if (L > MAX_PATH - 1) L = MAX_PATH - 1; wchar_t name[MAX_PATH]; wmemcpy(name, img, L); name[L] = 0;
        trace_add(pid, 0, 3, name);
        char nm[700]; jw(name, nm, sizeof nm); char js[900]; snprintf(js, sizeof js, "{\"ev\":\"trace\",\"kind\":\"image\",\"pid\":%lu,\"image\":\"%s\"}", (unsigned long)pid, nm); send_watchers(pid, js, 0);
    }
}
/* ------------------------------------------------------------------ TCP table seeding + TCP ESTATS (RTT, retransmits) ------------------------------------------------------------------ */
static int mib_state_map(DWORD s) { switch (s) { case MIB_TCP_STATE_ESTAB: return 2; case MIB_TCP_STATE_SYN_SENT: case MIB_TCP_STATE_SYN_RCVD: return 1; case MIB_TCP_STATE_LISTEN: return -1; default: return 3; } }
static void conns_seed(DWORD pid) {   /* current TCP table rows of pid -> connection records with real states; established rows that vanished are marked closed */
    static volatile LONG stamp_src; DWORD stamp = (DWORD)InterlockedIncrement(&stamp_src); DWORD sz = 0;
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER && sz) {
        MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) { EnterCriticalSection(&g_lock); for (DWORD i = 0; i < t->dwNumEntries; i++) { const MIB_TCPROW_OWNER_PID *r = &t->table[i]; if (r->dwOwningPid != pid) continue; int st = mib_state_map(r->dwState); if (st < 0 || r->dwRemoteAddr == 0) continue; BYTE la[16] = { 0 }, ra[16] = { 0 }; memcpy(la, &r->dwLocalAddr, 4); memcpy(ra, &r->dwRemoteAddr, 4); Conn *c = conn_get(pid, 0, 0, la, ntohs((uint16_t)r->dwLocalPort), ra, ntohs((uint16_t)r->dwRemotePort)); if (c) { c->stamp = stamp; if (c->state != 4) c->state = (BYTE)st; } } LeaveCriticalSection(&g_lock); }
        free(t);
    }
    sz = 0;
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER && sz) {
        MIB_TCP6TABLE_OWNER_PID *t = (MIB_TCP6TABLE_OWNER_PID *)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) { EnterCriticalSection(&g_lock); for (DWORD i = 0; i < t->dwNumEntries; i++) { const MIB_TCP6ROW_OWNER_PID *r = &t->table[i]; if (r->dwOwningPid != pid) continue; int st = mib_state_map(r->dwState); if (st < 0) continue; Conn *c = conn_get(pid, 1, 0, r->ucLocalAddr, ntohs((uint16_t)r->dwLocalPort), r->ucRemoteAddr, ntohs((uint16_t)r->dwRemotePort)); if (c) { c->stamp = stamp; if (c->state != 4) c->state = (BYTE)st; } } LeaveCriticalSection(&g_lock); }
        free(t);
    }
    EnterCriticalSection(&g_lock); ULONGLONG now = GetTickCount64(); for (int i = 0; i < MAX_CONNS; i++) { Conn *c = &g_conns[i]; if (c->used && c->pid == pid && !c->udp && c->state == 2 && c->stamp != stamp) { c->state = 3; c->t_close = now; c->last_seen = now; } } LeaveCriticalSection(&g_lock);
}
static void estats_refresh(DWORD pid) {   /* enable + read TCP ESTATS path statistics for the established TCP connections of pid (elevated: any process) */
    Conn *snap = (Conn *)malloc(256 * sizeof(Conn)); if (!snap) return; int n = 0;
    EnterCriticalSection(&g_lock); for (int i = 0; i < MAX_CONNS && n < 256; i++) { const Conn *c = &g_conns[i]; if (c->used && c->pid == pid && !c->udp && c->state == 2) snap[n++] = *c; } LeaveCriticalSection(&g_lock);
    for (int k = 0; k < n; k++) {
        Conn *s = &snap[k]; TCP_ESTATS_PATH_RW_v0 rw; rw.EnableCollection = TRUE; TCP_ESTATS_PATH_ROD_v0 rod; memset(&rod, 0, sizeof rod); ULONG rc;
        if (!s->v6) { MIB_TCPROW row; memset(&row, 0, sizeof row); row.dwState = MIB_TCP_STATE_ESTAB; memcpy(&row.dwLocalAddr, s->laddr, 4); row.dwLocalPort = htons(s->lport); memcpy(&row.dwRemoteAddr, s->raddr, 4); row.dwRemotePort = htons(s->rport); if (!s->estats) SetPerTcpConnectionEStats(&row, TcpConnectionEstatsPath, (PUCHAR)&rw, 0, sizeof rw, 0); rc = GetPerTcpConnectionEStats(&row, TcpConnectionEstatsPath, NULL, 0, 0, NULL, 0, 0, (PUCHAR)&rod, 0, sizeof rod); }
        else { MIB_TCP6ROW row; memset(&row, 0, sizeof row); row.State = MIB_TCP_STATE_ESTAB; memcpy(&row.LocalAddr, s->laddr, 16); row.dwLocalPort = htons(s->lport); memcpy(&row.RemoteAddr, s->raddr, 16); row.dwRemotePort = htons(s->rport); if (!s->estats) SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsPath, (PUCHAR)&rw, 0, sizeof rw, 0); rc = GetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsPath, NULL, 0, 0, NULL, 0, 0, (PUCHAR)&rod, 0, sizeof rod); }
        if (rc != NO_ERROR) continue;
        EnterCriticalSection(&g_lock); Conn *c = conn_find(s->v6, 0, s->laddr, s->lport, s->raddr, s->rport);
        if (c && c->pid == pid) { c->estats = 1; c->srtt = rod.SmoothedRtt; c->minrtt = rod.MinRtt; c->maxrtt = rod.MaxRtt; c->rto = rod.CurRto; c->pretrans = rod.PktsRetrans; c->timeouts = rod.Timeouts; c->cong = rod.CongSignals; c->cur_mss = rod.CurMss; c->dupacks = rod.DupAcksIn; }
        LeaveCriticalSection(&g_lock);
    }
    free(snap);
}

/* ------------------------------------------------------------------ process profile (CPU, memory, disk, GPU, identity, signer) ------------------------------------------------------------------ */
typedef struct {
    DWORD pid, ppid; wchar_t name[64], path[MAX_PATH], cmdline[1024], user[160], integrity[16], parent[64], signer[160]; int sig;   /* sig 0 pending, 1 signed+trusted, 2 unsigned, 3 signed but not trusted */
    FILETIME created; int alive, protect, samples;
    ULONGLONG cpu_prev, tick_prev; uint64_t rd_prev, wr_prev; double cpu, rd_bps, wr_bps, gpu; int gpu_ok; SIZE_T ws, priv; DWORD handles, threads, children; uint64_t cpu_ms;
    PDH_HQUERY pq; PDH_HCOUNTER pc; ULONGLONG pq_retry;
} Profile;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } MY_UNICODE_STRING;
typedef LONG (NTAPI *PFN_NtQIP)(HANDLE, int, PVOID, ULONG, PULONG);
typedef PDH_STATUS (WINAPI *PFN_PdhAddEng)(PDH_HQUERY, LPCWSTR, DWORD_PTR, PDH_HCOUNTER *);
static int ncpu(void) { static int n; if (!n) { SYSTEM_INFO si; GetSystemInfo(&si); n = si.dwNumberOfProcessors ? (int)si.dwNumberOfProcessors : 1; } return n; }
static void profile_gpu_open(Profile *pf) {   /* PDH "GPU Engine(pid_N_*)" instances: the same counters Task Manager reads */
    if (!pf->pq && PdhOpenQueryW(NULL, 0, &pf->pq) != ERROR_SUCCESS) { pf->pq = NULL; return; }
    static PFN_PdhAddEng add; static int tried; if (!tried) { tried = 1; HMODULE m = GetModuleHandleW(L"pdh.dll"); if (!m) m = LoadLibraryW(L"pdh.dll"); if (m) add = (PFN_PdhAddEng)GetProcAddress(m, "PdhAddEnglishCounterW"); }
    wchar_t cp[160]; _snwprintf(cp, 160, L"\\GPU Engine(pid_%lu_*)\\Utilization Percentage", (unsigned long)pf->pid);
    PDH_STATUS st = add ? add(pf->pq, cp, 0, &pf->pc) : PdhAddCounterW(pf->pq, cp, 0, &pf->pc);
    if (st == ERROR_SUCCESS) { pf->gpu_ok = 1; PdhCollectQueryData(pf->pq); } else pf->pc = NULL;
}
static void profile_init(Profile *pf, DWORD pid) {
    memset(pf, 0, sizeof *pf); pf->pid = pid; pf->alive = 1;
    if (!pid_path(pid, pf->path, MAX_PATH)) { EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) { wcscpy(pf->path, p->path); wcscpy(pf->name, p->name); } LeaveCriticalSection(&g_lock); }
    if (!pf->name[0]) { wcsncpy(pf->name, pf->path[0] ? basename_w(pf->path) : (pid == 4 ? L"System" : L"?"), 63); pf->name[63] = 0; }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) { pf->protect = GetLastError() == ERROR_ACCESS_DENIED; pf->alive = proc_alive(pid); }
    else {
        FILETIME ct, et, kt, ut; if (GetProcessTimes(h, &ct, &et, &kt, &ut)) pf->created = ct;
        static PFN_NtQIP qip; static int tried; if (!tried) { tried = 1; HMODULE m = GetModuleHandleW(L"ntdll.dll"); if (m) qip = (PFN_NtQIP)GetProcAddress(m, "NtQueryInformationProcess"); }
        if (qip) { ULONG need = 0; qip(h, 60 /* ProcessCommandLineInformation */, NULL, 0, &need); if (need && need < 65536) { BYTE *buf = (BYTE *)malloc(need); if (buf && qip(h, 60, buf, need, &need) == 0) { MY_UNICODE_STRING *us = (MY_UNICODE_STRING *)buf; int L = us->Length / 2; if (L > 1023) L = 1023; if (us->Buffer && L > 0) { wmemcpy(pf->cmdline, us->Buffer, L); pf->cmdline[L] = 0; } } free(buf); } }
        HANDLE tok; if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
            BYTE tb[1024]; DWORD rl;
            if (GetTokenInformation(tok, TokenUser, tb, sizeof tb, &rl)) { wchar_t nm[128], dom[128]; DWORD nl = 128, dl = 128; SID_NAME_USE use; if (LookupAccountSidW(NULL, ((TOKEN_USER *)tb)->User.Sid, nm, &nl, dom, &dl, &use)) _snwprintf(pf->user, 160, L"%ls\\%ls", dom, nm); }
            if (GetTokenInformation(tok, TokenIntegrityLevel, tb, sizeof tb, &rl)) { PSID s = ((TOKEN_MANDATORY_LABEL *)tb)->Label.Sid; DWORD rid = *GetSidSubAuthority(s, *GetSidSubAuthorityCount(s) - 1); wcscpy(pf->integrity, rid >= 0x4000 ? L"system" : rid >= 0x3000 ? L"high" : rid >= 0x2000 ? L"medium" : L"low"); }
            CloseHandle(tok);
        }
        CloseHandle(h);
    }
    pf->ppid = parent_pid(pid); if (!pf->ppid) { EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) pf->ppid = p->ppid; LeaveCriticalSection(&g_lock); }
    wchar_t pp[MAX_PATH]; if (pf->ppid && (pid_path(pf->ppid, pp, MAX_PATH) || trace_find_start(pf->ppid, pp, MAX_PATH))) { wcsncpy(pf->parent, basename_w(pp), 63); pf->parent[63] = 0; }
    profile_gpu_open(pf);
}
static void profile_sample(Profile *pf) {   /* once a second */
    ULONGLONG now = GetTickCount64(); HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pf->pid);
    if (h) {
        FILETIME ct, et, kt, ut;
        if (GetProcessTimes(h, &ct, &et, &kt, &ut)) { ULONGLONG cpu = (((ULONGLONG)kt.dwHighDateTime << 32) | kt.dwLowDateTime) + (((ULONGLONG)ut.dwHighDateTime << 32) | ut.dwLowDateTime); pf->cpu_ms = cpu / 10000; if (pf->tick_prev && now > pf->tick_prev && cpu >= pf->cpu_prev) pf->cpu = (double)(cpu - pf->cpu_prev) / 10000.0 / (double)(now - pf->tick_prev) * 100.0 / ncpu(); pf->cpu_prev = cpu; }
        IO_COUNTERS io; if (GetProcessIoCounters(h, &io)) { if (pf->tick_prev && now > pf->tick_prev) { pf->rd_bps = (double)(io.ReadTransferCount - pf->rd_prev) * 1000.0 / (double)(now - pf->tick_prev); pf->wr_bps = (double)(io.WriteTransferCount - pf->wr_prev) * 1000.0 / (double)(now - pf->tick_prev); } pf->rd_prev = io.ReadTransferCount; pf->wr_prev = io.WriteTransferCount; }
        PROCESS_MEMORY_COUNTERS_EX pm; pm.cb = sizeof pm; if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS *)&pm, sizeof pm)) { pf->ws = pm.WorkingSetSize; pf->priv = pm.PrivateUsage; }
        DWORD hc; if (GetProcessHandleCount(h, &hc)) pf->handles = hc;
        pf->alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT; CloseHandle(h);
    } else pf->alive = proc_alive(pf->pid);
    pf->tick_prev = now; pf->samples++;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s != INVALID_HANDLE_VALUE) { PROCESSENTRY32W e = { sizeof e }; DWORD ch = 0, th = 0; if (Process32FirstW(s, &e)) do { if (e.th32ProcessID == pf->pid) th = e.cntThreads; else if (e.th32ParentProcessID == pf->pid) ch++; } while (Process32NextW(s, &e)); CloseHandle(s); pf->children = ch; pf->threads = th; }
    if (pf->gpu_ok && PdhCollectQueryData(pf->pq) == ERROR_SUCCESS) {
        DWORD bs = 0, cnt = 0; PdhGetFormattedCounterArrayW(pf->pc, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bs, &cnt, NULL);
        if (bs) { PDH_FMT_COUNTERVALUE_ITEM_W *it = (PDH_FMT_COUNTERVALUE_ITEM_W *)malloc(bs); if (it && PdhGetFormattedCounterArrayW(pf->pc, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bs, &cnt, it) == ERROR_SUCCESS) { double mx = 0; for (DWORD i = 0; i < cnt; i++) if ((it[i].FmtValue.CStatus == PDH_CSTATUS_VALID_DATA || it[i].FmtValue.CStatus == PDH_CSTATUS_NEW_DATA) && it[i].FmtValue.doubleValue > mx) mx = it[i].FmtValue.doubleValue; pf->gpu = mx > 100 ? 100 : mx; } free(it); }
    } else if (!pf->gpu_ok && now > pf->pq_retry) { pf->pq_retry = now + 10000; profile_gpu_open(pf); }
}
static void profile_free(Profile *pf) { if (pf->pq) PdhCloseQuery(pf->pq); pf->pq = NULL; pf->pc = NULL; pf->gpu_ok = 0; }
#ifndef WTD_CACHE_ONLY_URL_RETRIEVAL
#define WTD_CACHE_ONLY_URL_RETRIEVAL 0x00001000
#endif
typedef struct { DWORD cbStruct; WCHAR wszCatalogFile[MAX_PATH]; } MY_CATALOG_INFO;
typedef BOOL (WINAPI *PFN_CatAcq2)(HANDLE *, const GUID *, PCWSTR, PVOID, DWORD); typedef BOOL (WINAPI *PFN_CatHash2)(HANDLE, HANDLE, DWORD *, BYTE *, DWORD); typedef HANDLE (WINAPI *PFN_CatEnum)(HANDLE, BYTE *, DWORD, DWORD, HANDLE *);
typedef BOOL (WINAPI *PFN_CatInfo)(HANDLE, MY_CATALOG_INFO *, DWORD); typedef BOOL (WINAPI *PFN_CatRelInfo)(HANDLE, HANDLE, DWORD); typedef BOOL (WINAPI *PFN_CatRel)(HANDLE, DWORD);
static int exe_signer(const wchar_t *path, wchar_t *out, int n) {   /* 1 signed and trusted, 2 unsigned, 3 signed but not trusted; out = publisher (embedded signature or the Windows catalog that covers the file) */
    out[0] = 0; GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi; memset(&fi, 0, sizeof fi); fi.cbStruct = sizeof fi; fi.pcwszFilePath = path;
    WINTRUST_DATA wd; memset(&wd, 0, sizeof wd); wd.cbStruct = sizeof wd; wd.dwUIChoice = WTD_UI_NONE; wd.fdwRevocationChecks = WTD_REVOKE_NONE; wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_VERIFY; wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG st = WinVerifyTrust(NULL, &act, &wd); wd.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(NULL, &act, &wd);
    wchar_t catpath[MAX_PATH] = L""; const wchar_t *sigfile = path;
    if (st == TRUST_E_NOSIGNATURE) {   /* no embedded signature: look the file's hash up in the system catalogs (how Windows' own binaries are signed) */
        HMODULE wt = LoadLibraryW(L"wintrust.dll");
        PFN_CatAcq2 acq = wt ? (PFN_CatAcq2)GetProcAddress(wt, "CryptCATAdminAcquireContext2") : NULL; PFN_CatHash2 hsh = wt ? (PFN_CatHash2)GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2") : NULL; PFN_CatEnum en = wt ? (PFN_CatEnum)GetProcAddress(wt, "CryptCATAdminEnumCatalogFromHash") : NULL;
        PFN_CatInfo inf = wt ? (PFN_CatInfo)GetProcAddress(wt, "CryptCATCatalogInfoFromContext") : NULL; PFN_CatRelInfo reli = wt ? (PFN_CatRelInfo)GetProcAddress(wt, "CryptCATAdminReleaseCatalogContext") : NULL; PFN_CatRel rel = wt ? (PFN_CatRel)GetProcAddress(wt, "CryptCATAdminReleaseContext") : NULL;
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (acq && hsh && en && inf && reli && rel && f != INVALID_HANDLE_VALUE) {
            HANDLE adm = NULL;
            if (acq(&adm, NULL, L"SHA256", NULL, 0)) {
                BYTE hash[64]; DWORD hl = sizeof hash;
                if (hsh(adm, f, &hl, hash, 0)) {
                    HANDLE ci = en(adm, hash, hl, 0, NULL);
                    if (ci) {
                        MY_CATALOG_INFO info; memset(&info, 0, sizeof info); info.cbStruct = sizeof info;
                        if (inf(ci, &info, 0)) {
                            wchar_t tag[132]; for (DWORD i = 0; i < hl && i < 64; i++) _snwprintf(tag + 2 * i, 3, L"%02X", hash[i]); tag[2 * (hl < 64 ? hl : 64)] = 0;
                            WINTRUST_CATALOG_INFO wci; memset(&wci, 0, sizeof wci); wci.cbStruct = sizeof wci; wci.pcwszCatalogFilePath = info.wszCatalogFile; wci.pcwszMemberFilePath = path; wci.pcwszMemberTag = tag; wci.hMemberFile = f; wci.pbCalculatedFileHash = hash; wci.cbCalculatedFileHash = hl;
                            wd.dwUnionChoice = WTD_CHOICE_CATALOG; wd.pCatalog = &wci; wd.dwStateAction = WTD_STATEACTION_VERIFY; st = WinVerifyTrust(NULL, &act, &wd); wd.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(NULL, &act, &wd);
                            wcscpy(catpath, info.wszCatalogFile); sigfile = catpath;
                        }
                        reli(adm, ci, 0);
                    }
                }
                rel(adm, 0);
            }
        }
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    if (st == TRUST_E_NOSIGNATURE) return 2;
    HCERTSTORE store = NULL; HCRYPTMSG msg = NULL; DWORD enc, ct, ft;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, sigfile, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ct, &ft, &store, &msg, NULL)) {
        DWORD sz = 0;
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &sz) && sz) { CMSG_SIGNER_INFO *si = (CMSG_SIGNER_INFO *)malloc(sz); if (si && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz)) { CERT_INFO ci; memset(&ci, 0, sizeof ci); ci.Issuer = si->Issuer; ci.SerialNumber = si->SerialNumber; PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL); if (cert) { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, out, n); CertFreeCertificateContext(cert); } } free(si); }
        if (msg) CryptMsgClose(msg); if (store) CertCloseStore(store, 0);
    }
    return st == ERROR_SUCCESS ? 1 : 3;
}
static int exe_signer_cached(const wchar_t *path, wchar_t *out, int n, char sha[65]) {   /* exe_signer keyed by path + SHA-256 of the file (a changed file is checked again); sha may be NULL */
    char h[65]; out[0] = 0; if (!sha256_file(path, h)) return exe_signer(path, out, n); if (sha) strcpy(sha, h);
    EnterCriticalSection(&g_slock); for (int i = 0; i < g_sigc_n; i++) { SigEnt *e = &g_sigc[i]; if (!_wcsicmp(e->path, path) && !strcmp(e->sha, h)) { wcsncpy(out, e->name, n - 1); out[n - 1] = 0; int sig = e->sig; e->when = GetTickCount64(); LeaveCriticalSection(&g_slock); return sig; } } LeaveCriticalSection(&g_slock);
    int sig = exe_signer(path, out, n);
    EnterCriticalSection(&g_slock); int slot = g_sigc_n < SIG_CACHE ? g_sigc_n++ : 0; if (slot == 0 && g_sigc_n == SIG_CACHE) for (int i = 1; i < SIG_CACHE; i++) if (g_sigc[i].when < g_sigc[slot].when) slot = i;
    SigEnt *e = &g_sigc[slot]; wcsncpy(e->path, path, MAX_PATH - 1); e->path[MAX_PATH - 1] = 0; strcpy(e->sha, h); e->sig = sig; wcsncpy(e->name, out, 159); e->name[159] = 0; e->when = GetTickCount64(); LeaveCriticalSection(&g_slock);
    return sig;
}
typedef struct { HWND h; wchar_t path[MAX_PATH]; } SignerJob;
static DWORD WINAPI signer_thread(LPVOID a) { SignerJob *j = (SignerJob *)a; wchar_t *res = (wchar_t *)calloc(170, sizeof(wchar_t)); res[0] = (wchar_t)exe_signer_cached(j->path, res + 1, 160, NULL); if (!IsWindow(j->h) || !PostMessageW(j->h, WM_SIGNER, 0, (LPARAM)res)) free(res); free(j); return 0; }
static void signer_async(HWND h, const wchar_t *path) { SignerJob *j = (SignerJob *)calloc(1, sizeof *j); j->h = h; wcsncpy(j->path, path, MAX_PATH - 1); HANDLE t = CreateThread(NULL, 0, signer_thread, j, 0, NULL); if (t) CloseHandle(t); else free(j); }

static int kill_pid(DWORD pid, char *err, int n) {
    static const wchar_t *critical[] = { L"csrss.exe", L"wininit.exe", L"winlogon.exe", L"smss.exe", L"lsass.exe", L"services.exe", L"System", L"Registry", L"Secure System", L"Hodometer.exe" };
    if (pid <= 4 || pid == GetCurrentProcessId()) { snprintf(err, n, "refusing to kill pid %lu", (unsigned long)pid); return 0; }
    wchar_t path[MAX_PATH]; pid_path(pid, path, MAX_PATH); const wchar_t *name = basename_w(path);
    for (size_t i = 0; i < sizeof critical / sizeof *critical; i++) if (!_wcsicmp(name, critical[i])) { snprintf(err, n, "refusing to kill critical process %ls", name); return 0; }
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid); if (!h) { snprintf(err, n, "OpenProcess failed (%lu)", GetLastError()); return 0; }
    int ok = TerminateProcess(h, 1); if (!ok) snprintf(err, n, "TerminateProcess failed (%lu)", GetLastError()); CloseHandle(h);
    if (ok) { char e[256]; jw(name, e, sizeof e); char line[512]; snprintf(line, sizeof line, "{\"ev\":\"killed\",\"pid\":%lu,\"name\":\"%s\"}", (unsigned long)pid, e); log_json(line); EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) p->dead = 1; LeaveCriticalSection(&g_lock); }
    return ok;
}
static void blocked_save(void) { FILE *f = _wfopen(g_block_path, L"wb"); if (!f) return; for (int i = 0; i < g_nblocked; i++) { char p[1200]; jw(g_blocked[i].path, p, sizeof p); fprintf(f, "{\"path\":\"%s\",\"since\":\"%s\"}\n", p, g_blocked[i].since); } fclose(f); }
static void rule_name(const wchar_t *path, wchar_t *out, int n) { char u[1200]; to_utf8(path, u, sizeof u); _snwprintf(out, n, L"Hodometer block: %ls [%08x]", basename_w(path), host_hash(u)); }
static int fw_block(const wchar_t *path, int block, char *err, int n) {
    if (!path[0] || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) { snprintf(err, n, "program path not found"); return 0; }
    wchar_t name[320], cmd[1600]; rule_name(path, name, 320); DWORD rc = 0;
    if (block) {
        _snwprintf(cmd, 1600, L"netsh advfirewall firewall add rule name=\"%ls\" dir=out program=\"%ls\" action=block enable=yes", name, path); rc |= run_hidden(cmd);
        _snwprintf(cmd, 1600, L"netsh advfirewall firewall add rule name=\"%ls\" dir=in program=\"%ls\" action=block enable=yes", name, path); rc |= run_hidden(cmd);
    } else { _snwprintf(cmd, 1600, L"netsh advfirewall firewall delete rule name=\"%ls\"", name); rc = run_hidden(cmd); }
    if (rc != 0 && block) { snprintf(err, n, "netsh returned %lu", (unsigned long)rc); return 0; }
    EnterCriticalSection(&g_tlock);
    int idx = -1; for (int i = 0; i < g_nblocked; i++) if (!_wcsicmp(g_blocked[i].path, path)) idx = i;
    if (block && idx < 0 && g_nblocked < MAX_BLOCKED) { wcsncpy(g_blocked[g_nblocked].path, path, MAX_PATH - 1); now_iso(g_blocked[g_nblocked].since, 24); g_nblocked++; }
    if (!block && idx >= 0) { g_blocked[idx] = g_blocked[--g_nblocked]; }
    blocked_save();
    LeaveCriticalSection(&g_tlock);
    EnterCriticalSection(&g_lock); for (int i = 0; i < MAX_PROCS; i++) if (g_procs[i].used && !_wcsicmp(g_procs[i].path, path)) g_procs[i].blocked = block; LeaveCriticalSection(&g_lock);
    char p[1200]; jw(path, p, sizeof p); char line[1400]; snprintf(line, sizeof line, "{\"ev\":\"%s\",\"path\":\"%s\"}", block ? "blocked" : "unblocked", p); log_json(line);
    return 1;
}
static void blocked_load(void) { FILE *f = _wfopen(g_block_path, L"rb"); if (!f) return; char line[2048]; while (fgets(line, sizeof line, f) && g_nblocked < MAX_BLOCKED) { char p[1200]; if (json_get_str(line, "path", p, sizeof p)) { to_wide(p, g_blocked[g_nblocked].path, MAX_PATH); json_get_str(line, "since", g_blocked[g_nblocked].since, 24); g_nblocked++; } } fclose(f); }

/* ------------------------------------------------------------------ ETW consumer ------------------------------------------------------------------ */
/* Microsoft-Windows-Kernel-Network. All transfer/lifecycle events start with PID, size, daddr, saddr, dport, sport (addresses 4 or 16 bytes,
   ports network order); 12/15 (connect attempted / established) continue with mss. daddr:dport is the remote end, saddr:sport the local socket. */
static void CALLBACK on_event(PEVENT_RECORD r) {
    const GUID *pg = &r->EventHeader.ProviderId;
    if (IsEqualGUID(pg, &DnsClientGuid)) { if (r->EventHeader.EventDescriptor.Id == 3008) dns_event((const BYTE *)r->UserData, r->UserDataLength); return; }
    if (IsEqualGUID(pg, &KernelProcessGuid)) { kproc_event(r); return; }
    if (!IsEqualGUID(pg, &KernelNetworkGuid)) return;
    USHORT id = r->EventHeader.EventDescriptor.Id; const BYTE *d = (const BYTE *)r->UserData; ULONG n = r->UserDataLength;
    if (id == 17 || id == 49) { if (n >= 4) { uint16_t code; memcpy(&code, d + 2, 2); net_fail(r->EventHeader.ProcessId, id == 49, code); } return; }   /* Proto, FailureCode: no address, pid from the header */
    int v6 = 0, udp = 0, op = id;
    if (id >= 26 && id <= 34) { v6 = 1; op = id - 16; } else if (id == 58 || id == 59) { v6 = 1; udp = 1; op = id - 16; } else if (id == 42 || id == 43) udp = 1; else if (id < 10 || id > 16) return;
    if (op == 18 || g_paused) return;
    size_t alen = v6 ? 16 : 4; if (n < 12 + 2 * alen) return;
    DWORD pid, size; memcpy(&pid, d, 4); memcpy(&size, d + 4, 4);
    const BYTE *daddr = d + 8, *saddr = d + 8 + alen; uint16_t dport_n, sport_n; memcpy(&dport_n, d + 8 + 2 * alen, 2); memcpy(&sport_n, d + 10 + 2 * alen, 2); uint16_t dport = ntohs(dport_n), sport = ntohs(sport_n);
    if (op == 43) { const BYTE *t = daddr; daddr = saddr; saddr = t; uint16_t tp = dport; dport = sport; sport = tp; }   /* UDP receive events are literal ("from saddr:sport to daddr:dport"): the sender is the remote end */
    uint16_t mss = 0; if ((op == 12 || op == 15) && n >= 14 + 2 * alen) memcpy(&mss, d + 12 + 2 * alen, 2);
    int local = v6 ? is_local6(daddr) : is_local4(daddr), count = !local || g_include_local;
    char addr[48]; addr_str(v6, daddr, addr, sizeof addr);
    ULONGLONG now = GetTickCount64(); int fl = 0, connect_ms = -1; uint64_t ctx = 0, crx = 0;
    EnterCriticalSection(&g_lock);
    Proc *p = proc_get(pid); Conn *c = conn_get(pid, v6, udp, saddr, sport, daddr, dport);
    switch (op) {
    case 10: case 42: if (p && count) { p->tx_total += size; p->tx_win += size; p->tx_min += size; g_tx_total += size; g_tx_win += size; remote_add(p, addr, dport, size, 0); } if (c) { c->tx += size; c->tx_win += size; } break;
    case 11: case 43: if (p && count) { p->rx_total += size; p->rx_win += size; p->rx_min += size; g_rx_total += size; g_rx_win += size; remote_add(p, addr, dport, 0, size); } if (c) { c->rx += size; c->rx_win += size; } break;
    case 12: if (c) { if (c->state >= 3) conn_reset(c, pid, now); c->state = 1; c->t_attempt = now; c->mss = mss; } fl = 4; break;
    case 15: if (c) { if (c->state == 1 && c->t_attempt) connect_ms = (int)(now - c->t_attempt); c->state = 2; c->t_est = now; if (mss) c->mss = mss; c->connect_ms = connect_ms; } fl = 5; break;
    case 13: if (c) { c->state = 3; c->t_close = now; ctx = c->tx; crx = c->rx; } fl = 6; break;
    case 14: if (c) { c->retx += size; c->retx_events++; } if (p) p->retx += size; fl = 8; break;
    case 16: if (c) { c->reconnects++; c->state = 1; c->t_attempt = now; } fl = 9; break;
    }
    LeaveCriticalSection(&g_lock);
    if (fl && zoom_interested(pid)) flow_report(pid, fl, v6, udp, sport, addr, dport, connect_ms, size, ctx, crx);
}
static EVENT_TRACE_PROPERTIES *etw_props(void) { ULONG sz = sizeof(EVENT_TRACE_PROPERTIES) + 2048; EVENT_TRACE_PROPERTIES *p = (EVENT_TRACE_PROPERTIES *)calloc(1, sz); p->Wnode.BufferSize = sz; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID; p->Wnode.ClientContext = 2; /* system time stamps (FILETIME) */ p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); p->BufferSize = 64; p->MinimumBuffers = 8; p->MaximumBuffers = 48; p->FlushTimer = 1; return p; }
static DWORD WINAPI etw_thread(LPVOID a) {
    (void)a; EVENT_TRACE_PROPERTIES *p = etw_props(); TRACEHANDLE h = 0; ULONG rc = StartTraceW(&h, SESSION_NAME, p);
    if (rc == ERROR_ALREADY_EXISTS) { ControlTraceW(0, SESSION_NAME, p, EVENT_TRACE_CONTROL_STOP); free(p); p = etw_props(); rc = StartTraceW(&h, SESSION_NAME, p); }
    if (rc != ERROR_SUCCESS) { g_etw_err = rc; InterlockedExchange(&g_etw_state, -1); free(p); return 0; }
    g_session = h;
    rc = EnableTraceEx2(h, &KernelNetworkGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) { g_etw_err = rc; InterlockedExchange(&g_etw_state, -2); free(p); return 0; }
    EnableTraceEx2(h, &DnsClientGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    EnableTraceEx2(h, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x10 /* WINEVENT_KEYWORD_PROCESS: start/stop only */, 0, 0, NULL);
    EVENT_TRACE_LOGFILEW lf; memset(&lf, 0, sizeof lf); lf.LoggerName = (LPWSTR)SESSION_NAME; lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; lf.EventRecordCallback = on_event;
    TRACEHANDLE th = OpenTraceW(&lf); if (th == (TRACEHANDLE)INVALID_HANDLE_VALUE) { g_etw_err = GetLastError(); InterlockedExchange(&g_etw_state, -3); free(p); return 0; }
    InterlockedExchange(&g_etw_state, 1); ProcessTrace(&th, 1, NULL, NULL); CloseTrace(th); free(p);
    if (!g_quitting) InterlockedExchange(&g_etw_state, -4); return 0;
}
static void etw_stop(void) { if (!g_session) return; EVENT_TRACE_PROPERTIES *p = etw_props(); ControlTraceW(g_session, NULL, p, EVENT_TRACE_CONTROL_STOP); free(p); g_session = 0; }

/* ------------------------------------------------------------------ zoom: raw frames from ndiscap.sys, decoded per connection ------------------------------------------------------------------
   A second real-time session enables Microsoft-Windows-NDIS-PacketCapture (event 1001 = one frame or fragment) and Kernel-Process image loads
   while at least one process is being inspected, watched or captured. Frames carry no PID; they are attributed by matching the 5-tuple against
   the connection table that the Kernel-Network events maintain. Only matched frames of interesting processes are kept. */
typedef struct { int v6, udp, ok; BYTE src[16], dst[16]; uint16_t sport, dport; BYTE tcpflags; const BYTE *payload; int plen; } PktInfo;
typedef struct { int kind; /* 0 none, 10 tls, 11 dns, 12 http, 13 quic */ char info[112], sni[96], alpn[24], http[96]; uint16_t tls_ver; int tls_server; uint32_t quic_ver; int nlearn; struct { char ip[48]; wchar_t name[128]; } learn[4]; } Decoded;
typedef struct { int used, kind; /* 1 TLS record stream (TCP), 2 QUIC CRYPTO stream */ int conn; ULONGLONG t; uint32_t have, need; BYTE buf[REASM_MAX], got[REASM_MAX / 8]; } Reasm;
static Reasm g_reasm[REASM_SLOTS];   /* zoom thread only */
static void reasm_put(Reasm *r, uint32_t off, const BYTE *d, uint32_t n) {   /* byte-range reassembly: Chrome scatters the QUIC ClientHello over many out-of-order CRYPTO fragments */
    if (off >= REASM_MAX) return; if (off + n > REASM_MAX) n = REASM_MAX - off; memcpy(r->buf + off, d, n); for (uint32_t i = off; i < off + n; i++) r->got[i >> 3] |= (BYTE)(1 << (i & 7));
    while (r->have < REASM_MAX && (r->got[r->have >> 3] & (1 << (r->have & 7)))) r->have++;   /* have = contiguous bytes from 0 */
}
static DWORD g_insp_pids[MAX_INSPECT];
static int parse_frame(const BYTE *f, int n, int raw_ip, PktInfo *pi) {
    memset(pi, 0, sizeof *pi); int off = 0, proto;
    if (!raw_ip) { if (n < 14) return 0; unsigned et = f[12] << 8 | f[13]; off = 14; if (et == 0x8100 || et == 0x88A8) { if (n < 18) return 0; et = f[16] << 8 | f[17]; off = 18; } if (et != 0x0800 && et != 0x86DD) return 0; }
    if (off >= n) return 0; int ver = f[off] >> 4;
    if (ver == 4) { if (off + 20 > n) return 0; int ihl = (f[off] & 15) * 4; if (ihl < 20 || off + ihl > n) return 0; int tot = f[off + 2] << 8 | f[off + 3]; if ((f[off + 6] << 8 | f[off + 7]) & 0x1FFF) return 0; proto = f[off + 9]; memcpy(pi->src, f + off + 12, 4); memcpy(pi->dst, f + off + 16, 4); int end = off + tot; if (tot < ihl || end > n) end = n; /* LSO/RSC frames may carry 0 or pre-segmentation lengths */ off += ihl; n = end; }
    else if (ver == 6) { pi->v6 = 1; if (off + 40 > n) return 0; int pl = f[off + 4] << 8 | f[off + 5]; proto = f[off + 6]; memcpy(pi->src, f + off + 8, 16); memcpy(pi->dst, f + off + 24, 16); int end = off + 40 + pl; if (pl == 0 || end > n) end = n; off += 40; n = end; for (int hops = 0; hops < 4 && (proto == 0 || proto == 43 || proto == 60); hops++) { if (off + 8 > n) return 0; int next = f[off], hl = (f[off + 1] + 1) * 8; proto = next; off += hl; } if (proto == 44) return 0; }
    else return 0;
    if (proto == 6) { if (off + 20 > n) return 0; pi->sport = (uint16_t)(f[off] << 8 | f[off + 1]); pi->dport = (uint16_t)(f[off + 2] << 8 | f[off + 3]); int doff = (f[off + 12] >> 4) * 4; if (doff < 20 || off + doff > n) return 0; pi->tcpflags = f[off + 13]; pi->payload = f + off + doff; pi->plen = n - off - doff; pi->ok = 1; }
    else if (proto == 17) { if (off + 8 > n) return 0; pi->udp = 1; pi->sport = (uint16_t)(f[off] << 8 | f[off + 1]); pi->dport = (uint16_t)(f[off + 2] << 8 | f[off + 3]); pi->payload = f + off + 8; pi->plen = n - off - 8; pi->ok = 1; }
    return pi->ok;
}
static void sanitize(char *s) { for (; *s; s++) if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e) *s = '?'; }
static void tcp_flags_str(BYTE f, char *out, int n) { static const char *names[] = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" }; out[0] = 0; for (int i = 0; i < 8; i++) if (f & (1 << i)) { if (out[0]) strncat(out, ",", n - strlen(out) - 1); strncat(out, names[i], n - strlen(out) - 1); } }
static const char *tls_ver_str(uint16_t v) { switch (v) { case 0x0304: return "1.3"; case 0x0303: return "1.2"; case 0x0302: return "1.1"; case 0x0301: return "1.0"; default: return "?"; } }
static int tls_hello_parse(const BYTE *p, int n, Decoded *d) {   /* one TLS handshake message: ClientHello (SNI, ALPN, supported_versions) or ServerHello (negotiated version) */
    if (n < 4) return 0; int ht = p[0]; if (ht != 1 && ht != 2) return 0; int hl = p[1] << 16 | p[2] << 8 | p[3]; int end = 4 + hl < n ? 4 + hl : n, off = 4;
    if (off + 35 > end) return 0; uint16_t legacy = (uint16_t)(p[off] << 8 | p[off + 1]); off += 34; int sl = p[off++]; off += sl;
    if (ht == 1) { if (off + 2 > end) return 0; int cl = p[off] << 8 | p[off + 1]; off += 2 + cl; if (off + 1 > end) return 0; off += 1 + p[off]; } else off += 3;
    d->tls_ver = legacy; d->tls_server = ht == 2; d->kind = 10;
    if (off + 2 > end) return 1; int el = p[off] << 8 | p[off + 1]; off += 2; int eend = off + el < end ? off + el : end;
    while (off + 4 <= eend) {
        int et = p[off] << 8 | p[off + 1], len = p[off + 2] << 8 | p[off + 3]; off += 4; if (off + len > eend) break; const BYTE *e = p + off;
        if (et == 0 && ht == 1 && len >= 5 && e[2] == 0) { int nl = e[3] << 8 | e[4]; if (nl > len - 5) nl = len - 5; if (nl > (int)sizeof d->sni - 1) nl = (int)sizeof d->sni - 1; memcpy(d->sni, e + 5, nl); d->sni[nl] = 0; sanitize(d->sni); }
        else if (et == 16 && len >= 3) { int ll = e[0] << 8 | e[1], o = 2, w = 0; if (ll > len - 2) ll = len - 2; while (o < 2 + ll) { int pl = e[o++]; if (o + pl > 2 + ll) break; if (w && w < (int)sizeof d->alpn - 1) d->alpn[w++] = ','; for (int k = 0; k < pl && w < (int)sizeof d->alpn - 1; k++) d->alpn[w++] = (char)e[o + k]; o += pl; } d->alpn[w] = 0; sanitize(d->alpn); }
        else if (et == 43) { if (ht == 2 && len >= 2) d->tls_ver = (uint16_t)(e[0] << 8 | e[1]); else if (ht == 1 && len >= 3) { int vl = e[0]; for (int k = 0; k + 1 < vl && 2 + k < len; k += 2) if (e[1 + k] == 3 && e[2 + k] == 4) d->tls_ver = 0x0304; } }
        off += len;
    }
    return 1;
}
static void hello_info(Decoded *d, const char *pfx) { snprintf(d->info, sizeof d->info, "%s%s ClientHello%s%s%s%s", pfx, tls_ver_str(d->tls_ver), d->sni[0] ? "  SNI=" : "", d->sni, d->alpn[0] ? "  ALPN=" : "", d->alpn); }
static int http_request(const BYTE *p, int n, Decoded *d) {
    static const char *m[] = { "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT " }; int ok = 0; for (int i = 0; i < 8; i++) if (n > (int)strlen(m[i]) && !memcmp(p, m[i], strlen(m[i]))) ok = 1; if (!ok) return 0;
    char line[160]; int L = 0; while (L < n && L < 159 && p[L] != '\r' && p[L] != '\n') { line[L] = (char)p[L]; L++; } line[L] = 0; sanitize(line); char *sp = strrchr(line, ' '); if (sp && !strncmp(sp + 1, "HTTP/", 5)) *sp = 0;
    char host[128] = ""; for (int i = 0; i + 8 < n && i < 2048; i++) if (p[i] == '\n' && !_strnicmp((const char *)p + i + 1, "Host:", 5)) { int j = i + 6; while (j < n && p[j] == ' ') j++; int k = 0; while (j < n && p[j] != '\r' && p[j] != '\n' && k < 127) host[k++] = (char)p[j++]; host[k] = 0; sanitize(host); break; }
    d->kind = 12; snprintf(d->info, sizeof d->info, "HTTP %s%s%s", line, host[0] ? "  Host: " : "", host); snprintf(d->http, sizeof d->http, "%s%s%s", host, host[0] ? " " : "", line); return 1;
}
static const char *dns_type(int t) { switch (t) { case 1: return "A"; case 28: return "AAAA"; case 5: return "CNAME"; case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT"; case 33: return "SRV"; case 65: return "HTTPS"; case 2: return "NS"; case 6: return "SOA"; default: return "?"; } }
static int dns_name(const BYTE *p, int n, int off, char *out, int on) {   /* label sequence with compression pointers; returns the offset after the name in the original stream, -1 on error */
    int o = 0, jumped = 0, ret = -1, hops = 0;
    while (off < n && hops < 32) { int l = p[off]; if (l == 0) { off++; break; } if ((l & 0xC0) == 0xC0) { if (off + 1 >= n) return -1; int ptr = ((l & 0x3F) << 8) | p[off + 1]; if (!jumped) ret = off + 2; jumped = 1; off = ptr; hops++; continue; } off++; if (off + l > n) return -1; if (o && o < on - 1) out[o++] = '.'; for (int i = 0; i < l && o < on - 1; i++) { char ch = (char)p[off + i]; out[o++] = (ch >= 0x20 && ch < 0x7f) ? ch : '?'; } off += l; }
    out[o] = 0; return jumped ? ret : off;
}
static void dns_decode(const BYTE *p, int n, Decoded *d) {
    if (n < 12) return; int qr = p[2] & 0x80, qd = p[4] << 8 | p[5], an = p[6] << 8 | p[7], off = 12, qtype = 0; char q[200] = "";
    if (qd >= 1) { off = dns_name(p, n, off, q, sizeof q); if (off < 0 || off + 4 > n) return; qtype = p[off] << 8 | p[off + 1]; off += 4; for (int i = 1; i < qd; i++) { char t[8]; off = dns_name(p, n, off, t, sizeof t); if (off < 0) return; off += 4; } }
    d->kind = 11;
    if (!qr) { snprintf(d->info, sizeof d->info, "DNS query %s %s", dns_type(qtype), q); return; }
    char first[48] = ""; int nans = 0;
    for (int i = 0; i < an && off >= 0 && off < n; i++) { char t[8]; off = dns_name(p, n, off, t, sizeof t); if (off < 0 || off + 10 > n) break; int ty = p[off] << 8 | p[off + 1], rdl = p[off + 8] << 8 | p[off + 9]; off += 10; if (off + rdl > n) break; if ((ty == 1 && rdl == 4) || (ty == 28 && rdl == 16)) { char ip[48]; addr_str(ty == 28, p + off, ip, sizeof ip); if (!first[0]) strcpy(first, ip); if (d->nlearn < 4 && q[0]) { strcpy(d->learn[d->nlearn].ip, ip); to_wide(q, d->learn[d->nlearn].name, 128); d->nlearn++; } nans++; } off += rdl; }
    if (nans) snprintf(d->info, sizeof d->info, "DNS answer %s -> %s%s", q, first, nans > 1 ? " (+more)" : ""); else snprintf(d->info, sizeof d->info, "DNS response %s %s (%d answers, rcode %d)", dns_type(qtype), q, an, p[3] & 15);
}
/* QUIC v1 client Initial packets are protected with keys derived only from the destination connection id (RFC 9001 5.2), so the ClientHello
   inside them can be read from the wire: HKDF-SHA256 for the keys, AES-128-ECB for header protection, AES-128-GCM for the payload. */
static int zoom_crypto_init(void) {
    static int done, ok; if (done) return ok; done = 1;
    if (BCryptOpenAlgorithmProvider(&g_alg_hmac, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) return 0;
    if (BCryptOpenAlgorithmProvider(&g_alg_ecb, BCRYPT_AES_ALGORITHM, NULL, 0) || BCryptSetProperty(g_alg_ecb, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof BCRYPT_CHAIN_MODE_ECB, 0)) return 0;
    if (BCryptOpenAlgorithmProvider(&g_alg_gcm, BCRYPT_AES_ALGORITHM, NULL, 0) || BCryptSetProperty(g_alg_gcm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof BCRYPT_CHAIN_MODE_GCM, 0)) return 0;
    ok = 1; return 1;
}
static int hmac_sha256(const BYTE *key, int kl, const BYTE *d1, int l1, const BYTE *d2, int l2, BYTE out[32]) { BCRYPT_HASH_HANDLE hh; if (BCryptCreateHash(g_alg_hmac, &hh, NULL, 0, (PUCHAR)key, kl, 0)) return 0; if (l1) BCryptHashData(hh, (PUCHAR)d1, l1, 0); if (l2) BCryptHashData(hh, (PUCHAR)d2, l2, 0); int ok = BCryptFinishHash(hh, out, 32, 0) == 0; BCryptDestroyHash(hh); return ok; }
static int hkdf_expand_label(const BYTE *secret, const char *label, int L, BYTE *out) {   /* TLS 1.3 HKDF-Expand-Label, empty context, L <= 32 */
    BYTE info[80]; int n = 0, ll = (int)strlen(label); info[n++] = (BYTE)(L >> 8); info[n++] = (BYTE)L; info[n++] = (BYTE)(6 + ll); memcpy(info + n, "tls13 ", 6); n += 6; memcpy(info + n, label, ll); n += ll; info[n++] = 0; BYTE one = 1, t[32];
    if (!hmac_sha256(secret, 32, info, n, &one, 1, t)) return 0; memcpy(out, t, L); return 1;
}
static int quic_initial_keys(const BYTE *dcid, int dl, BYTE key[16], BYTE iv[12], BYTE hp[16]) {
    static const BYTE salt[20] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a }; BYTE initial[32], client[32];
    if (!hmac_sha256(salt, 20, dcid, dl, NULL, 0, initial)) return 0;
    return hkdf_expand_label(initial, "client in", 32, client) && hkdf_expand_label(client, "quic key", 16, key) && hkdf_expand_label(client, "quic iv", 12, iv) && hkdf_expand_label(client, "quic hp", 16, hp);
}
static int aes_ecb_block(const BYTE key[16], const BYTE in[16], BYTE out[16]) { BCRYPT_KEY_HANDLE k; if (BCryptGenerateSymmetricKey(g_alg_ecb, &k, NULL, 0, (PUCHAR)key, 16, 0)) return 0; ULONG r; int ok = BCryptEncrypt(k, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &r, 0) == 0; BCryptDestroyKey(k); return ok; }
static int aes_gcm_decrypt(const BYTE key[16], const BYTE nonce[12], const BYTE *aad, int aadl, const BYTE *ct, int ctl, BYTE *out) {   /* ct includes the 16-byte tag; returns plaintext length or -1 */
    if (ctl < 16) return -1; BCRYPT_KEY_HANDLE k; if (BCryptGenerateSymmetricKey(g_alg_gcm, &k, NULL, 0, (PUCHAR)key, 16, 0)) return -1;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; memset(&ai, 0, sizeof ai); ai.cbSize = sizeof ai; ai.dwInfoVersion = 1; ai.pbNonce = (PUCHAR)nonce; ai.cbNonce = 12; ai.pbAuthData = (PUCHAR)aad; ai.cbAuthData = aadl; ai.pbTag = (PUCHAR)(ct + ctl - 16); ai.cbTag = 16;
    ULONG r = 0; NTSTATUS st = BCryptDecrypt(k, (PUCHAR)ct, ctl - 16, &ai, NULL, 0, out, ctl - 16, &r, 0); BCryptDestroyKey(k); return st == 0 ? (int)r : -1;
}
static int quic_varint(const BYTE *p, int n, int *off, uint64_t *v) { if (*off >= n) return 0; int l = 1 << (p[*off] >> 6); if (*off + l > n) return 0; uint64_t x = p[*off] & 0x3F; for (int i = 1; i < l; i++) x = (x << 8) | p[*off + i]; *off += l; *v = x; return 1; }
static int quic_initial_crypto(const BYTE *p, int n, Reasm *r, int *consumed) {   /* decrypt one client Initial (v1) and append its CRYPTO frames to the stream r; returns 1 if the packet decrypted */
    if (n < 7 || !(p[0] & 0x80) || ((p[0] >> 4) & 3) != 0) return 0; if (((uint32_t)p[1] << 24 | p[2] << 16 | p[3] << 8 | p[4]) != 1) return 0;
    int off = 5, dcl = p[off++]; if (dcl > 20 || off + dcl > n) return 0; const BYTE *dcid = p + off; off += dcl; if (off >= n) return 0; int scl = p[off++]; if (off + scl > n) return 0; off += scl;
    uint64_t tl, len; if (!quic_varint(p, n, &off, &tl) || off + tl > (uint64_t)n) return 0; off += (int)tl; if (!quic_varint(p, n, &off, &len)) return 0; int pn_off = off; if (len < 20 || pn_off + len > (uint64_t)n || pn_off + 4 > 480) return 0; int end = pn_off + (int)len; *consumed = end;
    BYTE key[16], iv[12], hp[16], mask[16]; if (!quic_initial_keys(dcid, dcl, key, iv, hp) || !aes_ecb_block(hp, p + pn_off + 4, mask)) return 0;
    BYTE hdr[512]; memcpy(hdr, p, pn_off + 4); hdr[0] ^= mask[0] & 0x0F; int pnl = (hdr[0] & 3) + 1; uint32_t pn = 0; for (int i = 0; i < pnl; i++) { hdr[pn_off + i] ^= mask[1 + i]; pn = (pn << 8) | hdr[pn_off + i]; } int hl = pn_off + pnl;
    BYTE nonce[12]; memcpy(nonce, iv, 12); for (int i = 0; i < 4; i++) nonce[11 - i] ^= (BYTE)(pn >> (8 * i));
    static BYTE plain[2048]; int cl = end - hl; if (cl - 16 > (int)sizeof plain) return 0; int pl = aes_gcm_decrypt(key, nonce, hdr, hl, p + hl, cl, plain); if (pl <= 0) return 0;
    int o = 0;
    while (o < pl) {
        uint64_t ft; if (!quic_varint(plain, pl, &o, &ft)) break;
        if (ft == 0 || ft == 1) continue;
        if (ft == 2 || ft == 3) { uint64_t la, dl, rc, fr; if (!quic_varint(plain, pl, &o, &la) || !quic_varint(plain, pl, &o, &dl) || !quic_varint(plain, pl, &o, &rc) || !quic_varint(plain, pl, &o, &fr)) break; int bad = 0; for (uint64_t i = 0; i < rc && !bad; i++) { uint64_t g, l2; if (!quic_varint(plain, pl, &o, &g) || !quic_varint(plain, pl, &o, &l2)) bad = 1; } if (bad) break; if (ft == 3) { uint64_t e1, e2, e3; if (!quic_varint(plain, pl, &o, &e1) || !quic_varint(plain, pl, &o, &e2) || !quic_varint(plain, pl, &o, &e3)) break; } continue; }
        if (ft == 6) { uint64_t coff, clen; if (!quic_varint(plain, pl, &o, &coff) || !quic_varint(plain, pl, &o, &clen) || o + clen > (uint64_t)pl) break; if (coff < REASM_MAX) reasm_put(r, (uint32_t)coff, plain + o, (uint32_t)clen); o += (int)clen; continue; }
        break;   /* CONNECTION_CLOSE or anything else: nothing more for us */
    }
    return 1;
}
static Reasm *reasm_find(int conn, int kind) { for (int i = 0; i < REASM_SLOTS; i++) if (g_reasm[i].used && g_reasm[i].conn == conn && g_reasm[i].kind == kind) return &g_reasm[i]; return NULL; }
static Reasm *reasm_alloc(int conn, int kind) { ULONGLONG now = GetTickCount64(); for (int i = 0; i < REASM_SLOTS; i++) { Reasm *r = &g_reasm[i]; if (!r->used || now - r->t > 5000) { memset(r, 0, sizeof *r); r->used = 1; r->conn = conn; r->kind = kind; r->t = now; return r; } } return NULL; }
static void decode_tcp(int ci, int had_hello, const PktInfo *pi, int out, Decoded *d) {
    const BYTE *p = pi->payload; int n = pi->plen; char fl[48]; tcp_flags_str(pi->tcpflags, fl, sizeof fl);
    if (n <= 0) { snprintf(d->info, sizeof d->info, "%s", fl); return; }
    if (out) {
        Reasm *r = reasm_find(ci, 1);
        if (r) { reasm_put(r, r->have, p, (uint32_t)n); r->t = GetTickCount64();
            if (r->have >= r->need) { tls_hello_parse(r->buf + 5, (int)r->need - 5, d); r->used = 0; if (d->kind == 10) { hello_info(d, "TLS "); strncat(d->info, "  (reassembled)", sizeof d->info - strlen(d->info) - 1); return; } } else if (r->have >= REASM_MAX) r->used = 0;
            snprintf(d->info, sizeof d->info, "%s  TLS ClientHello continues (%d B)", fl, n); return; }
        if (!had_hello && n >= 9 && p[0] == 0x16 && p[1] == 3 && p[5] == 1) {
            uint32_t need = 5 + (uint32_t)(p[3] << 8 | p[4]);
            if ((int)need <= n) { if (tls_hello_parse(p + 5, (int)need - 5, d)) { hello_info(d, "TLS "); return; } }
            else if ((r = reasm_alloc(ci, 1)) != NULL) { r->need = need; reasm_put(r, 0, p, (uint32_t)n); snprintf(d->info, sizeof d->info, "%s  TLS ClientHello %d of %u B", fl, n, need); return; }
        }
        if (http_request(p, n, d)) return;
    } else {
        if (n >= 9 && p[0] == 0x16 && p[1] == 3 && p[5] == 2) { int rl = p[3] << 8 | p[4]; if (rl > n - 5) rl = n - 5; if (tls_hello_parse(p + 5, rl, d)) { snprintf(d->info, sizeof d->info, "TLS %s ServerHello", tls_ver_str(d->tls_ver)); return; } }
        if (n >= 8 && !memcmp(p, "HTTP/1.", 7)) { char line[100]; int L = 0; while (L < n && L < 99 && p[L] != '\r' && p[L] != '\n') { line[L] = (char)p[L]; L++; } line[L] = 0; sanitize(line); d->kind = 12; snprintf(d->info, sizeof d->info, "%s", line); return; }
    }
    if (p[0] == 0x17 && p[1] == 3) snprintf(d->info, sizeof d->info, "%s  TLS data %d B", fl, n); else if (p[0] == 0x16 && p[1] == 3) snprintf(d->info, sizeof d->info, "%s  TLS handshake %d B", fl, n); else if (p[0] == 0x14 && p[1] == 3) snprintf(d->info, sizeof d->info, "%s  TLS change cipher spec", fl); else if (p[0] == 0x15 && p[1] == 3) snprintf(d->info, sizeof d->info, "%s  TLS alert", fl); else snprintf(d->info, sizeof d->info, "%s  %d B", fl, n);
}
static void decode_udp(int ci, int quic, const PktInfo *pi, int out, Decoded *d) {
    const BYTE *p = pi->payload; int n = pi->plen;
    if (pi->sport == 53 || pi->dport == 53 || pi->sport == 5353 || pi->dport == 5353) { dns_decode(p, n, d); if (!d->info[0]) snprintf(d->info, sizeof d->info, "DNS %d B", n); return; }
    if (n >= 5 && (p[0] & 0x80)) {
        uint32_t ver = (uint32_t)p[1] << 24 | p[2] << 16 | p[3] << 8 | p[4]; d->kind = 13; d->quic_ver = ver;
        if (ver == 0) { snprintf(d->info, sizeof d->info, "QUIC version negotiation"); return; }
        int t = (p[0] >> 4) & 3; const char *tn = ver == 1 ? (t == 0 ? "Initial" : t == 1 ? "0-RTT" : t == 2 ? "Handshake" : "Retry") : ver == 0x6b3343cf ? (t == 1 ? "Initial" : t == 2 ? "0-RTT" : t == 3 ? "Handshake" : "Retry") : "long header";
        const char *vn = ver == 1 ? "v1" : ver == 0x6b3343cf ? "v2" : (ver & 0x0F0F0F0F) == 0x0A0A0A0A ? "grease" : "draft";
        if (ver == 1 && t == 0 && out && zoom_crypto_init()) {
            Reasm *r = reasm_find(ci, 2); if (!r) r = reasm_alloc(ci, 2);
            int off = 0, any = 0; while (r && off < n && (p[off] & 0x80)) { int used = 0; if (!quic_initial_crypto(p + off, n - off, r, &used) || used <= 0) break; off += used; any = 1; }
            if (r && any) { r->t = GetTickCount64(); if (r->have >= 4) { uint32_t need = 4 + ((uint32_t)r->buf[1] << 16 | r->buf[2] << 8 | r->buf[3]); if (r->have >= need && need <= REASM_MAX) { tls_hello_parse(r->buf, (int)need, d); d->kind = 13; d->quic_ver = ver; r->used = 0; hello_info(d, "QUIC Initial v1  TLS "); return; } } snprintf(d->info, sizeof d->info, "QUIC Initial v1  ClientHello fragment (%u B contiguous so far)", r->have); return; }
        }
        snprintf(d->info, sizeof d->info, "QUIC %s %s  %d B", tn, vn, n); return;
    }
    if (quic || (n >= 20 && (p[0] & 0xC0) == 0x40)) { snprintf(d->info, sizeof d->info, "QUIC 1-RTT  %d B", n); return; }
    snprintf(d->info, sizeof d->info, "UDP %d B", n);
}
/* pcapng: one section, one Ethernet interface; frames captured without a link header get a synthetic one so Wireshark opens them */
static void pcap_header(FILE *f) { uint32_t shb[7] = { 0x0A0D0D0A, 28, 0x1A2B3C4D, 0x00010000, 0xFFFFFFFF, 0xFFFFFFFF, 28 }; fwrite(shb, 4, 7, f); uint32_t idb[5] = { 1, 20, 1, 0x40000, 20 }; fwrite(idb, 4, 5, f); }
static void pcap_packet(FILE *f, ULONGLONG ft, const BYTE *data, int n, int raw_ip, int v6) {
    uint64_t us = (ft - 116444736000000000ULL) / 10; int extra = raw_ip ? 14 : 0, cap = n + extra, pad = (4 - cap % 4) % 4; uint32_t len = 32 + cap + pad;
    uint32_t hdr[7] = { 6, len, 0, (uint32_t)(us >> 32), (uint32_t)us, (uint32_t)cap, (uint32_t)cap }; fwrite(hdr, 4, 7, f);
    if (raw_ip) { BYTE eth[14] = { 0 }; eth[12] = v6 ? 0x86 : 0x08; eth[13] = v6 ? 0xDD : 0x00; fwrite(eth, 1, 14, f); }
    fwrite(data, 1, n, f); static const BYTE z[4]; fwrite(z, 1, pad, f); fwrite(&len, 4, 1, f);
}
/* Up to MAX_CAPS captures run at once, one per pid (pid 0 = every process the zoom is interested in); starting one for a pid that is already
   being captured replaces that capture. The file is closed under g_zlock; the 'capture' event goes out after unlocking (cap_announce). */
static int cap_close_locked(int k, CapDone *d) {   /* under g_zlock; returns 1 and fills d */
    Cap *c = &g_caps[k]; if (!c->f) return 0; fclose(c->f); c->f = NULL; wcscpy(d->path, c->path); d->pid = c->pid; d->pkts = c->pkts; d->bytes = c->bytes; g_cap_last = *d; return 1;
}
static int cap_active_locked(void) { int n = 0; for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f) n++; return n; }
static int cap_for_pid_locked(DWORD pid) { for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f && g_caps[k].pid == pid) return k; return -1; }
static void cap_announce(const CapDone *d) {
    int left; EnterCriticalSection(&g_zlock); left = cap_active_locked(); LeaveCriticalSection(&g_zlock);
    char p[1200]; jw(d->path, p, sizeof p); char js[1500];
    snprintf(js, sizeof js, "{\"ev\":\"capture\",\"ok\":true,\"path\":\"%s\",\"pid\":%lu,\"packets\":%llu,\"bytes\":%llu,\"active\":%d}", p, (unsigned long)d->pid, (unsigned long long)d->pkts, (unsigned long long)d->bytes, left);
    bcast(js); log_json(js); wchar_t det[120]; _snwprintf(det, 120, L"pcapng saved: %ls  (%I64u packets)", basename_w(d->path), (unsigned long long)d->pkts); trace_add(d->pid, 0, 14, det); zoom_recalc();
}
static int cap_start(DWORD pid, int seconds, const wchar_t *path, char *err, int n) {
    if (seconds <= 0) seconds = 30; if (seconds > 3600) seconds = 3600; CapDone old; int had = 0;
    EnterCriticalSection(&g_zlock); int slot = cap_for_pid_locked(pid); if (slot >= 0) had = cap_close_locked(slot, &old); else for (int k = 0; k < MAX_CAPS; k++) if (!g_caps[k].f) { slot = k; break; }
    if (slot < 0) { LeaveCriticalSection(&g_zlock); snprintf(err, n, "%d captures already running (capture stop <pid> ends one)", MAX_CAPS); return 0; }
    FILE *f = _wfopen(path, L"wb"); if (!f) { LeaveCriticalSection(&g_zlock); if (had) cap_announce(&old); snprintf(err, n, "cannot create %ls", path); return 0; }
    Cap *c = &g_caps[slot]; pcap_header(f); c->f = f; c->pid = pid; c->started = now_ft(); c->until = c->started + (ULONGLONG)seconds * 10000000ULL; c->pkts = c->bytes = 0; wcsncpy(c->path, path, MAX_PATH - 1); c->path[MAX_PATH - 1] = 0;
    LeaveCriticalSection(&g_zlock); if (had) cap_announce(&old); zoom_recalc(); return 1;
}
static int cap_stop(DWORD pid, int all) {   /* ends the capture of pid, or every capture; returns how many ended */
    CapDone done[MAX_CAPS]; int nd = 0; EnterCriticalSection(&g_zlock); for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f && (all || g_caps[k].pid == pid)) nd += cap_close_locked(k, &done[nd]); LeaveCriticalSection(&g_zlock);
    for (int k = 0; k < nd; k++) cap_announce(&done[k]); return nd;
}
static void cap_expire(void) {   /* once a second: close captures whose time is up even when no frame of theirs arrives */
    CapDone done[MAX_CAPS]; int nd = 0; ULONGLONG now = now_ft(); EnterCriticalSection(&g_zlock); for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f && now > g_caps[k].until) nd += cap_close_locked(k, &done[nd]); LeaveCriticalSection(&g_zlock);
    for (int k = 0; k < nd; k++) cap_announce(&done[k]);
}
static void pkt_handle(const BYTE *f, int n, int raw_ip, DWORD ifidx, ULONGLONG ts) {
    PktInfo pi; if (!parse_frame(f, n, raw_ip, &pi)) return;
    int out = 1; EnterCriticalSection(&g_lock);
    Conn *c = conn_find(pi.v6, pi.udp, pi.src, pi.sport, pi.dst, pi.dport); if (!c) { c = conn_find(pi.v6, pi.udp, pi.dst, pi.dport, pi.src, pi.sport); out = 0; }
    if (!c) { LeaveCriticalSection(&g_lock); InterlockedIncrement64(&g_zoom_unmatched); return; }
    if (c->ifidx && c->ifidx != ifidx) { LeaveCriticalSection(&g_lock); return; }   /* the same flow seen again on another interface (vSwitch, bridge): a duplicate */
    if (!c->ifidx) c->ifidx = ifidx; if (out) c->pkts_out++; else c->pkts_in++;
    int ci = (int)(c - g_conns), had_hello = c->tls_hello, quic = c->quic; DWORD pid = c->pid; BYTE raddr[16]; memcpy(raddr, c->raddr, 16); uint16_t lport = c->lport, rport = c->rport;
    LeaveCriticalSection(&g_lock); InterlockedIncrement64(&g_zoom_matched);
    Decoded d; memset(&d, 0, sizeof d); if (pi.udp) decode_udp(ci, quic, &pi, out, &d); else decode_tcp(ci, had_hello, &pi, out, &d);
    int interested = zoom_interested(pid), announce = 0; Conn fi;
    if (d.sni[0] || d.alpn[0] || d.tls_ver || d.http[0] || d.quic_ver) {
        EnterCriticalSection(&g_lock); Conn *c2 = &g_conns[ci];
        if (c2->used && c2->lport == lport && c2->rport == rport) { if (d.sni[0]) { strcpy(c2->sni, d.sni); c2->tls_hello = 1; } if (d.alpn[0]) strcpy(c2->alpn, d.alpn); if (d.tls_ver && (!c2->tls_ver || d.tls_server)) c2->tls_ver = d.tls_ver; if (d.http[0] && !c2->http[0]) strcpy(c2->http, d.http); if (d.quic_ver) { c2->quic = 1; c2->quic_ver = d.quic_ver; }
            /* flowinfo: once per flow when its identity is first decoded (1 TLS/QUIC ClientHello with SNI or ALPN, 2 HTTP request, 4 TLS ServerHello of a flow whose ClientHello was never seen) */
            int cls = 0; if (d.sni[0] || d.alpn[0]) cls |= 1; if (d.http[0]) cls |= 2; if (d.tls_server && !(c2->announced & 1)) cls |= 4;
            if (interested && (cls & ~c2->announced)) { c2->announced |= (BYTE)cls; fi = *c2; announce = 1; } }
        LeaveCriticalSection(&g_lock);
    }
    for (int i = 0; i < d.nlearn; i++) host_learn(d.learn[i].ip, d.learn[i].name, 1);
    char ra[48]; addr_str(pi.v6, raddr, ra, sizeof ra);
    if (d.sni[0]) { wchar_t w[128]; to_wide(d.sni, w, 128); host_learn(ra, w, 4); }
    if (!interested) return;
    char js[1500];
    if (announce) { char cj[1400], *cp = cj, *ce = cj + sizeof cj - 2; cj[0] = 0; append_conn_json(&cp, ce, &fi); if (cj[0] == '{') { snprintf(js, sizeof js, "{\"ev\":\"flowinfo\",%s", cj + 1); send_watchers(pid, js, 0); } }
    Pkt pk; memset(&pk, 0, sizeof pk); pk.t = ts; pk.pid = pid; pk.conn = ci; pk.out = (BYTE)out; pk.v6 = (BYTE)pi.v6; pk.udp = (BYTE)pi.udp; pk.flags = pi.tcpflags; pk.len = (uint16_t)(n > 65535 ? 65535 : n); pk.lport = lport; pk.rport = rport; memcpy(pk.raddr, raddr, 16); strncpy(pk.info, d.info, sizeof pk.info - 1);
    CapDone done[MAX_CAPS]; int nd = 0;
    EnterCriticalSection(&g_zlock); g_pkts[g_pkt_head % PKT_RING] = pk; g_pkt_head++;
    for (int k = 0; k < MAX_CAPS; k++) { Cap *cp = &g_caps[k]; if (!cp->f || (cp->pid && cp->pid != pid)) continue; if (ts > cp->until) nd += cap_close_locked(k, &done[nd]); else { pcap_packet(cp->f, ts, f, n, raw_ip, pi.v6); cp->pkts++; cp->bytes += (uint64_t)n; } }
    LeaveCriticalSection(&g_zlock);
    for (int k = 0; k < nd; k++) cap_announce(&done[k]);
    wchar_t host[128]; char hostu[300] = "", info[400], ts_s[40]; if (host_lookup(ra, host, 128)) jw(host, hostu, sizeof hostu); json_escape(d.info, info, sizeof info); ft_iso(ts, ts_s, sizeof ts_s); char fl[48]; tcp_flags_str(pi.tcpflags, fl, sizeof fl);
    snprintf(js, sizeof js, "{\"ev\":\"pkt\",\"pid\":%lu,\"t\":\"%s\",\"dir\":\"%s\",\"proto\":\"%s%s\",\"lport\":%u,\"remote\":\"%s\",\"port\":%u,\"host\":\"%s\",\"len\":%d,\"flags\":\"%s\",\"info\":\"%s\"}", (unsigned long)pid, ts_s, out ? "out" : "in", pi.udp ? "udp" : "tcp", pi.v6 ? "6" : "", lport, ra, rport, hostu, n, fl, info);
    int handshake = d.kind == 10 || d.kind == 11 || d.kind == 12 || (d.kind == 13 && (d.sni[0] || d.alpn[0]));   /* what a 'handshakes' watcher receives: TLS hellos, DNS, HTTP, decoded QUIC hellos */
    send_watchers(pid, js, handshake ? 2 : 1);
    if ((d.kind == 10 && d.sni[0]) || (d.kind == 13 && d.sni[0]) || (d.kind == 11 && !strncmp(d.info, "DNS query", 9)) || (d.kind == 12 && out)) { wchar_t det[120]; to_wide(d.info, det, 120); trace_add(pid, 0, d.kind, det); }
}
static void CALLBACK on_zoom_event(PEVENT_RECORD r) {
    if (IsEqualGUID(&r->EventHeader.ProviderId, &KernelProcessGuid)) { kproc_event(r); return; }
    if (!IsEqualGUID(&r->EventHeader.ProviderId, &NdisCapGuid) || r->EventHeader.EventDescriptor.Id != 1001) return;
    const BYTE *d = (const BYTE *)r->UserData; ULONG n = r->UserDataLength; if (n < 12) return; DWORD ifidx, fsz; memcpy(&ifidx, d, 4); memcpy(&fsz, d + 8, 4); if (12 + fsz > n) fsz = n - 12; const BYTE *frag = d + 12;
    ULONGLONG kw = r->EventHeader.EventDescriptor.Keyword; if (kw & 0x10000) return;   /* native 802.11 frames: not parsed */
    int raw_ip = (kw & (0x200 | 0x8000)) != 0, start = (kw & 0x40000000) != 0, end = (kw & 0x80000000) != 0; ULONGLONG ts = (ULONGLONG)r->EventHeader.TimeStamp.QuadPart;
    InterlockedIncrement64(&g_zoom_frames); InterlockedAdd64(&g_zoom_bytes, fsz);
    static BYTE asm_buf[65536 + 4096]; static int asm_len, asm_active;   /* a frame larger than one event arrives as PacketStart .. PacketEnd fragments */
    if (!asm_active || start) { if (start && !end) { asm_active = 1; asm_len = 0; } else { asm_active = 0; pkt_handle(frag, (int)fsz, raw_ip, ifidx, ts); return; } }
    if (asm_len + (int)fsz > (int)sizeof asm_buf) { asm_active = 0; return; } memcpy(asm_buf + asm_len, frag, fsz); asm_len += (int)fsz;
    if (end) { asm_active = 0; pkt_handle(asm_buf, asm_len, raw_ip, ifidx, ts); }
}
static DWORD WINAPI zoom_thread(LPVOID a) {
    (void)a; EVENT_TRACE_PROPERTIES *p = etw_props(); p->BufferSize = 512; p->MinimumBuffers = 16; p->MaximumBuffers = 128; TRACEHANDLE h = 0; ULONG rc = StartTraceW(&h, ZOOM_SESSION, p);
    if (rc == ERROR_ALREADY_EXISTS) { ControlTraceW(0, ZOOM_SESSION, p, EVENT_TRACE_CONTROL_STOP); free(p); p = etw_props(); p->BufferSize = 512; p->MinimumBuffers = 16; p->MaximumBuffers = 128; rc = StartTraceW(&h, ZOOM_SESSION, p); }
    if (rc != ERROR_SUCCESS) { g_zoom_err = rc; g_zoom_fail_tick = GetTickCount64(); InterlockedExchange(&g_zoom_state, -1); free(p); return 0; }
    g_zoom_session = h;
    rc = EnableTraceEx2(h, &NdisCapGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) { g_zoom_err = rc; g_zoom_fail_tick = GetTickCount64(); InterlockedExchange(&g_zoom_state, -1); ControlTraceW(h, NULL, p, EVENT_TRACE_CONTROL_STOP); g_zoom_session = 0; free(p); return 0; }
    EnableTraceEx2(h, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x40 /* WINEVENT_KEYWORD_IMAGE */, 0, 0, NULL);
    EVENT_TRACE_LOGFILEW lf; memset(&lf, 0, sizeof lf); lf.LoggerName = (LPWSTR)ZOOM_SESSION; lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; lf.EventRecordCallback = on_zoom_event;
    TRACEHANDLE th = OpenTraceW(&lf); if (th == (TRACEHANDLE)INVALID_HANDLE_VALUE) { g_zoom_err = GetLastError(); g_zoom_fail_tick = GetTickCount64(); InterlockedExchange(&g_zoom_state, -1); ControlTraceW(h, NULL, p, EVENT_TRACE_CONTROL_STOP); g_zoom_session = 0; free(p); return 0; }
    zoom_crypto_init(); InterlockedExchange(&g_zoom_state, 2); log_json("{\"ev\":\"zoom\",\"state\":\"running\"}");
    ProcessTrace(&th, 1, NULL, NULL); CloseTrace(th); free(p); InterlockedExchange(&g_zoom_state, 0); log_json("{\"ev\":\"zoom\",\"state\":\"stopped\"}"); return 0;
}
static void zoom_start(void) { if (g_zoom_state == -1 && GetTickCount64() - g_zoom_fail_tick > 30000) InterlockedCompareExchange(&g_zoom_state, 0, -1); if (InterlockedCompareExchange(&g_zoom_state, 1, 0) == 0) { HANDLE t = CreateThread(NULL, 0, zoom_thread, NULL, 0, NULL); if (t) CloseHandle(t); else InterlockedExchange(&g_zoom_state, 0); } }
static void zoom_stop(void) { TRACEHANDLE h = g_zoom_session; if (!h) return; g_zoom_session = 0; EVENT_TRACE_PROPERTIES *p = etw_props(); ControlTraceW(h, NULL, p, EVENT_TRACE_CONTROL_STOP); free(p); }
static void zoom_recalc(void) {   /* interest set = open inspectors + socket watchers + capture target; the session runs while it is non-empty (30 s grace after) */
    DWORD pids[MAX_ZOOM_PIDS]; int n = 0, all = 0;
    for (int i = 0; i < MAX_INSPECT; i++) if (g_insp_pids[i] && n < MAX_ZOOM_PIDS) pids[n++] = g_insp_pids[i];
    EnterCriticalSection(&g_clock); for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s != INVALID_SOCKET && g_clients[i].state == 2) for (int k = 0; k < g_clients[i].nwatch; k++) { if (g_clients[i].watch[k] == 0xFFFFFFFFu) all = 1; else if (n < MAX_ZOOM_PIDS) pids[n++] = g_clients[i].watch[k]; } LeaveCriticalSection(&g_clock);
    EnterCriticalSection(&g_zlock); for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f) { if (g_caps[k].pid == 0) all = 1; else if (n < MAX_ZOOM_PIDS) pids[n++] = g_caps[k].pid; } memcpy(g_zoom_pids, pids, n * sizeof pids[0]); g_nzoom = n; g_zoom_all = all; LeaveCriticalSection(&g_zlock);
    if (n || all) { g_zoom_idle_since = 0; zoom_start(); } else if (!g_zoom_idle_since) g_zoom_idle_since = GetTickCount64();
}
static const char *zoom_state_str(void) { switch (g_zoom_state) { case 2: return "running"; case 1: return "starting"; case -1: return "error"; default: return "off"; } }

/* ------------------------------------------------------------------ audit keeper ------------------------------------------------------------------ */
typedef struct { GUID sub; ULONG info; GUID cat; } MY_AUDIT_POLICY_INFORMATION;
typedef BOOLEAN (WINAPI *PFN_AQSP)(const GUID *, ULONG, MY_AUDIT_POLICY_INFORMATION **); typedef BOOLEAN (WINAPI *PFN_ASSP)(const MY_AUDIT_POLICY_INFORMATION *, ULONG); typedef VOID (WINAPI *PFN_AF)(PVOID);
static PFN_AQSP pAuditQuery; static PFN_ASSP pAuditSet; static PFN_AF pAuditFree;
static void audit_init(void) { HMODULE m = LoadLibraryW(L"advapi32.dll"); if (!m) return; pAuditQuery = (PFN_AQSP)GetProcAddress(m, "AuditQuerySystemPolicy"); pAuditSet = (PFN_ASSP)GetProcAddress(m, "AuditSetSystemPolicy"); pAuditFree = (PFN_AF)GetProcAddress(m, "AuditFree"); enable_privilege(L"SeSecurityPrivilege"); }
static int audit_query(void) { if (!pAuditQuery) return -1; MY_AUDIT_POLICY_INFORMATION *pol = NULL; if (!pAuditQuery(&AuditFpConnGuid, 1, &pol) || !pol) return -1; int on = (pol->info & 3) == 3; if (pAuditFree) pAuditFree(pol); return on; }
static int audit_enable(void) { if (!pAuditSet) return 0; MY_AUDIT_POLICY_INFORMATION p; memset(&p, 0, sizeof p); p.sub = AuditFpConnGuid; p.info = 3; return pAuditSet(&p, 1) ? 1 : 0; }

/* ------------------------------------------------------------------ history ------------------------------------------------------------------ */
static void history_rotate_minute(void) {   /* called under g_lock at a minute boundary */
    Minute *m = &g_hist[g_hist_i]; memset(m, 0, sizeof *m); now_iso(m->t, 20); m->t[16] = 0;
    for (int i = 0; i < MAX_PROCS; i++) {
        Proc *p = &g_procs[i]; if (!p->used || (p->tx_min == 0 && p->rx_min == 0)) continue;
        m->tx += p->tx_min; m->rx += p->rx_min;
        int slot = -1; uint64_t v = p->tx_min + p->rx_min;
        if (m->n < HIST_PROCS) slot = m->n++; else { uint64_t least = ~0ULL; for (int k = 0; k < HIST_PROCS; k++) if (m->p[k].tx + m->p[k].rx < least) { least = m->p[k].tx + m->p[k].rx; slot = k; } if (v <= least) slot = -1; }
        if (slot >= 0) { m->p[slot].pid = p->pid; wcsncpy(m->p[slot].name, p->name, 47); m->p[slot].tx = p->tx_min; m->p[slot].rx = p->rx_min; }
        p->tx_min = p->rx_min = 0;
    }
    g_hist_i = (g_hist_i + 1) % HIST_MIN; if (g_hist_n < HIST_MIN) g_hist_n++;
    if (m->tx || m->rx) {
        WIN32_FILE_ATTRIBUTE_DATA fa; if (GetFileAttributesExW(g_hist_path, GetFileExInfoStandard, &fa) && fa.nFileSizeLow > 64u * 1024 * 1024) { wchar_t old[MAX_PATH]; _snwprintf(old, MAX_PATH, L"%ls.1", g_hist_path); DeleteFileW(old); MoveFileW(g_hist_path, old); }
        FILE *f = _wfopen(g_hist_path, L"ab"); if (f) { fprintf(f, "{\"t\":\"%s\",\"tx\":%llu,\"rx\":%llu,\"procs\":[", m->t, (unsigned long long)m->tx, (unsigned long long)m->rx); for (int k = 0; k < m->n; k++) { char nm[160]; jw(m->p[k].name, nm, sizeof nm); fprintf(f, "%s{\"pid\":%lu,\"name\":\"%s\",\"tx\":%llu,\"rx\":%llu}", k ? "," : "", (unsigned long)m->p[k].pid, nm, (unsigned long long)m->p[k].tx, (unsigned long long)m->p[k].rx); } fprintf(f, "]}\n"); fclose(f); }
    }
}

/* ------------------------------------------------------------------ trust / deny / clients ------------------------------------------------------------------ */
static void trust_save(void) { FILE *f = _wfopen(g_trust_path, L"wb"); if (!f) return; for (int i = 0; i < g_ntrust; i++) { char p[1200]; jw(g_trust[i].path, p, sizeof p); fprintf(f, "{\"path\":\"%s\",\"sha256\":\"%s\",\"since\":\"%s\"}\n", p, g_trust[i].sha, g_trust[i].since); } fclose(f); }
static void trust_load(void) { FILE *f = _wfopen(g_trust_path, L"rb"); if (!f) return; char line[2048]; while (fgets(line, sizeof line, f) && g_ntrust < MAX_TRUST) { char p[1200]; if (json_get_str(line, "path", p, sizeof p)) { to_wide(p, g_trust[g_ntrust].path, MAX_PATH); json_get_str(line, "sha256", g_trust[g_ntrust].sha, 65); json_get_str(line, "since", g_trust[g_ntrust].since, 24); g_ntrust++; } } fclose(f); }
static int trust_check(const wchar_t *path, const char *sha) { for (int i = 0; i < g_ntrust; i++) if (!_wcsicmp(g_trust[i].path, path) && !_stricmp(g_trust[i].sha, sha)) return 1; return 0; }
static void trust_add(const wchar_t *path, const char *sha) { EnterCriticalSection(&g_tlock); if (!trust_check(path, sha) && g_ntrust < MAX_TRUST) { wcsncpy(g_trust[g_ntrust].path, path, MAX_PATH - 1); strncpy(g_trust[g_ntrust].sha, sha, 64); now_iso(g_trust[g_ntrust].since, 24); g_ntrust++; trust_save(); } LeaveCriticalSection(&g_tlock); }
static Deny *deny_find(const wchar_t *path, int create) { for (int i = 0; i < g_ndeny; i++) if (!_wcsicmp(g_deny[i].path, path)) return &g_deny[i]; if (!create) return NULL; if (g_ndeny >= MAX_DENY) { g_ndeny = 0; } Deny *d = &g_deny[g_ndeny++]; memset(d, 0, sizeof *d); wcsncpy(d->path, path, MAX_PATH - 1); return d; }
static void tray_balloon(const wchar_t *title, const wchar_t *text, int force);
static void bcast(const char *s);
static void deny_record(const wchar_t *path, const char *why) {
    EnterCriticalSection(&g_tlock); Deny *d = deny_find(path, 1); d->count++; d->last = GetTickCount64(); int count = d->count, already = d->blocked; if (count >= 3) d->blocked = 1; LeaveCriticalSection(&g_tlock);
    char p[1200]; jw(path, p, sizeof p); char line[1500];
    snprintf(line, sizeof line, "{\"ev\":\"auth\",\"status\":\"denied\",\"path\":\"%s\",\"count\":%d,\"why\":\"%s\"}", p, count, why); log_json(line); bcast(line);
    if (count >= 3 && !already) {
        char err[160]; int ok = fw_block(path, 1, err, sizeof err);
        snprintf(line, sizeof line, "{\"ev\":\"intruder\",\"path\":\"%s\",\"denials\":%d,\"firewall_blocked\":%s}", p, count, ok ? "true" : "false"); log_json(line); bcast(line);
        wchar_t t[300]; _snwprintf(t, 300, L"%ls tried to control Hodometer %d times and was denied. Its network access is now blocked by firewall rule.", basename_w(path), count);
        tray_balloon(L"Hodometer: intruder blocked", t, 1);
    }
}
static int attempts_recent(void) { ULONGLONG now = GetTickCount64(); int c = 0; for (int i = 0; i < 32; i++) if (g_attempts[i] && now - g_attempts[i] < 60000) c++; return c; }
static DWORD peer_pid(SOCKET s) {
    struct sockaddr_in a; int al = sizeof a; if (getpeername(s, (struct sockaddr *)&a, &al)) return 0; USHORT pport = ntohs(a.sin_port);
    DWORD sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(sz); DWORD pid = 0;
    if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) for (DWORD i = 0; i < t->dwNumEntries; i++) if (ntohs((USHORT)t->table[i].dwLocalPort) == pport && ntohs((USHORT)t->table[i].dwRemotePort) == (USHORT)g_port) { pid = t->table[i].dwOwningPid; break; }
    free(t); return pid;
}
static int client_count(void) { int c = 0; EnterCriticalSection(&g_clock); for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s != INVALID_SOCKET && g_clients[i].state == 2) c++; LeaveCriticalSection(&g_clock); return c; }
static void client_drop(int i) { Client *c = &g_clients[i]; if (c->s != INVALID_SOCKET) { closesocket(c->s); c->s = INVALID_SOCKET; c->state = 0; c->len = 0; } free(c->outbuf); c->outbuf = NULL; c->outlen = 0; c->overflow = 0; if (c->nwatch) { c->nwatch = 0; InterlockedExchange(&g_watch_dirty, 1); } }
/* Output is queued per client and drained by the socket thread, so the UI thread never blocks on a slow client.
   A client that lets 512 KB pile up is dropped as a slow consumer. */
static void send_line(int i, const char *s) {
    EnterCriticalSection(&g_clock);
    Client *c = &g_clients[i];
    if (c->s != INVALID_SOCKET) { int len = (int)strlen(s); if (!c->outbuf) c->outbuf = (char *)malloc(OUTBUF_MAX); if (c->outbuf) { if (c->outlen + len + 1 > OUTBUF_MAX) c->overflow = 1; else { memcpy(c->outbuf + c->outlen, s, len); c->outlen += len; c->outbuf[c->outlen++] = '\n'; } } }
    LeaveCriticalSection(&g_clock);
}
static void bcast(const char *s) { for (int i = 0; i < MAX_CLIENTS; i++) { EnterCriticalSection(&g_clock); int on = g_clients[i].s != INVALID_SOCKET && g_clients[i].state == 2; LeaveCriticalSection(&g_clock); if (on) send_line(i, s); } }
static void flush_client(int i) {   /* socket thread only */
    Client *c = &g_clients[i]; if (c->s == INVALID_SOCKET || c->outlen == 0) return;
    int r = send(c->s, c->outbuf, c->outlen, 0);
    if (r == SOCKET_ERROR) { if (WSAGetLastError() != WSAEWOULDBLOCK) client_drop(i); return; }
    if (r > 0) { memmove(c->outbuf, c->outbuf + r, c->outlen - r); c->outlen -= r; }
}

/* ------------------------------------------------------------------ socket commands ------------------------------------------------------------------ */
static const char *audit_str(void) { return g_audit_ok == 1 ? "on" : g_audit_ok == 0 ? "off" : "unknown"; }
static const char *etw_str(void) { return g_etw_state == 1 ? "running" : g_etw_state == 0 ? "starting" : "error"; }
static void append_proc_json(char **cur, char *end, const Proc *p) {
    char esc[400], pesc[1200], rem[80] = "", hostu[300] = ""; jw(p->name, esc, sizeof esc); jw(p->path, pesc, sizeof pesc);
    const Remote *r = proc_top_remote(p);
    if (r) { snprintf(rem, sizeof rem, "%s:%u", r->addr, r->port); wchar_t h[128]; if (host_lookup(r->addr, h, 128)) jw(h, hostu, sizeof hostu); }
    int n = snprintf(*cur, end - *cur, "{\"pid\":%lu,\"name\":\"%s\",\"tx_bps\":%.0f,\"rx_bps\":%.0f,\"tx_total\":%llu,\"rx_total\":%llu,\"remote\":\"%s\",\"host\":\"%s\",\"blocked\":%s,\"vm\":%s,\"conns\":%lu,\"retx\":%llu,\"fails\":%lu,\"path\":\"%s\"}",
        (unsigned long)p->pid, esc, p->tx_rate, p->rx_rate, (unsigned long long)p->tx_total, (unsigned long long)p->rx_total, rem, hostu, p->blocked ? "true" : "false", p->vm ? "true" : "false", (unsigned long)p->nconn, (unsigned long long)p->retx, (unsigned long)p->fails, pesc);
    if (n > 0 && *cur + n < end) *cur += n; else **cur = 0;
}
static void append_conn_json(char **cur, char *end, const Conn *c) {
    char ip[48], hostu[300] = "", sni[200], alpn[60], http[200]; addr_str(c->v6, c->raddr, ip, sizeof ip); wchar_t h[128]; if (host_lookup(ip, h, 128)) jw(h, hostu, sizeof hostu); json_escape(c->sni, sni, sizeof sni); json_escape(c->alpn, alpn, sizeof alpn); json_escape(c->http, http, sizeof http);
    int n = snprintf(*cur, end - *cur, "{\"pid\":%lu,\"proto\":\"%s%s\",\"lport\":%u,\"remote\":\"%s\",\"port\":%u,\"host\":\"%s\",\"state\":\"%s\",\"local\":%s,\"age_s\":%llu,\"connect_ms\":%d,\"tx\":%llu,\"rx\":%llu,\"tx_bps\":%.0f,\"rx_bps\":%.0f,\"retx_bytes\":%llu,\"retx_events\":%lu,\"reconnects\":%lu,\"mss\":%u,\"pkts_out\":%llu,\"pkts_in\":%llu,\"estats\":%s,\"srtt_ms\":%lu,\"min_rtt_ms\":%lu,\"max_rtt_ms\":%lu,\"rto_ms\":%lu,\"pkts_retrans\":%lu,\"timeouts\":%lu,\"cong_signals\":%lu,\"dup_acks\":%lu,\"sni\":\"%s\",\"alpn\":\"%s\",\"tls\":\"%s\",\"quic\":%s,\"http\":\"%s\"}",
        (unsigned long)c->pid, c->udp ? "udp" : "tcp", c->v6 ? "6" : "", c->lport, ip, c->rport, hostu, conn_state_str(c), c->local ? "true" : "false", (unsigned long long)((GetTickCount64() - c->first_seen) / 1000), c->connect_ms, (unsigned long long)c->tx, (unsigned long long)c->rx, c->tx_rate, c->rx_rate,
        (unsigned long long)c->retx, (unsigned long)c->retx_events, (unsigned long)c->reconnects, c->mss, (unsigned long long)c->pkts_out, (unsigned long long)c->pkts_in, c->estats ? "true" : "false", (unsigned long)c->srtt, (unsigned long)(c->minrtt == 0xFFFFFFFF ? 0 : c->minrtt), (unsigned long)c->maxrtt, (unsigned long)c->rto, (unsigned long)c->pretrans, (unsigned long)c->timeouts, (unsigned long)c->cong, (unsigned long)c->dupacks,
        sni, alpn, c->tls_ver ? tls_ver_str(c->tls_ver) : "", c->quic ? "true" : "false", http);
    if (n > 0 && *cur + n < end) *cur += n; else **cur = 0;
}
static void build_status(char *out, int n) {
    int caps; EnterCriticalSection(&g_zlock); caps = cap_active_locked(); LeaveCriticalSection(&g_zlock);
    snprintf(out, n, "{\"reply\":\"status\",\"version\":\"%s\",\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,\"tx_total\":%llu,\"rx_total\":%llu,\"audit\":\"%s\",\"audit_auto\":%s,\"etw\":\"%s\",\"etw_error\":%lu,\"zoom\":\"%s\",\"include_local\":%s,\"paused\":%s,\"threshold_tx_mbps\":%.2f,\"threshold_rx_mbps\":%.2f,\"clients\":%d,\"trusted\":%d,\"blocked\":%d,\"captures\":%d,\"max_captures\":%d,\"max_watch\":%d,\"workers\":%d,\"conn_events\":%llu,\"history_minutes\":%d,\"uptime_s\":%llu,\"port\":%d}",
        APP_VERSION, g_tx_rate / 1048576.0, g_rx_rate / 1048576.0, (unsigned long long)g_tx_total, (unsigned long long)g_rx_total, audit_str(), g_audit_auto ? "true" : "false", etw_str(), (unsigned long)g_etw_err, zoom_state_str(), g_include_local ? "true" : "false", g_paused ? "true" : "false", g_tx_thresh, g_rx_thresh, client_count(), g_ntrust, g_nblocked, caps, MAX_CAPS, MAX_WATCH, CMD_WORKERS, (unsigned long long)g_conn_events, g_hist_n, (unsigned long long)((GetTickCount64() - g_start_tick) / 1000), g_port);
}
static int resolve_target(const char *arg, wchar_t *path, int n) {   /* pid or path -> path */
    path[0] = 0; if (!arg[0]) return 0;
    if (isdigit((unsigned char)arg[0]) && strspn(arg, "0123456789") == strlen(arg)) { DWORD pid = (DWORD)strtoul(arg, NULL, 10); EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p && p->path[0]) wcsncpy(path, p->path, n - 1); LeaveCriticalSection(&g_lock); if (!path[0]) pid_path(pid, path, n); return path[0] != 0; }
    to_wide(arg, path, n); return path[0] != 0;
}
static void handle_command(int ci, char *line, char *big, int bign) {   /* runs on a command worker; big is that worker's reply buffer (CMD_BIG) */
    char cmd[32] = "", arg1[1200] = "", arg2[1200] = "";
    while (*line == ' ' || *line == '\t') line++; size_t L = strlen(line); while (L && (line[L - 1] == '\r' || line[L - 1] == ' ')) line[--L] = 0; if (!L) return;
    if (line[0] == '{') { json_get_str(line, "cmd", cmd, sizeof cmd); if (!json_get_str(line, "pid", arg1, sizeof arg1)) if (!json_get_str(line, "path", arg1, sizeof arg1)) json_get_str(line, "value", arg1, sizeof arg1); json_get_str(line, "rx", arg2, sizeof arg2); if (!arg2[0]) json_get_str(line, "arg", arg2, sizeof arg2); }
    else { char *sp = strchr(line, ' '); if (sp) { *sp = 0; strncpy(cmd, line, 31); char *rest = sp + 1; while (*rest == ' ') rest++; char *sp2 = (rest[0] == '"') ? NULL : strchr(rest, ' '); if (rest[0] == '"') { char *q = strchr(rest + 1, '"'); if (q) { *q = 0; strncpy(arg1, rest + 1, sizeof arg1 - 1); sp2 = q + 1; while (*sp2 == ' ') sp2++; strncpy(arg2, sp2, sizeof arg2 - 1); } } else if (sp2) { *sp2 = 0; strncpy(arg1, rest, sizeof arg1 - 1); strncpy(arg2, sp2 + 1, sizeof arg2 - 1); } else strncpy(arg1, rest, sizeof arg1 - 1); } else strncpy(cmd, line, 31); }
    for (char *c = cmd; *c; c++) *c = (char)tolower((unsigned char)*c);
    char out[4096];
    if (!strcmp(cmd, "status")) { build_status(out, sizeof out); send_line(ci, out); }
    else if (!strcmp(cmd, "whoami")) { char p[1200], nm[200]; jw(g_clients[ci].path, p, sizeof p); jw(g_clients[ci].name, nm, sizeof nm); snprintf(out, sizeof out, "{\"reply\":\"whoami\",\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\",\"sha256\":\"%s\",\"trusted\":%s}", (unsigned long)g_clients[ci].pid, nm, p, g_clients[ci].sha, g_clients[ci].once ? "false" : "true"); send_line(ci, out); }
    else if (!strcmp(cmd, "clients")) { char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"clients\",\"clients\":["); int first = 1; for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s != INVALID_SOCKET) { char nm[200]; jw(g_clients[i].name, nm, sizeof nm); cur += snprintf(cur, end - cur, "%s{\"pid\":%lu,\"name\":\"%s\",\"state\":\"%s\",\"since_s\":%llu}", first ? "" : ",", (unsigned long)g_clients[i].pid, nm, g_clients[i].state == 2 ? "allowed" : g_clients[i].state == 1 ? "pending" : "closing", (unsigned long long)((GetTickCount64() - g_clients[i].since) / 1000)); first = 0; } cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "list")) {
        char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"list\",\"procs\":["); int first = 1;
        EnterCriticalSection(&g_lock); for (int i = 0; i < MAX_PROCS; i++) { const Proc *p = &g_procs[i]; if (!p->used || (p->tx_total == 0 && p->rx_total == 0)) continue; if (!first) { if (cur < end) *cur++ = ','; } first = 0; append_proc_json(&cur, end, p); if (end - cur < 3000) break; } LeaveCriticalSection(&g_lock);
        if (cur < end) { *cur++ = ']'; *cur++ = '}'; } *cur = 0; send_line(ci, big);
    }
    else if (!strcmp(cmd, "kill")) { DWORD pid = (DWORD)strtoul(arg1, NULL, 10); char err[160] = ""; int ok = pid ? kill_pid(pid, err, sizeof err) : 0; if (!pid) strcpy(err, "usage: kill <pid>"); char e[320]; json_escape(err, e, sizeof e); snprintf(out, sizeof out, "{\"reply\":\"kill\",\"pid\":%lu,\"ok\":%s,\"error\":\"%s\"}", (unsigned long)pid, ok ? "true" : "false", e); send_line(ci, out); if (ok) { char nm[200]; jw(g_clients[ci].name, nm, sizeof nm); snprintf(out, sizeof out, "{\"ev\":\"killed\",\"pid\":%lu,\"by\":\"socket:%s\"}", (unsigned long)pid, nm); bcast(out); } }
    else if (!strcmp(cmd, "block") || !strcmp(cmd, "unblock")) { wchar_t path[MAX_PATH]; char err[160] = ""; int ok = 0; if (resolve_target(arg1, path, MAX_PATH)) ok = fw_block(path, cmd[0] == 'b', err, sizeof err); else strcpy(err, "usage: block <pid|path> (path quoted if it has spaces)"); char p[1200], e[320]; jw(path, p, sizeof p); json_escape(err, e, sizeof e); snprintf(out, sizeof out, "{\"reply\":\"%s\",\"path\":\"%s\",\"ok\":%s,\"error\":\"%s\"}", cmd, p, ok ? "true" : "false", e); send_line(ci, out); if (ok) { snprintf(out, sizeof out, "{\"ev\":\"%sed\",\"path\":\"%s\"}", cmd, p); bcast(out); } }
    else if (!strcmp(cmd, "blocks")) { char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"blocks\",\"blocked\":["); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_nblocked; i++) { char p[1200]; jw(g_blocked[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"since\":\"%s\"}", i ? "," : "", p, g_blocked[i].since); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "trust")) {
        if (!strcmp(arg1, "clear")) { EnterCriticalSection(&g_tlock); g_ntrust = 0; trust_save(); LeaveCriticalSection(&g_tlock); send_line(ci, "{\"reply\":\"trust\",\"ok\":true,\"trusted\":0}"); }
        else if (!strcmp(arg1, "remove")) { int removed = 0; wchar_t w[300]; to_wide(arg2, w, 300); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ntrust; i++) { wchar_t lp[MAX_PATH], lw[300]; wcscpy(lp, g_trust[i].path); wcscpy(lw, w); _wcslwr(lp); _wcslwr(lw); if (lw[0] && wcsstr(lp, lw)) { g_trust[i] = g_trust[--g_ntrust]; i--; removed++; } } trust_save(); LeaveCriticalSection(&g_tlock); snprintf(out, sizeof out, "{\"reply\":\"trust\",\"removed\":%d,\"trusted\":%d}", removed, g_ntrust); send_line(ci, out); }
        else { char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"trust\",\"trusted\":["); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ntrust; i++) { char p[1200]; jw(g_trust[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"sha256\":\"%s\",\"since\":\"%s\"}", i ? "," : "", p, g_trust[i].sha, g_trust[i].since); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    }
    else if (!strcmp(cmd, "snap")) {   /* snap [file.bmp] [pid]: capture the main window, or the open Inspector of pid, to a .bmp; an AI can look at the GUI */
        wchar_t *path = (wchar_t *)calloc(MAX_PATH, sizeof(wchar_t)); if (arg1[0] && !isdigit((unsigned char)arg1[0])) to_wide(arg1, path, MAX_PATH); else _snwprintf(path, MAX_PATH, L"%ls\\snapshot.bmp", g_exe_dir);
        DWORD pid = (DWORD)strtoul(arg2[0] ? arg2 : arg1, NULL, 10); HWND target = pid ? insp_hwnd(pid) : NULL;
        if (pid && !target) { free(path); snprintf(out, sizeof out, "{\"reply\":\"snap\",\"ok\":false,\"error\":\"no inspector open for pid %lu (use: inspect %lu show)\"}", (unsigned long)pid, (unsigned long)pid); send_line(ci, out); return; }
        char p[1200]; jw(path, p, sizeof p); snprintf(out, sizeof out, "{\"reply\":\"snap\",\"path\":\"%s\",\"window\":\"%s\",\"scheduled\":true,\"note\":\"a 'snap' event follows when the file is written\"}", p, target ? "inspector" : "main"); send_line(ci, out);
        PostMessageW(g_main, WM_SNAP, (WPARAM)target, (LPARAM)path);
    }
    else if (!strcmp(cmd, "denials")) { char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"denials\",\"suspended\":%s,\"denied\":[", GetTickCount64() < g_auth_suspended_until ? "true" : "false"); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ndeny; i++) { char p[1200]; jw(g_deny[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"count\":%d,\"blocked\":%s,\"cooldown_s\":%lld}", i ? "," : "", p, g_deny[i].count, g_deny[i].blocked ? "true" : "false", (long long)((600000 - (GetTickCount64() - g_deny[i].last)) / 1000 > 0 ? (600000 - (GetTickCount64() - g_deny[i].last)) / 1000 : 0)); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "pardon")) {   /* clear denial record (and firewall block) for programs whose path contains the argument */
        int n = 0; wchar_t w[300]; to_wide(arg1, w, 300); _wcslwr(w);
        EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ndeny && w[0]; i++) { wchar_t lp[MAX_PATH]; wcscpy(lp, g_deny[i].path); _wcslwr(lp); if (wcsstr(lp, w)) { wchar_t path[MAX_PATH]; wcscpy(path, g_deny[i].path); int wasblocked = g_deny[i].blocked; g_deny[i] = g_deny[--g_ndeny]; i--; n++; LeaveCriticalSection(&g_tlock); if (wasblocked) { char err[160]; fw_block(path, 0, err, sizeof err); } EnterCriticalSection(&g_tlock); } } LeaveCriticalSection(&g_tlock);
        snprintf(out, sizeof out, "{\"reply\":\"pardon\",\"cleared\":%d}", n); send_line(ci, out);
    }
    else if (!strcmp(cmd, "history")) {
        int mins = atoi(arg1); if (mins <= 0) mins = 60; if (mins > HIST_MIN) mins = HIST_MIN;
        char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"history\",\"minutes\":[");
        EnterCriticalSection(&g_lock); int n = g_hist_n < mins ? g_hist_n : mins; int first = 1;
        for (int k = n; k >= 1 && end - cur > 4000; k--) { const Minute *m = &g_hist[(g_hist_i - k + HIST_MIN) % HIST_MIN]; cur += snprintf(cur, end - cur, "%s{\"t\":\"%s\",\"tx\":%llu,\"rx\":%llu,\"procs\":[", first ? "" : ",", m->t, (unsigned long long)m->tx, (unsigned long long)m->rx); first = 0; for (int j = 0; j < m->n && j < 10; j++) { char nm[160]; jw(m->p[j].name, nm, sizeof nm); cur += snprintf(cur, end - cur, "%s{\"pid\":%lu,\"name\":\"%s\",\"tx\":%llu,\"rx\":%llu}", j ? "," : "", (unsigned long)m->p[j].pid, nm, (unsigned long long)m->p[j].tx, (unsigned long long)m->p[j].rx); } cur += snprintf(cur, end - cur, "]}"); }
        LeaveCriticalSection(&g_lock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big);
    }
    else if (!strcmp(cmd, "resolve")) { wchar_t h[128]; int src = host_lookup(arg1, h, 128); char hu[300]; jw(h, hu, sizeof hu); char ip[64]; json_escape(arg1, ip, sizeof ip); snprintf(out, sizeof out, "{\"reply\":\"resolve\",\"ip\":\"%s\",\"host\":\"%s\",\"source\":\"%s\"}", ip, hu, src == 1 ? "dns" : src == 2 ? "ptr" : src == 4 ? "sni" : "pending"); send_line(ci, out); }
    else if (!strcmp(cmd, "inspect")) {   /* everything the Inspector window shows: profile, connections with RTT/retransmits, timeline, recent packets */
        DWORD pid = (DWORD)strtoul(arg1, NULL, 10); if (!pid) { send_line(ci, "{\"reply\":\"error\",\"error\":\"usage: inspect <pid> [show]  (show also opens the Inspector window)\"}"); return; }
        if (!strcmp(arg2, "show") && g_main) PostMessageW(g_main, WM_INSPECT, (WPARAM)pid, 0);
        build_inspect_json(pid, big, bign, 0); send_line(ci, big);
    }
    else if (!strcmp(cmd, "conns")) {   /* conns [pid|all] [active] [since <now>] [cursor <n>] [limit <n>]: connections of one pid (seeded from the TCP table, with ESTATS) or of every process, in pages */
        DWORD pid = 0; int active = 0, limit = CONNS_PAGE, cursor = 0; ULONGLONG since = 0;
        if (line[0] == '{') { char v[40]; pid = (DWORD)strtoul(arg1, NULL, 10); if (json_get_str(line, "active", v, sizeof v)) active = strcmp(v, "false") != 0 && strcmp(v, "0") != 0; if (json_get_str(line, "since", v, sizeof v)) since = strtoull(v, NULL, 10); if (json_get_str(line, "cursor", v, sizeof v)) cursor = atoi(v); if (json_get_str(line, "limit", v, sizeof v)) limit = atoi(v); }
        else { char toks[2500]; snprintf(toks, sizeof toks, "%s %s", arg1, arg2); char *t = toks;
            while (*t) { while (*t == ' ') t++; if (!*t) break; char *e = t; while (*e && *e != ' ') e++; if (*e) *e++ = 0;
                if (!strcmp(t, "active")) active = 1; else if (isdigit((unsigned char)t[0])) pid = (DWORD)strtoul(t, NULL, 10);
                else if (!strcmp(t, "since") || !strcmp(t, "cursor") || !strcmp(t, "limit")) { while (*e == ' ') e++; char *v = e; while (*e && *e != ' ') e++; if (*e) *e++ = 0; if (t[0] == 's') since = strtoull(v, NULL, 10); else if (t[0] == 'c') cursor = atoi(v); else limit = atoi(v); }
                t = e; } }
        if (limit <= 0 || limit > CONNS_PAGE) limit = CONNS_PAGE; if (cursor < 0 || cursor >= MAX_CONNS) cursor = 0;
        if (pid) { conns_seed(pid); estats_refresh(pid); }
        Conn *cs = (Conn *)malloc(CONNS_PAGE * sizeof(Conn)); int *idx = (int *)malloc(CONNS_PAGE * sizeof(int)); int nc = 0, total = 0, next = -1; if (!cs || !idx) { free(cs); free(idx); return; }
        ULONGLONG now = GetTickCount64();
        EnterCriticalSection(&g_lock);
        for (int i = 0; i < MAX_CONNS; i++) { const Conn *c = &g_conns[i]; if (!c->used || (pid && c->pid != pid) || (active && (c->state == 3 || c->state == 4)) || (since && c->last_seen < since)) continue; total++; if (i < cursor) continue; if (nc < limit) { cs[nc] = *c; idx[nc++] = i; } else if (next < 0) next = i; }
        LeaveCriticalSection(&g_lock);
        char *cur = big, *end = big + bign - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"conns\",\"pid\":%lu,\"active\":%s,\"since\":%llu,\"cursor\":%d,\"total\":%d,\"now\":%llu,\"conns\":[", (unsigned long)pid, active ? "true" : "false", (unsigned long long)since, cursor, total, (unsigned long long)now);
        int em = 0; for (; em < nc && end - cur > 2000; em++) { if (em) *cur++ = ','; append_conn_json(&cur, end, &cs[em]); }
        if (em < nc) next = idx[em];   /* the reply buffer filled up: resume from the first flow that did not fit */
        if (next >= 0) cur += snprintf(cur, end - cur, "],\"count\":%d,\"next\":%d}", em, next); else cur += snprintf(cur, end - cur, "],\"count\":%d,\"next\":null}", em);
        free(cs); free(idx); send_line(ci, big);
    }
    else if (!strcmp(cmd, "watch")) {   /* watch <pid|all> [packets|handshakes|nopackets] | watch <pid|all> off | watch packets|handshakes|nopackets | watch off | watch  -> flow/trace/flowinfo (and pkt) events for those processes */
        int mode = -1; const char *mw = arg2[0] ? arg2 : arg1; if (!strcmp(mw, "packets")) mode = 1; else if (!strcmp(mw, "handshakes")) mode = 2; else if (!strcmp(mw, "nopackets")) mode = 0;
        EnterCriticalSection(&g_clock); Client *c = &g_clients[ci]; int full = 0;
        if (!arg1[0] || !strcmp(arg1, "list")) { }
        else if (!strcmp(arg1, "off")) c->nwatch = 0;
        else if (!arg2[0] && mode >= 0) c->watch_pkts = mode;   /* change the packet mode of an existing watch */
        else { DWORD pid = !strcmp(arg1, "all") ? 0xFFFFFFFFu : (DWORD)strtoul(arg1, NULL, 10);
            if (!pid) { LeaveCriticalSection(&g_clock); send_line(ci, "{\"reply\":\"error\",\"error\":\"usage: watch <pid|all> [packets|handshakes|nopackets|off]\"}"); return; }
            if (!strcmp(arg2, "off")) { for (int k = 0; k < c->nwatch; k++) if (c->watch[k] == pid) { c->watch[k] = c->watch[--c->nwatch]; k--; } }
            else { int have = 0; for (int k = 0; k < c->nwatch; k++) if (c->watch[k] == pid) have = 1; if (!have) { if (c->nwatch < MAX_WATCH) c->watch[c->nwatch++] = pid; else full = 1; } if (mode >= 0) c->watch_pkts = mode; } }
        char *cur = out, *end = out + sizeof out - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"watch\",\"watching\":["); for (int k = 0; k < c->nwatch; k++) cur += snprintf(cur, end - cur, "%s%s", k ? "," : "", c->watch[k] == 0xFFFFFFFFu ? "\"all\"" : ""), cur += c->watch[k] == 0xFFFFFFFFu ? 0 : snprintf(cur, end - cur, "%lu", (unsigned long)c->watch[k]);
        int pk = c->watch_pkts, nw = c->nwatch; LeaveCriticalSection(&g_clock); zoom_recalc();
        cur += snprintf(cur, end - cur, "],\"count\":%d,\"max\":%d,\"packets\":%s,\"mode\":\"%s\",\"zoom\":\"%s\",\"events\":[\"flow\",\"trace\",\"flowinfo\"%s]%s}", nw, MAX_WATCH, pk ? "true" : "false", pk == 1 ? "packets" : pk == 2 ? "handshakes" : "none", zoom_state_str(), pk ? ",\"pkt\"" : "", full ? ",\"error\":\"watch list full\"" : ""); send_line(ci, out);
    }
    else if (!strcmp(cmd, "capture")) {   /* capture <pid|all> [seconds] [file.pcapng] | capture stop [pid|all] | capture  (JSON: {"cmd":"capture","pid":N,"seconds":S,"path":"..."}) */
        if (!strcmp(arg1, "stop")) {   /* capture stop: every capture; capture stop <pid>: that one; capture stop all: the 'all' capture */
            int nd = !arg2[0] ? cap_stop(0, 1) : cap_stop(!strcmp(arg2, "all") ? 0 : (DWORD)strtoul(arg2, NULL, 10), 0);
            snprintf(out, sizeof out, "{\"reply\":\"capture\",\"stopped\":%s,\"count\":%d}", nd ? "true" : "false", nd); send_line(ci, out); return; }
        if (!arg1[0]) {   /* state: the newest capture in the 1.2 fields, every running one in captures[] */
            char *cur = out, *end = out + sizeof out - 2; ULONGLONG now = now_ft(); char p[1200]; EnterCriticalSection(&g_zlock);
            int n = 0, newest = -1; for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f) { n++; if (newest < 0 || g_caps[k].started > g_caps[newest].started) newest = k; }
            const Cap *t = newest >= 0 ? &g_caps[newest] : NULL; jw(t ? t->path : L"", p, sizeof p);
            cur += snprintf(cur, end - cur, "{\"reply\":\"capture\",\"active\":%s,\"count\":%d,\"max\":%d,\"pid\":%lu,\"path\":\"%s\",\"packets\":%llu,\"bytes\":%llu,\"seconds_left\":%lld,\"captures\":[", t ? "true" : "false", n, MAX_CAPS, t ? (unsigned long)t->pid : 0UL, p, t ? (unsigned long long)t->pkts : 0ULL, t ? (unsigned long long)t->bytes : 0ULL, t ? (long long)(t->until - now) / 10000000LL : 0LL);
            int first = 1; for (int k = 0; k < MAX_CAPS; k++) if (g_caps[k].f) { jw(g_caps[k].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"pid\":%lu,\"path\":\"%s\",\"packets\":%llu,\"bytes\":%llu,\"seconds_left\":%lld}", first ? "" : ",", (unsigned long)g_caps[k].pid, p, (unsigned long long)g_caps[k].pkts, (unsigned long long)g_caps[k].bytes, (long long)(g_caps[k].until - now) / 10000000LL); first = 0; }
            LeaveCriticalSection(&g_zlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, out); return; }
        DWORD pid = !strcmp(arg1, "all") ? 0 : (DWORD)strtoul(arg1, NULL, 10); if (!pid && strcmp(arg1, "all")) { send_line(ci, "{\"reply\":\"error\",\"error\":\"usage: capture <pid|all> [seconds] [file.pcapng] | capture stop\"}"); return; }
        int secs = 30; char fileu[1200] = ""; if (line[0] == '{') { char s[32]; if (json_get_str(line, "seconds", s, sizeof s)) secs = atoi(s); json_get_str(line, "path", fileu, sizeof fileu); if (!strcmp(fileu, arg1)) fileu[0] = 0; } else if (arg2[0]) { secs = atoi(arg2); char *sp = strchr(arg2, ' '); if (sp) { while (*sp == ' ') sp++; strncpy(fileu, sp, sizeof fileu - 1); } if (secs <= 0) { secs = 30; if (!sp) strncpy(fileu, arg2, sizeof fileu - 1); } }
        wchar_t path[MAX_PATH]; if (fileu[0]) { to_wide(fileu, path, MAX_PATH); if (!wcschr(path, L'\\') && !wcschr(path, L'/')) { wchar_t tmp[MAX_PATH]; _snwprintf(tmp, MAX_PATH, L"%ls\\%ls", g_exe_dir, path); wcscpy(path, tmp); } } else { SYSTEMTIME st; GetLocalTime(&st); _snwprintf(path, MAX_PATH, L"%ls\\capture_%lu_%02d%02d%02d.pcapng", g_exe_dir, (unsigned long)pid, st.wHour, st.wMinute, st.wSecond); }
        char err[300] = ""; int ok = cap_start(pid, secs, path, err, sizeof err); char p[1200], e[600]; jw(path, p, sizeof p); json_escape(err, e, sizeof e);
        snprintf(out, sizeof out, "{\"reply\":\"capture\",\"ok\":%s,\"pid\":%lu,\"seconds\":%d,\"path\":\"%s\",\"error\":\"%s\",\"note\":\"a 'capture' event follows when the file is closed\"}", ok ? "true" : "false", (unsigned long)pid, secs, p, e); send_line(ci, out);
    }
    else if (!strcmp(cmd, "zoom")) { EnterCriticalSection(&g_zlock); int caps = cap_active_locked(); char *cur = out, *end = out + sizeof out - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"zoom\",\"state\":\"%s\",\"error\":%lu,\"frames\":%lld,\"bytes\":%lld,\"matched\":%lld,\"unmatched\":%lld,\"capture_active\":%s,\"captures\":%d,\"all\":%s,\"interest\":[", zoom_state_str(), (unsigned long)g_zoom_err, (long long)g_zoom_frames, (long long)g_zoom_bytes, (long long)g_zoom_matched, (long long)g_zoom_unmatched, caps ? "true" : "false", caps, g_zoom_all ? "true" : "false"); for (int i = 0; i < g_nzoom; i++) cur += snprintf(cur, end - cur, "%s%lu", i ? "," : "", (unsigned long)g_zoom_pids[i]); LeaveCriticalSection(&g_zlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, out); }
    else if (!strcmp(cmd, "audit")) { if (!strcmp(arg1, "on")) { int ok = audit_enable(); InterlockedExchange(&g_audit_ok, audit_query()); snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"set_ok\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", ok ? "true" : "false", g_audit_auto ? "true" : "false"); } else if (!strcmp(arg1, "auto")) { g_audit_auto = strcmp(arg2, "off") != 0; snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", g_audit_auto ? "true" : "false"); } else { InterlockedExchange(&g_audit_ok, audit_query()); snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", g_audit_auto ? "true" : "false"); } send_line(ci, out); }
    else if (!strcmp(cmd, "threshold")) { double tx = atof(arg1), rx = atof(arg2); if (tx > 0) g_tx_thresh = tx; if (rx > 0) g_rx_thresh = rx; snprintf(out, sizeof out, "{\"reply\":\"threshold\",\"tx_mbps\":%.2f,\"rx_mbps\":%.2f}", g_tx_thresh, g_rx_thresh); send_line(ci, out); }
    else if (!strcmp(cmd, "local")) { InterlockedExchange(&g_include_local, !strcmp(arg1, "on")); if (g_main) InvalidateRect(g_main, NULL, TRUE); snprintf(out, sizeof out, "{\"reply\":\"local\",\"include_local\":%s}", g_include_local ? "true" : "false"); send_line(ci, out); }
    else if (!strcmp(cmd, "pause")) { InterlockedExchange(&g_paused, strcmp(arg1, "off") != 0); snprintf(out, sizeof out, "{\"reply\":\"pause\",\"paused\":%s}", g_paused ? "true" : "false"); send_line(ci, out); }
    else if (!strcmp(cmd, "reset")) { EnterCriticalSection(&g_lock); memset(g_procs, 0, sizeof g_procs); memset(g_pidx, 0, sizeof g_pidx); memset(g_conns, 0, sizeof g_conns); memset(g_chash, 0, sizeof g_chash); g_tx_total = g_rx_total = 0; LeaveCriticalSection(&g_lock); send_line(ci, "{\"reply\":\"reset\",\"ok\":true}"); }
    else if (!strcmp(cmd, "show")) { if (g_main) PostMessageW(g_main, WM_SHOWME, 0, 0); send_line(ci, "{\"reply\":\"show\",\"ok\":true}"); }
    else if (!strcmp(cmd, "help")) send_line(ci, "{\"reply\":\"help\",\"commands\":[\"status\",\"whoami\",\"clients\",\"list\",\"inspect <pid> [show]\",\"conns [pid|all] [active] [since <now>] [cursor <n>] [limit <n>]\",\"watch <pid|all> [packets|handshakes|nopackets|off]\",\"watch packets|handshakes|nopackets\",\"watch off\",\"capture <pid|all> [seconds] [file.pcapng]\",\"capture stop [pid|all]\",\"capture\",\"zoom\",\"kill <pid>\",\"block <pid|path>\",\"unblock <pid|path>\",\"blocks\",\"trust [list|remove <substr>|clear]\",\"denials\",\"pardon <path-substr>\",\"history [minutes]\",\"snap [file.bmp] [pid]\",\"resolve <ip>\",\"audit [on|status|auto on|auto off]\",\"threshold <tx_mbps> [rx_mbps]\",\"local on|off\",\"pause on|off\",\"reset\",\"show\",\"help\"],\"events\":[\"hello\",\"auth\",\"tick\",\"spike\",\"conn\",\"flow\",\"flowinfo\",\"pkt\",\"trace\",\"capture\",\"killed\",\"blocked\",\"unblocked\",\"intruder\",\"audit\",\"snap\",\"client\"],\"json_form\":\"{\\\"cmd\\\":\\\"kill\\\",\\\"pid\\\":123}\"}");
    else { char cesc[80]; json_escape(cmd, cesc, sizeof cesc); snprintf(out, sizeof out, "{\"reply\":\"error\",\"error\":\"unknown command '%s' (try help)\"}", cesc); send_line(ci, out); }
}
/* Commands run on CMD_WORKERS threads so a slow one (inspect takes up to a second) never stalls other clients. One command per client runs at a
   time and the queue is served in arrival order, so each client's replies come back in the order it sent its commands. */
static void job_push(int ci, DWORD gen, const char *line) {
    EnterCriticalSection(&g_jlock); int slot = -1; for (int i = 0; i < JOB_RING; i++) if (!g_jobs[i].used) { slot = i; break; }
    if (slot >= 0) { Job *j = &g_jobs[slot]; j->used = 1; j->ci = ci; j->gen = gen; j->seq = ++g_job_seq; strncpy(j->line, line, CLIENT_LINE_MAX - 1); j->line[CLIENT_LINE_MAX - 1] = 0; WakeConditionVariable(&g_jcv); }
    LeaveCriticalSection(&g_jlock);
    if (slot < 0) send_line(ci, "{\"reply\":\"error\",\"error\":\"command queue full, try again\"}");
}
static DWORD WINAPI cmd_worker(LPVOID a) {
    (void)a; char *big = (char *)malloc(CMD_BIG); if (!big) return 0; static Job cur[CMD_WORKERS]; static volatile LONG next_slot; Job *j = &cur[InterlockedIncrement(&next_slot) - 1];   /* each worker owns one 4 KB job copy */
    for (;;) {
        EnterCriticalSection(&g_jlock); int pick;
        for (;;) { ULONGLONG best = ~0ULL; pick = -1; for (int i = 0; i < JOB_RING; i++) if (g_jobs[i].used && !g_cmd_busy[g_jobs[i].ci] && g_jobs[i].seq < best) { best = g_jobs[i].seq; pick = i; } if (pick >= 0 || g_quitting) break; SleepConditionVariableCS(&g_jcv, &g_jlock, INFINITE); }
        if (pick < 0) { LeaveCriticalSection(&g_jlock); break; }
        *j = g_jobs[pick]; g_jobs[pick].used = 0; g_cmd_busy[j->ci] = 1; LeaveCriticalSection(&g_jlock);
        int live; EnterCriticalSection(&g_clock); live = g_clients[j->ci].s != INVALID_SOCKET && g_clients[j->ci].gen == j->gen && g_clients[j->ci].state == 2; LeaveCriticalSection(&g_clock);
        if (live) handle_command(j->ci, j->line, big, CMD_BIG);
        EnterCriticalSection(&g_jlock); g_cmd_busy[j->ci] = 0; WakeAllConditionVariable(&g_jcv); LeaveCriticalSection(&g_jlock);
    }
    free(big); return 0;
}
static DWORD WINAPI sock_thread(LPVOID a) {
    (void)a; for (int i = 0; i < MAX_CLIENTS; i++) g_clients[i].s = INVALID_SOCKET;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (ls == INVALID_SOCKET) return 0;
    BOOL yes = TRUE; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((u_short)g_port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 8)) { closesocket(ls); return 0; }
    u_long nb = 1; ioctlsocket(ls, FIONBIO, &nb);
    char hello[600]; snprintf(hello, sizeof hello, "{\"ev\":\"hello\",\"app\":\"Hodometer\",\"version\":\"%s\",\"port\":%d,\"note\":\"JSON lines. Send 'help' for commands. Ticks every second.\"}", APP_VERSION, g_port);
    while (!g_quitting) {
        fd_set rf, wf; FD_ZERO(&rf); FD_ZERO(&wf); FD_SET(ls, &rf); SOCKET mx = ls;
        EnterCriticalSection(&g_clock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            Client *c = &g_clients[i]; if (c->s == INVALID_SOCKET) continue;
            if (c->overflow) { char nm[200]; jw(c->name, nm, sizeof nm); char l[300]; snprintf(l, sizeof l, "{\"ev\":\"client\",\"status\":\"dropped\",\"why\":\"slow consumer (512 KB unread)\",\"pid\":%lu,\"name\":\"%s\"}", (unsigned long)c->pid, nm); log_json(l); client_drop(i); continue; }
            if (c->state == 3) { const char *d = "{\"ev\":\"auth\",\"status\":\"denied\"}\n"; send(c->s, d, (int)strlen(d), 0); client_drop(i); continue; }
            if (c->state == 2 && !c->greeted) { c->greeted = 1; send_line(i, hello); char nm[200]; jw(c->name, nm, sizeof nm); char l[400]; snprintf(l, sizeof l, "{\"ev\":\"auth\",\"status\":\"allowed\",\"pid\":%lu,\"name\":\"%s\",\"remembered\":%s}", (unsigned long)c->pid, nm, c->once ? "false" : "true"); send_line(i, l); }
            if (c->state == 1 && c->outlen) flush_client(i);   /* pending clients only ever get the 'pending' line */
            FD_SET(c->s, &rf); if (c->outlen) FD_SET(c->s, &wf); if (c->s > mx) mx = c->s;
        }
        LeaveCriticalSection(&g_clock);
        struct timeval tv = { 0, 300000 }; int r = select((int)mx + 1, &rf, &wf, NULL, &tv); if (r <= 0) continue;
        EnterCriticalSection(&g_clock); for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s != INVALID_SOCKET && FD_ISSET(g_clients[i].s, &wf)) flush_client(i); LeaveCriticalSection(&g_clock);
        if (FD_ISSET(ls, &rf)) {
            SOCKET c = accept(ls, NULL, NULL);
            if (c != INVALID_SOCKET) {
                ioctlsocket(c, FIONBIO, &nb);
                DWORD pid = peer_pid(c); wchar_t path[MAX_PATH] = L""; char sha[65] = ""; if (pid) pid_path(pid, path, MAX_PATH); if (path[0]) sha256_file(path, sha);
                ULONGLONG now = GetTickCount64(); int decision = 1; const char *why = "";   /* 1 ask, 2 allow, 3 deny */
                EnterCriticalSection(&g_tlock);
                if (path[0] && sha[0] && trust_check(path, sha)) decision = 2;
                else { Deny *d = deny_find(path[0] ? path : L"(unknown)", 0); if (d && d->blocked) { decision = 3; why = "blocked"; } else if (d && now - d->last < 600000) { decision = 3; why = "cooldown"; } else if (now < g_auth_suspended_until) { decision = 3; why = "prompts suspended"; } else if (!path[0]) { decision = 3; why = "unidentified client"; } }
                LeaveCriticalSection(&g_tlock);
                if (decision == 1) { g_attempts[g_attempt_i++ % 32] = now; if (attempts_recent() > 10) { g_auth_suspended_until = now + 300000; decision = 3; why = "flood"; log_json("{\"ev\":\"auth\",\"status\":\"suspended\",\"why\":\"more than 10 connection attempts in 60 s\"}"); tray_balloon(L"Hodometer: connection flood", L"More than 10 programs asked for control within a minute. Prompts are suspended for 5 minutes; all new unknown clients are denied.", 1); } }
                int placed = -1;
                EnterCriticalSection(&g_clock);
                for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s == INVALID_SOCKET && !g_cmd_busy[i]) { Client *cl = &g_clients[i]; memset(cl, 0, sizeof *cl); cl->s = c; cl->gen = ++g_client_gen; cl->since = now; cl->pid = pid; cl->ppid = parent_pid(pid); wcscpy(cl->path, path); wcsncpy(cl->name, path[0] ? basename_w(path) : L"(unknown)", 63); strcpy(cl->sha, sha); cl->state = decision == 2 ? 2 : decision == 3 ? 3 : 1; placed = i; break; }
                LeaveCriticalSection(&g_clock);
                if (placed < 0) closesocket(c);
                else if (decision == 3) { if (path[0]) deny_record(path, why); else { char l[200]; snprintf(l, sizeof l, "{\"ev\":\"auth\",\"status\":\"denied\",\"why\":\"%s\"}", why); log_json(l); } }
                else if (decision == 1) { send_line(placed, "{\"ev\":\"auth\",\"status\":\"pending\",\"note\":\"waiting for the user to allow this program in Hodometer\"}"); EnterCriticalSection(&g_clock); flush_client(placed); LeaveCriticalSection(&g_clock); char nm[200]; jw(basename_w(path), nm, sizeof nm); char l[400]; snprintf(l, sizeof l, "{\"ev\":\"auth\",\"status\":\"asking\",\"pid\":%lu,\"name\":\"%s\"}", (unsigned long)pid, nm); log_json(l); PostMessageW(g_main, WM_AUTHREQ, (WPARAM)placed, 0); }
            }
        }
        for (int i = 0; i < MAX_CLIENTS; i++) {
            EnterCriticalSection(&g_clock); Client *cl = &g_clients[i]; SOCKET s = cl->s;
            if (s == INVALID_SOCKET || !FD_ISSET(s, &rf)) { LeaveCriticalSection(&g_clock); continue; }
            char tmp[1024]; int n = recv(s, tmp, sizeof tmp, 0);
            if (n <= 0) { client_drop(i); LeaveCriticalSection(&g_clock); continue; }
            static char lines[16][CLIENT_LINE_MAX]; int nl = 0, allowed = cl->state == 2; DWORD gen = cl->gen;
            for (int k = 0; k < n; k++) { char ch = tmp[k]; if (ch == '\n') { cl->buf[cl->len] = 0; if (nl < 16) strcpy(lines[nl++], cl->buf); cl->len = 0; } else if (cl->len < CLIENT_LINE_MAX - 1) cl->buf[cl->len++] = ch; else cl->len = 0; }
            LeaveCriticalSection(&g_clock);
            for (int k = 0; k < nl; k++) { if (allowed) job_push(i, gen, lines[k]); else send_line(i, "{\"reply\":\"error\",\"error\":\"not allowed yet\"}"); }   /* commands run on the worker threads, never on this one */
        }
    }
    closesocket(ls); return 0;
}

/* ------------------------------------------------------------------ Security 5156 subscription ------------------------------------------------------------------ */
typedef HANDLE MY_EVT_HANDLE; typedef DWORD (WINAPI *MY_EVT_SUBSCRIBE_CALLBACK)(int, PVOID, MY_EVT_HANDLE);
typedef MY_EVT_HANDLE (WINAPI *PFN_EvtSubscribe)(MY_EVT_HANDLE, HANDLE, LPCWSTR, LPCWSTR, MY_EVT_HANDLE, PVOID, MY_EVT_SUBSCRIBE_CALLBACK, DWORD); typedef BOOL (WINAPI *PFN_EvtRender)(MY_EVT_HANDLE, MY_EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
static PFN_EvtRender pEvtRender; static MY_EVT_HANDLE g_sub;
static int xml_data(const wchar_t *xml, const wchar_t *name, wchar_t *out, int n) { wchar_t pat[96]; _snwprintf(pat, 96, L"Name='%ls'>", name); const wchar_t *p = wcsstr(xml, pat); if (!p) return 0; p += wcslen(pat); int o = 0; while (*p && *p != L'<' && o < n - 1) out[o++] = *p++; out[o] = 0; return 1; }
static DWORD WINAPI on_security_event(int action, PVOID ctx, MY_EVT_HANDLE ev) {
    (void)ctx; if (action != 1 || !pEvtRender) return 0;
    static __thread wchar_t xml[16384]; DWORD used = 0, props = 0; if (!pEvtRender(NULL, ev, 1, sizeof xml, xml, &used, &props)) return 0;
    wchar_t dir[32], app[600], dst[64], port[16], pidw[16], proto[8];
    if (!xml_data(xml, L"Direction", dir, 32) || wcscmp(dir, L"%%14593")) return 0;
    if (!xml_data(xml, L"DestAddress", dst, 64)) return 0;
    char dsta[64]; to_utf8(dst, dsta, sizeof dsta); if (is_local_str(dsta) && !g_include_local) return 0;
    if (InterlockedIncrement(&g_conn_this_sec) > 300) return 0;
    xml_data(xml, L"Application", app, 600); xml_data(xml, L"DestPort", port, 16); xml_data(xml, L"Protocol", proto, 8); if (!xml_data(xml, L"ProcessId", pidw, 16)) xml_data(xml, L"ProcessID", pidw, 16);
    char appe[2400], basee[512], hostu[300] = ""; jw(app, appe, sizeof appe); jw(basename_w(app), basee, sizeof basee); wchar_t h[128]; if (host_lookup(dsta, h, 128)) jw(h, hostu, sizeof hostu);
    char line[3600]; snprintf(line, sizeof line, "{\"ev\":\"conn\",\"pid\":%ls,\"app\":\"%s\",\"path\":\"%s\",\"dst\":\"%s\",\"host\":\"%s\",\"port\":%ls,\"proto\":%ls}", pidw[0] ? pidw : L"0", basee, appe, dsta, hostu, port[0] ? port : L"0", proto[0] ? proto : L"0");
    g_conn_events++; bcast(line); return 0;
}
static void security_subscribe(void) { HMODULE m = LoadLibraryW(L"wevtapi.dll"); if (!m) return; PFN_EvtSubscribe pSub = (PFN_EvtSubscribe)GetProcAddress(m, "EvtSubscribe"); pEvtRender = (PFN_EvtRender)GetProcAddress(m, "EvtRender"); if (!pSub || !pEvtRender) return; g_sub = pSub(NULL, NULL, L"Security", L"*[System[(EventID=5156)]]", NULL, NULL, on_security_event, 1); }

/* ------------------------------------------------------------------ UI: drawing helpers ------------------------------------------------------------------ */
static void card(HDC dc, int W, int H) { RECT rc = { 0, 0, W, H }; HBRUSH bg = CreateSolidBrush(C_BG); FillRect(dc, &rc, bg); DeleteObject(bg); HBRUSH pb = CreateSolidBrush(C_PANEL); HPEN pp = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ ob = SelectObject(dc, pb), op = SelectObject(dc, pp); RoundRect(dc, 0, 0, W, H, 14, 14); SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(pb); DeleteObject(pp); }
/* Windows' dark-mode switch for common controls (uxtheme ordinals 135 SetPreferredAppMode, 133 AllowDarkModeForWindow, 136 FlushMenuThemes; Windows 10 1809+).
   Together with the DarkMode_Explorer theme it gives dark scrollbars on list views and dark popup menus. */
static void dark_mode_init(void) {
    HMODULE ux = LoadLibraryW(L"uxtheme.dll"); if (!ux) return;
    typedef int (WINAPI *PFN_SPAM)(int); PFN_SPAM spam = (PFN_SPAM)GetProcAddress(ux, MAKEINTRESOURCEA(135)); if (spam) spam(1 /* AllowDark */);
    typedef void (WINAPI *PFN_V)(void); PFN_V rics = (PFN_V)GetProcAddress(ux, MAKEINTRESOURCEA(104)); if (rics) rics(); PFN_V fmt = (PFN_V)GetProcAddress(ux, MAKEINTRESOURCEA(136)); if (fmt) fmt();
}
static void dark_mode_window(HWND h) {
    HMODULE ux = GetModuleHandleW(L"uxtheme.dll"); if (!ux) ux = LoadLibraryW(L"uxtheme.dll"); if (!ux) return;
    typedef BOOL (WINAPI *PFN_ADW)(HWND, BOOL); PFN_ADW adw = (PFN_ADW)GetProcAddress(ux, MAKEINTRESOURCEA(133)); if (adw) adw(h, TRUE);
    typedef HRESULT (WINAPI *PFN_SWT)(HWND, LPCWSTR, LPCWSTR); PFN_SWT swt = (PFN_SWT)GetProcAddress(ux, "SetWindowTheme"); if (swt) swt(h, L"DarkMode_Explorer", NULL);
    SendMessageW(h, WM_THEMECHANGED, 0, 0);
}
static void list_fill_last(HWND lv, int ncols, int minw) {   /* the last column takes whatever width is left, so nothing hides behind a horizontal scrollbar */
    RECT rc; GetClientRect(lv, &rc); int used = 0; for (int i = 0; i < ncols - 1; i++) used += ListView_GetColumnWidth(lv, i); int w = rc.right - used - 4; if (w < minw) w = minw; if (ListView_GetColumnWidth(lv, ncols - 1) != w) ListView_SetColumnWidth(lv, ncols - 1, w);
}
static LRESULT CALLBACK BtnSubclass(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref) {   /* hover tracking for owner-drawn buttons */
    (void)id; (void)ref;
    if (m == WM_MOUSEMOVE) { LONG_PTR d = GetWindowLongPtrW(h, GWLP_USERDATA); if (!(d & 0x100)) { SetWindowLongPtrW(h, GWLP_USERDATA, d | 0x100); TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 }; TrackMouseEvent(&t); InvalidateRect(h, NULL, TRUE); } }
    else if (m == WM_MOUSELEAVE) { LONG_PTR d = GetWindowLongPtrW(h, GWLP_USERDATA); SetWindowLongPtrW(h, GWLP_USERDATA, d & ~(LONG_PTR)0x100); InvalidateRect(h, NULL, TRUE); }
    return DefSubclassProc(h, m, w, l);
}
static void draw_button(DRAWITEMSTRUCT *di) {
    LONG_PTR data = GetWindowLongPtrW(di->hwndItem, GWLP_USERDATA); int kind = (int)(data & 0xff), hot = (data & 0x100) != 0, sel = (data & 0x200) != 0;   /* kind: 0 normal, 1 danger, 2 toggle, 3 tab (0x200 = selected) */
    int pressed = di->itemState & ODS_SELECTED, disabled = di->itemState & ODS_DISABLED, focus = di->itemState & ODS_FOCUS;
    HDC dc = di->hDC; RECT r = di->rcItem;
    COLORREF accent = kind == 1 ? C_RED : C_BLUE;
    COLORREF fill = pressed ? RGB(38, 41, 52) : hot ? RGB(40, 44, 56) : C_CELL, border = (focus || hot) ? accent : C_BORDER, text = disabled ? C_MUTED : (kind == 1 ? C_RED : C_TEXT);
    if (kind == 2 && g_include_local) { fill = RGB(34, 52, 44); border = C_GREEN; }
    if (kind == 3) { if (sel) { fill = RGB(36, 50, 72); border = C_BLUE; text = C_TEXT; } else if (!hot) text = C_MUTED; }
    { HBRUSH bgb = CreateSolidBrush(C_BG); FillRect(dc, &r, bgb); DeleteObject(bgb); }   /* corners outside the rounded rect take the window colour, not the control default */
    HBRUSH b = CreateSolidBrush(fill); HPEN p = CreatePen(PS_SOLID, 1, border); HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p);
    RoundRect(dc, r.left, r.top, r.right, r.bottom, 8, 8); SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(b); DeleteObject(p);
    wchar_t t[128]; GetWindowTextW(di->hwndItem, t, 128); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, text); SelectObject(dc, g_font);
    if (kind == 2) { RECT box = { r.left + 10, (r.top + r.bottom) / 2 - 7, r.left + 24, (r.top + r.bottom) / 2 + 7 }; HBRUSH bb = CreateSolidBrush(g_include_local ? C_GREEN : C_PANEL); HPEN bp = CreatePen(PS_SOLID, 1, g_include_local ? C_GREEN : C_MUTED); ob = SelectObject(dc, bb); op = SelectObject(dc, bp); RoundRect(dc, box.left, box.top, box.right, box.bottom, 3, 3); SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(bb); DeleteObject(bp); r.left += 30; DrawTextW(dc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE); }
    else DrawTextW(dc, t, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}
static HWND mk_button(HWND parent, int id, const wchar_t *text, int kind) { HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, g_inst, NULL); SetWindowLongPtrW(b, GWLP_USERDATA, kind); SendMessageW(b, WM_SETFONT, (WPARAM)g_font, 1); SetWindowSubclass(b, BtnSubclass, 2, 0); return b; }
static void dot(HDC dc, int x, int y, COLORREF c) { HBRUSH b = CreateSolidBrush(c); HPEN p = CreatePen(PS_SOLID, 1, c); HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p); Ellipse(dc, x - 5, y - 5, x + 5, y + 5); SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(b); DeleteObject(p); }

/* ------------------------------------------------------------------ odometer ------------------------------------------------------------------ */
typedef struct { double shown, target, rate; int digits; wchar_t label[48]; HFONT fdig; COLORREF accent; } Odo;
static LRESULT CALLBACK OdoProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Odo *o = (Odo *)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_NCCREATE: { o = (Odo *)calloc(1, sizeof *o); o->digits = 12; CREATESTRUCTW *cs = (CREATESTRUCTW *)l; if (cs->lpCreateParams) wcsncpy(o->label, (const wchar_t *)cs->lpCreateParams, 47); o->fdig = CreateFontW(-34, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"); o->accent = C_GREEN; SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)o); return TRUE; }
    case WM_CREATE: SetTimer(h, 1, 33, NULL); return 0;
    case WM_ODO_SET: { uint64_t *v = (uint64_t *)w; o->target = (double)*v; o->rate = *(double *)l; return 0; }
    case WM_TIMER: { double d = o->target - o->shown; if (fabs(d) > 0.5) { o->shown += d * 0.22; InvalidateRect(h, NULL, FALSE); } else if (o->shown != o->target) { o->shown = o->target; InvalidateRect(h, NULL, FALSE); } return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc); int W = rc.right, H = rc.bottom;
        HDC mdc = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, W, H); HGDIOBJ ob = SelectObject(mdc, bmp);
        card(mdc, W, H); SetBkMode(mdc, TRANSPARENT);
        SelectObject(mdc, g_font_small); SetTextColor(mdc, C_MUTED); RECT lr = { 14, 6, 300, 24 }; DrawTextW(mdc, o->label, -1, &lr, DT_LEFT | DT_SINGLELINE);
        int cw = 28, chh = 42, gap = 3, top = 26, x = 14; SelectObject(mdc, o->fdig);
        HBRUSH cell = CreateSolidBrush(C_CELL); HPEN edge = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ op = SelectObject(mdc, edge), obr = SelectObject(mdc, cell);
        double v = o->shown < 0 ? 0 : o->shown;
        for (int i = 0; i < o->digits; i++) {
            int power = o->digits - 1 - i; double pos = fmod(v / pow(10.0, power), 10.0); int d = (int)floor(pos); double f = pos - d; if (d > 9) d = 9;
            int leading = (v < pow(10.0, power)) && power > 0; RECT cr = { x, top, x + cw, top + chh };
            RoundRect(mdc, cr.left, cr.top, cr.right, cr.bottom, 5, 5);
            if (!leading) { SaveDC(mdc); IntersectClipRect(mdc, cr.left + 1, cr.top + 1, cr.right - 1, cr.bottom - 1); SetTextColor(mdc, C_TEXT); wchar_t s1[2] = { (wchar_t)(L'0' + d), 0 }, s2[2] = { (wchar_t)(L'0' + (d + 1) % 10), 0 }; int dy = (int)(f * chh); RECT r1 = { cr.left, cr.top - dy, cr.right, cr.bottom - dy }; DrawTextW(mdc, s1, 1, &r1, DT_CENTER | DT_VCENTER | DT_SINGLELINE); RECT r2 = { cr.left, cr.top + chh - dy, cr.right, cr.bottom + chh - dy }; DrawTextW(mdc, s2, 1, &r2, DT_CENTER | DT_VCENTER | DT_SINGLELINE); RestoreDC(mdc, -1); }
            else { SetTextColor(mdc, RGB(60, 63, 72)); DrawTextW(mdc, L"0", 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE); }
            x += cw + gap; if (power % 3 == 0 && power) x += 6;
        }
        HPEN hl = CreatePen(PS_SOLID, 1, RGB(70, 74, 86)); SelectObject(mdc, hl); MoveToEx(mdc, 14, top + chh / 2, NULL); LineTo(mdc, x - gap, top + chh / 2); SelectObject(mdc, op); DeleteObject(hl); SelectObject(mdc, obr); DeleteObject(cell); DeleteObject(edge);
        SelectObject(mdc, g_font_small); SetTextColor(mdc, C_MUTED); RECT ur = { x + 4, top + chh - 18, x + 60, top + chh }; DrawTextW(mdc, L"bytes", -1, &ur, DT_LEFT | DT_SINGLELINE);
        wchar_t rate[48], tot[48]; fmt_rate_w(o->rate, rate, 48); fmt_bytes_w((uint64_t)o->target, tot, 48);
        HFONT fr = CreateFontW(-22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); SelectObject(mdc, fr); SetTextColor(mdc, o->rate > 0 ? o->accent : C_MUTED);
        RECT rr = { x + 62, top, W - 8, top + chh }; DrawTextW(mdc, rate, -1, &rr, DT_LEFT | DT_VCENTER | DT_SINGLELINE); DeleteObject(fr);
        SelectObject(mdc, g_font_small); SetTextColor(mdc, RGB(110, 114, 124)); RECT tr = { 200, 6, x, 24 }; DrawTextW(mdc, tot, -1, &tr, DT_RIGHT | DT_SINGLELINE);
        BitBlt(dc, 0, 0, W, H, mdc, 0, 0, SRCCOPY); SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc); EndPaint(h, &ps); return 0; }
    case WM_NCDESTROY: if (o) { KillTimer(h, 1); DeleteObject(o->fdig); free(o); } return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
static void odo_set(HWND h, uint64_t v, double rate) { SendMessageW(h, WM_ODO_SET, (WPARAM)&v, (LPARAM)&rate); }

/* ------------------------------------------------------------------ sparkline ------------------------------------------------------------------ */
static LRESULT CALLBACK SparkProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc); int W = rc.right, H = rc.bottom;
        HDC mdc = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, W, H); HGDIOBJ ob = SelectObject(mdc, bmp);
        card(mdc, W, H); SetBkMode(mdc, TRANSPARENT);
        double mx = 10240; for (int i = 0; i < SPARK_N; i++) { if (g_spark_tx[i] > mx) mx = g_spark_tx[i]; if (g_spark_rx[i] > mx) mx = g_spark_rx[i]; }
        int left = 12, right = W - 12, top = 24, bottom = H - 10; double sx = (right - left) / (double)(SPARK_N - 1);
        HPEN grid = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ op = SelectObject(mdc, grid); for (int k = 1; k < 4; k++) { int y = top + (bottom - top) * k / 4; MoveToEx(mdc, left, y, NULL); LineTo(mdc, right, y); } SelectObject(mdc, op); DeleteObject(grid);
        for (int series = 0; series < 2; series++) {
            double *v = series ? g_spark_tx : g_spark_rx; COLORREF col = series ? C_GREEN : C_BLUE; COLORREF fillc = series ? RGB(34, 62, 46) : RGB(34, 48, 70);
            POINT pts[SPARK_N + 2]; int n = 0;
            for (int i = 0; i < SPARK_N; i++) { double val = v[(g_spark_i + i) % SPARK_N]; pts[n].x = left + (int)(i * sx); pts[n].y = bottom - (int)((bottom - top) * (val / mx)); n++; }
            pts[n].x = right; pts[n].y = bottom; n++; pts[n].x = left; pts[n].y = bottom; n++;
            HBRUSH fb = CreateSolidBrush(fillc); HPEN fp = CreatePen(PS_NULL, 0, 0); HGDIOBJ obr = SelectObject(mdc, fb), opp = SelectObject(mdc, fp); Polygon(mdc, pts, n); SelectObject(mdc, obr); SelectObject(mdc, opp); DeleteObject(fb); DeleteObject(fp);
            HPEN lp = CreatePen(PS_SOLID, 2, col); opp = SelectObject(mdc, lp); Polyline(mdc, pts, n - 2); SelectObject(mdc, opp); DeleteObject(lp);
        }
        SelectObject(mdc, g_font_small); SetTextColor(mdc, C_MUTED); wchar_t t[200], mxs[48], txs[48], rxs[48]; fmt_rate_w(mx, mxs, 48); fmt_rate_w(g_tx_rate, txs, 48); fmt_rate_w(g_rx_rate, rxs, 48); _snwprintf(t, 200, L"LAST 5 MINUTES     scale %ls     now  out %ls   in %ls", mxs, txs, rxs); RECT lr = { 14, 5, W - 160, 23 }; DrawTextW(mdc, t, -1, &lr, DT_LEFT | DT_SINGLELINE);
        SetTextColor(mdc, C_GREEN); RECT g1 = { W - 150, 4, W - 80, 22 }; DrawTextW(mdc, L"\x25A0 out", -1, &g1, DT_RIGHT | DT_SINGLELINE); SetTextColor(mdc, C_BLUE); RECT g2 = { W - 76, 4, W - 12, 22 }; DrawTextW(mdc, L"\x25A0 in", -1, &g2, DT_RIGHT | DT_SINGLELINE);
        BitBlt(dc, 0, 0, W, H, mdc, 0, 0, SRCCOPY); SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc); EndPaint(h, &ps); return 0; }
    }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------------ status bar ------------------------------------------------------------------ */
static LRESULT CALLBACK StatusProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc); int W = rc.right, H = rc.bottom;
        HDC mdc = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, W, H); HGDIOBJ ob = SelectObject(mdc, bmp);
        HBRUSH bg = CreateSolidBrush(C_BG); FillRect(mdc, &rc, bg); DeleteObject(bg); SetBkMode(mdc, TRANSPARENT); SelectObject(mdc, g_font);
        int x = 0, y = H / 2; wchar_t t[600];
        #define SEG(color, fmt, ...) do { _snwprintf(t, 600, fmt, __VA_ARGS__); SIZE sz; GetTextExtentPoint32W(mdc, t, (int)wcslen(t), &sz); int pw = sz.cx + 38; HBRUSH pb = CreateSolidBrush(C_PANEL); HPEN pp = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ ob2 = SelectObject(mdc, pb), op2 = SelectObject(mdc, pp); RoundRect(mdc, x, 1, x + pw, H - 1, H - 2, H - 2); SelectObject(mdc, ob2); SelectObject(mdc, op2); DeleteObject(pb); DeleteObject(pp); dot(mdc, x + 14, y, color); SetTextColor(mdc, C_TEXT); RECT r = { x + 26, 0, x + pw, H }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX); x += pw + 8; } while (0)
        SEG(g_etw_state == 1 ? (g_paused ? C_AMBER : C_GREEN) : C_RED, L"Capture %ls", g_etw_state == 1 ? (g_paused ? L"paused" : L"running") : g_etw_state == 0 ? L"starting" : L"ERROR");
        SEG(g_audit_ok == 1 ? C_GREEN : g_audit_ok == 0 ? C_RED : C_AMBER, L"Audit %ls%ls", g_audit_ok == 1 ? L"on" : g_audit_ok == 0 ? L"OFF" : L"unknown", g_audit_auto ? L" (auto-repair)" : L"");
        int nc = client_count(); wchar_t names[300] = L""; EnterCriticalSection(&g_clock); for (int i = 0, k = 0; i < MAX_CLIENTS && k < 4; i++) if (g_clients[i].s != INVALID_SOCKET && g_clients[i].state == 2) { wchar_t one[80]; _snwprintf(one, 80, L"%ls%ls(%lu)", k ? L", " : L": ", g_clients[i].name, (unsigned long)g_clients[i].pid); wcsncat(names, one, 299 - wcslen(names)); k++; } LeaveCriticalSection(&g_clock);
        SEG(nc ? C_BLUE : C_MUTED, L"Socket 127.0.0.1:%d  %d client%ls%ls", g_port, nc, nc == 1 ? L"" : L"s", names);
        if (g_auth_current >= 0 || g_auth_qn) SEG(C_AMBER, L"%d program%ls waiting for your decision", g_auth_qn + (g_auth_current >= 0), (g_auth_qn + (g_auth_current >= 0)) == 1 ? L"" : L"s");
        if (GetTickCount64() < g_auth_suspended_until) SEG(C_RED, L"prompts suspended (flood)%ls", L"");
        SEG(g_include_local ? C_AMBER : C_MUTED, L"Local %ls", g_include_local ? L"shown" : L"hidden");
        SEG(C_MUTED, L"Blocked %d   Trusted %d   5156 events %I64u", g_nblocked, g_ntrust, (unsigned long long)g_conn_events);
        if (g_zoom_state != 0) { int ni = 0; for (int i = 0; i < MAX_INSPECT; i++) if (g_insp_pids[i]) ni++; SEG(g_zoom_state == 2 ? C_GREEN : g_zoom_state == 1 ? C_AMBER : C_RED, L"Zoom %hs   %d inspector%ls   %I64d frames", zoom_state_str(), ni, ni == 1 ? L"" : L"s", (long long)g_zoom_frames); }
        #undef SEG
        BitBlt(dc, 0, 0, W, H, mdc, 0, 0, SRCCOPY); SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc); EndPaint(h, &ps); return 0; }
    }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------------ auth prompt (elevated window: UIPI blocks clicks from lower-integrity processes) ------------------------------------------------------------------ */
static void auth_decide(int ci, int result);   /* 1 always, 2 once, 3 deny */
static void auth_show_next(void);
static LRESULT CALLBACK AuthProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    static int countdown;
    switch (m) {
    case WM_CREATE: { countdown = g_auth_timeout; mk_button(h, IDC_AUTH_ALWAYS, L"Allow always", 0); mk_button(h, IDC_AUTH_ONCE, L"Allow once", 0); mk_button(h, IDC_AUTH_DENY, L"Deny", 1); SetTimer(h, 1, 1000, NULL); return 0; }
    case WM_SIZE: { RECT rc; GetClientRect(h, &rc); int W = rc.right, H = rc.bottom; MoveWindow(GetDlgItem(h, IDC_AUTH_ALWAYS), W - 3 * 150 - 12, H - 46, 140, 34, TRUE); MoveWindow(GetDlgItem(h, IDC_AUTH_ONCE), W - 2 * 150 - 12, H - 46, 140, 34, TRUE); MoveWindow(GetDlgItem(h, IDC_AUTH_DENY), W - 150 - 12, H - 46, 140, 34, TRUE); return 0; }
    case WM_DRAWITEM: draw_button((DRAWITEMSTRUCT *)l); return TRUE;
    case WM_ERASEBKGND: { RECT rc; GetClientRect(h, &rc); HBRUSH b = CreateSolidBrush(C_BG); FillRect((HDC)w, &rc, b); DeleteObject(b); return 1; }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc); SetBkMode(dc, TRANSPARENT);
        Client c; memset(&c, 0, sizeof c); EnterCriticalSection(&g_clock); if (g_auth_current >= 0) c = g_clients[g_auth_current]; LeaveCriticalSection(&g_clock);
        wchar_t ppath[MAX_PATH] = L""; pid_path(c.ppid, ppath, MAX_PATH);
        int y = 16; RECT r;
        SelectObject(dc, g_font_b); SetTextColor(dc, C_AMBER); r = (RECT){ 20, y, rc.right - 20, y + 26 }; DrawTextW(dc, L"A program wants to control Hodometer", -1, &r, DT_LEFT | DT_SINGLELINE); y += 34;
        SelectObject(dc, g_font); SetTextColor(dc, C_TEXT); wchar_t line[1400];
        _snwprintf(line, 1400, L"%ls   (pid %lu)", c.name, (unsigned long)c.pid); r = (RECT){ 20, y, rc.right - 20, y + 22 }; DrawTextW(dc, line, -1, &r, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX); y += 24;
        SetTextColor(dc, C_MUTED); r = (RECT){ 20, y, rc.right - 20, y + 40 }; DrawTextW(dc, c.path, -1, &r, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX | DT_END_ELLIPSIS); y += 44;
        _snwprintf(line, 1400, L"Started by: %ls (pid %lu)", ppath[0] ? basename_w(ppath) : L"unknown", (unsigned long)c.ppid); r = (RECT){ 20, y, rc.right - 20, y + 22 }; DrawTextW(dc, line, -1, &r, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX); y += 22;
        wchar_t shaw[80]; to_wide(c.sha, shaw, 80); shaw[16] = 0; _snwprintf(line, 1400, L"SHA-256: %ls\x2026   (remembered with \"Allow always\"; a changed file asks again)", shaw); r = (RECT){ 20, y, rc.right - 20, y + 22 }; DrawTextW(dc, line, -1, &r, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX); y += 30;
        SetTextColor(dc, C_TEXT); r = (RECT){ 20, y, rc.right - 20, y + 44 }; DrawTextW(dc, L"If allowed it can read all traffic on this computer, kill processes and add firewall rules through Hodometer.", -1, &r, DT_LEFT | DT_WORDBREAK); y += 48;
        SetTextColor(dc, C_RED); _snwprintf(line, 1400, L"Auto-deny in %d s", countdown); r = (RECT){ 20, rc.bottom - 40, 200, rc.bottom - 12 }; DrawTextW(dc, line, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        EndPaint(h, &ps); return 0; }
    case WM_TIMER: {
        int gone = 1; EnterCriticalSection(&g_clock); if (g_auth_current >= 0) gone = !(g_clients[g_auth_current].s != INVALID_SOCKET && g_clients[g_auth_current].state == 1); LeaveCriticalSection(&g_clock);
        if (gone) { log_json("{\"ev\":\"auth\",\"status\":\"abandoned\",\"why\":\"client disconnected before a decision\"}"); DestroyWindow(h); return 0; }   /* no denial recorded for a client that gave up */
        countdown--; if (countdown <= 0) { auth_decide(g_auth_current, 3); DestroyWindow(h); return 0; } InvalidateRect(h, NULL, TRUE); return 0; }
    case WM_COMMAND: if (LOWORD(w) == IDC_AUTH_ALWAYS) { auth_decide(g_auth_current, 1); DestroyWindow(h); } else if (LOWORD(w) == IDC_AUTH_ONCE) { auth_decide(g_auth_current, 2); DestroyWindow(h); } else if (LOWORD(w) == IDC_AUTH_DENY) { auth_decide(g_auth_current, 3); DestroyWindow(h); } return 0;
    case WM_CLOSE: auth_decide(g_auth_current, 3); DestroyWindow(h); return 0;
    case WM_DESTROY: KillTimer(h, 1); g_auth_dlg = NULL; g_auth_current = -1; PostMessageW(g_main, WM_AUTHREQ, (WPARAM)-1, 0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
static void auth_decide(int ci, int result) {
    if (ci < 0) return;
    wchar_t path[MAX_PATH]; char sha[65]; wchar_t name[64];
    EnterCriticalSection(&g_clock); Client *c = &g_clients[ci]; wcscpy(path, c->path); strcpy(sha, c->sha); wcscpy(name, c->name);
    if (c->s != INVALID_SOCKET && c->state == 1) { if (result == 3) c->state = 3; else { c->state = 2; c->once = result == 2; } }
    LeaveCriticalSection(&g_clock);
    char nm[200]; jw(name, nm, sizeof nm); char line[400];
    if (result == 1) { trust_add(path, sha); snprintf(line, sizeof line, "{\"ev\":\"auth\",\"status\":\"allowed\",\"name\":\"%s\",\"remembered\":true}", nm); log_json(line); }
    else if (result == 2) { snprintf(line, sizeof line, "{\"ev\":\"auth\",\"status\":\"allowed\",\"name\":\"%s\",\"remembered\":false}", nm); log_json(line); }
    else deny_record(path, "user denied or timeout");
    if (g_status) InvalidateRect(g_status, NULL, FALSE);
}
/* The prompt is a standard Windows task dialog (the familiar shield dialog), modal on the UI thread; queued prompts follow one at a time. */
static HRESULT CALLBACK auth_td_cb(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LONG_PTR data) {
    (void)lp; (void)data;
    if (msg == TDN_CREATED) { SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SetForegroundWindow(hwnd); FLASHWINFO fi = { sizeof fi, hwnd, FLASHW_ALL | FLASHW_TIMERNOFG, 6, 0 }; FlashWindowEx(&fi); }
    else if (msg == TDN_TIMER) {
        int gone = 1; EnterCriticalSection(&g_clock); if (g_auth_current >= 0) gone = !(g_clients[g_auth_current].s != INVALID_SOCKET && g_clients[g_auth_current].state == 1); LeaveCriticalSection(&g_clock);
        if (gone) { SendMessageW(hwnd, TDM_CLICK_BUTTON, IDCANCEL, 0); return S_OK; }
        int left = g_auth_timeout - (int)(wp / 1000); if (left < 0) left = 0;
        wchar_t f[160]; _snwprintf(f, 160, L"Denied automatically in %d seconds if you do nothing. Hodometer is elevated, so other programs cannot click this for you.", left);
        SendMessageW(hwnd, TDM_UPDATE_ELEMENT_TEXT, TDE_FOOTER, (LPARAM)f);
        if ((int)(wp / 1000) >= g_auth_timeout) SendMessageW(hwnd, TDM_CLICK_BUTTON, IDC_AUTH_DENY, 0);
    }
    return S_OK;
}
static void auth_show_next(void) {
    while (!g_auth_dlg && g_auth_qn > 0) {
        int ci = g_auth_queue[0]; for (int i = 1; i < g_auth_qn; i++) g_auth_queue[i - 1] = g_auth_queue[i]; g_auth_qn--;
        Client c; memset(&c, 0, sizeof c);
        EnterCriticalSection(&g_clock); int valid = g_clients[ci].s != INVALID_SOCKET && g_clients[ci].state == 1; if (valid) c = g_clients[ci]; LeaveCriticalSection(&g_clock);
        if (!valid) continue;
        g_auth_current = ci; g_auth_dlg = (HWND)1;   /* "a prompt is up" while the modal dialog runs */
        if (g_status) InvalidateRect(g_status, NULL, FALSE);
        wchar_t ppath[MAX_PATH] = L""; pid_path(c.ppid, ppath, MAX_PATH);
        wchar_t title[200], content[1800], shaw[80]; to_wide(c.sha, shaw, 80); shaw[16] = 0;
        _snwprintf(title, 200, L"Allow %ls to control Hodometer?", c.name);
        _snwprintf(content, 1800, L"Program:  %ls\nProcess:  %lu, started by %ls (pid %lu)\nFile hash:  SHA-256 %ls\x2026\n\nIf allowed, it can read all network activity on this computer, kill processes and add firewall rules through Hodometer. A program allowed always is remembered by path and file hash; if the file changes it is asked again.", c.path, (unsigned long)c.pid, ppath[0] ? basename_w(ppath) : L"unknown", (unsigned long)c.ppid, shaw);
        TASKDIALOG_BUTTON btns[3] = { { IDC_AUTH_ALWAYS, L"Allow always\nRemember this program (by path and file hash)" }, { IDC_AUTH_ONCE, L"Allow once\nOnly this connection" }, { IDC_AUTH_DENY, L"Deny\nRefuse now, and refuse it silently for the next 10 minutes" } };
        TASKDIALOGCONFIG tc; memset(&tc, 0, sizeof tc); tc.cbSize = sizeof tc; tc.hInstance = g_inst;
        tc.dwFlags = TDF_USE_COMMAND_LINKS | TDF_CALLBACK_TIMER | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT | TDF_POSITION_RELATIVE_TO_WINDOW;
        tc.pszWindowTitle = L"Hodometer"; tc.pszMainIcon = TD_SHIELD_ICON; tc.pszMainInstruction = title; tc.pszContent = content; tc.pszFooterIcon = TD_INFORMATION_ICON; tc.pszFooter = L"Denied automatically if you do nothing."; tc.pButtons = btns; tc.cButtons = 3; tc.nDefaultButton = IDC_AUTH_DENY; tc.pfCallback = auth_td_cb;
        int pressed = 0; HRESULT hr = TaskDialogIndirect(&tc, &pressed, NULL, NULL);
        int gone; EnterCriticalSection(&g_clock); gone = !(g_clients[ci].s != INVALID_SOCKET && g_clients[ci].state == 1); LeaveCriticalSection(&g_clock);
        if (FAILED(hr)) pressed = IDC_AUTH_DENY;
        if (pressed == IDC_AUTH_ALWAYS) auth_decide(ci, 1); else if (pressed == IDC_AUTH_ONCE) auth_decide(ci, 2); else if (gone) log_json("{\"ev\":\"auth\",\"status\":\"abandoned\",\"why\":\"client disconnected before a decision\"}"); else auth_decide(ci, 3);
        g_auth_dlg = NULL; g_auth_current = -1;
        if (g_status) InvalidateRect(g_status, NULL, FALSE);
    }
}

/* ------------------------------------------------------------------ tray ------------------------------------------------------------------ */
static HICON make_icon(int sz) {
    BITMAPV5HEADER bi; memset(&bi, 0, sizeof bi); bi.bV5Size = sizeof bi; bi.bV5Width = sz; bi.bV5Height = -sz; bi.bV5Planes = 1; bi.bV5BitCount = 32; bi.bV5Compression = BI_BITFIELDS; bi.bV5RedMask = 0x00FF0000; bi.bV5GreenMask = 0x0000FF00; bi.bV5BlueMask = 0x000000FF; bi.bV5AlphaMask = 0xFF000000;
    HDC dc = GetDC(NULL); void *bits = NULL; HBITMAP color = CreateDIBSection(dc, (BITMAPINFO *)&bi, DIB_RGB_COLORS, &bits, NULL, 0); ReleaseDC(NULL, dc); HBITMAP mask = CreateBitmap(sz, sz, 1, 1, NULL);
    if (bits) { uint32_t *px = (uint32_t *)bits; double c = (sz - 1) / 2.0, r2 = sz * 0.46, r1 = sz * 0.28; for (int y = 0; y < sz; y++) for (int x = 0; x < sz; x++) { double d = sqrt((x - c) * (x - c) + (y - c) * (y - c)); uint32_t v = 0; if (d <= r2 && d >= r1) v = 0xFF5AC878; else if (d < sz * 0.12) v = 0xFF5AC878; else if (d < r2 + 1 && d > r2) v = 0x60000000; px[y * sz + x] = v; } }
    ICONINFO ii = { TRUE, 0, 0, mask, color }; HICON ic = CreateIconIndirect(&ii); DeleteObject(color); DeleteObject(mask); return ic;
}
static void tray_add(void) { memset(&g_nid, 0, sizeof g_nid); g_nid.cbSize = sizeof g_nid; g_nid.hWnd = g_main; g_nid.uID = 1; g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; g_nid.uCallbackMessage = WM_TRAY; g_nid.hIcon = g_icon_small; wcscpy(g_nid.szTip, L"Hodometer"); Shell_NotifyIconW(NIM_ADD, &g_nid); }
static void tray_tip(void) { wchar_t tx[48], rx[48]; fmt_rate_w(g_tx_rate, tx, 48); fmt_rate_w(g_rx_rate, rx, 48); _snwprintf(g_nid.szTip, 128, L"Hodometer  out %ls  in %ls\naudit %ls, %d client%ls", tx, rx, g_audit_ok == 1 ? L"on" : L"OFF", client_count(), client_count() == 1 ? L"" : L"s"); g_nid.uFlags = NIF_TIP | NIF_ICON; g_nid.hIcon = g_icon_small; Shell_NotifyIconW(NIM_MODIFY, &g_nid); }
static void tray_balloon(const wchar_t *title, const wchar_t *text, int force) { ULONGLONG now = GetTickCount64(); if (!force && now - g_last_balloon < 300000) return; g_last_balloon = now; g_nid.uFlags = NIF_INFO; wcsncpy(g_nid.szInfoTitle, title, 63); wcsncpy(g_nid.szInfo, text, 255); g_nid.dwInfoFlags = NIIF_WARNING; Shell_NotifyIconW(NIM_MODIFY, &g_nid); }
static void tray_menu(void) {
    HMENU m = CreatePopupMenu(); POINT pt; GetCursorPos(&pt);
    AppendMenuW(m, MF_STRING, IDM_SHOW, IsWindowVisible(g_main) ? L"Hide window" : L"Show window"); AppendMenuW(m, MF_STRING | (g_paused ? MF_CHECKED : 0), IDM_PAUSE, L"Pause capture");
    AppendMenuW(m, MF_STRING, IDM_AUDIT, L"Re-enable connection auditing now"); AppendMenuW(m, MF_STRING, IDM_TRUSTCLEAR, L"Forget all trusted programs"); AppendMenuW(m, MF_STRING, IDM_COPYADDR, L"Copy socket address"); AppendMenuW(m, MF_STRING, IDM_LOGDIR, L"Open log folder"); AppendMenuW(m, MF_STRING, IDM_OPENREADME, L"Open README");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL); AppendMenuW(m, MF_STRING, IDM_EXIT, L"Exit Hodometer");
    SetForegroundWindow(g_main); TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_main, NULL); PostMessageW(g_main, WM_NULL, 0, 0); DestroyMenu(m);
}

/* ------------------------------------------------------------------ main window ------------------------------------------------------------------ */
static int cmp_snap(const void *a, const void *b) { const Proc *x = a, *y = b; double rx = x->tx_rate + x->rx_rate, ry = y->tx_rate + y->rx_rate; if (rx != ry) return rx < ry ? 1 : -1; uint64_t tx = x->tx_total + x->rx_total, ty = y->tx_total + y->rx_total; return tx < ty ? 1 : tx > ty ? -1 : 0; }
static void tick(void) {
    EnterCriticalSection(&g_lock);
    g_tx_rate = (double)g_tx_win; g_rx_rate = (double)g_rx_win; g_tx_win = g_rx_win = 0; ULONGLONG now = GetTickCount64();
    for (int i = 0; i < MAX_PROCS; i++) { Proc *p = &g_procs[i]; if (!p->used) continue; p->tx_rate = (double)p->tx_win; p->rx_rate = (double)p->rx_win; p->tx_win = p->rx_win = 0; p->nconn = 0; if (!p->name[0] || (!p->path[0] && now - p->last_alive_check > 5000)) { proc_resolve(p); p->last_alive_check = now; } else if (now - p->last_alive_check > 7000) { p->last_alive_check = now; if (!p->dead && !proc_alive(p->pid)) p->dead = 1; } }
    for (int i = 0; i < MAX_CONNS; i++) {   /* per-connection rates; forget closed flows after 15 min, idle UDP after 10 min, idle TCP after 2 h */
        Conn *c = &g_conns[i]; if (!c->used) continue; c->tx_rate = (double)c->tx_win; c->rx_rate = (double)c->rx_win; c->tx_win = c->rx_win = 0; ULONGLONG idle = now - c->last_seen;
        if (((c->state == 3 || c->state == 4) && idle > 900000) || (c->udp && idle > 600000) || idle > 7200000) { conn_remove(i); continue; }
        if (c->state != 3 && c->state != 4) { Proc *p = proc_find(c->pid); if (p) p->nconn++; }
    }
    SYSTEMTIME st; GetLocalTime(&st); int minute = st.wHour * 60 + st.wMinute; if (g_cur_minute >= 0 && minute != g_cur_minute) history_rotate_minute(); g_cur_minute = minute;
    g_snap_n = 0; for (int i = 0; i < MAX_PROCS; i++) { const Proc *p = &g_procs[i]; if (p->used && (p->tx_total || p->rx_total)) g_snap[g_snap_n++] = *p; }
    LeaveCriticalSection(&g_lock);
    qsort(g_snap, g_snap_n, sizeof(Proc), cmp_snap); InterlockedExchange(&g_conn_this_sec, 0);
    EnterCriticalSection(&g_clock); for (int i = 0; i < MAX_CLIENTS; i++) g_clients[i].pkt_budget = PKT_BUDGET; LeaveCriticalSection(&g_clock);   /* at most PKT_BUDGET pkt events per watcher per second */
    if (InterlockedExchange(&g_watch_dirty, 0)) zoom_recalc();
    cap_expire();
    if (g_zoom_idle_since && g_zoom_state == 2 && now - g_zoom_idle_since > 30000) { int idle; EnterCriticalSection(&g_zlock); idle = g_nzoom == 0 && !g_zoom_all; LeaveCriticalSection(&g_zlock); if (idle) { zoom_stop(); g_zoom_idle_since = 0; } }
    g_spark_tx[g_spark_i] = g_tx_rate; g_spark_rx[g_spark_i] = g_rx_rate; g_spark_i = (g_spark_i + 1) % SPARK_N;
    odo_set(g_odo_tx, g_tx_total, g_tx_rate); odo_set(g_odo_rx, g_rx_total, g_rx_rate);
    ListView_SetItemCountEx(g_list, g_snap_n, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); InvalidateRect(g_list, NULL, FALSE); InvalidateRect(g_spark, NULL, FALSE); InvalidateRect(g_status, NULL, FALSE);
    static char buf[65536];
    if (client_count() > 0) { char *cur = buf, *end = buf + sizeof buf - 2, ts[32]; now_iso(ts, 32); cur += snprintf(cur, end - cur, "{\"ev\":\"tick\",\"t\":\"%s\",\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,\"tx_total\":%llu,\"rx_total\":%llu,\"audit\":\"%s\",\"etw\":\"%s\",\"procs\":[", ts, g_tx_rate / 1048576.0, g_rx_rate / 1048576.0, (unsigned long long)g_tx_total, (unsigned long long)g_rx_total, audit_str(), etw_str()); int shown = 0; for (int i = 0; i < g_snap_n && shown < 25 && end - cur > 3000; i++) { if (g_snap[i].tx_rate == 0 && g_snap[i].rx_rate == 0) break; if (shown++) *cur++ = ','; append_proc_json(&cur, end, &g_snap[i]); } *cur++ = ']'; *cur++ = '}'; *cur = 0; bcast(buf); }
    double txm = g_tx_rate / 1048576.0, rxm = g_rx_rate / 1048576.0; int up = txm >= g_tx_thresh, down = rxm >= g_rx_thresh;
    if ((up && now > g_spike_until_tx) || (down && now > g_spike_until_rx)) { char *cur = buf, *end = buf + sizeof buf - 2; cur += snprintf(cur, end - cur, "{\"ev\":\"spike\",\"kind\":\"%s\",\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,\"top\":[", up ? "upload" : "download", txm, rxm); for (int i = 0, k = 0; i < g_snap_n && k < 6 && end - cur > 3000; i++) { if (g_snap[i].tx_rate == 0 && g_snap[i].rx_rate == 0) break; if (k++) *cur++ = ','; append_proc_json(&cur, end, &g_snap[i]); } *cur++ = ']'; *cur++ = '}'; *cur = 0; bcast(buf); log_json(buf); if (up) { wchar_t t[256]; const Proc *p = g_snap_n ? &g_snap[0] : NULL; _snwprintf(t, 256, L"Upload %.2f MB/s. Top: %ls (pid %lu)", txm, p ? p->name : L"-", p ? (unsigned long)p->pid : 0UL); tray_balloon(L"Hodometer: upload spike", t, 0); } }
    if (up) g_spike_until_tx = now + 10000; if (down) g_spike_until_rx = now + 10000;
}
static void audit_check(int force_log) { int before = g_audit_ok, now = audit_query(); if (now == 0 && g_audit_auto) { audit_enable(); now = audit_query(); if (now == 1) { log_json("{\"ev\":\"audit\",\"action\":\"re-enabled\"}"); bcast("{\"ev\":\"audit\",\"action\":\"re-enabled\",\"enabled\":true}"); } } InterlockedExchange(&g_audit_ok, now); if (now != before || force_log) { char l[128]; snprintf(l, sizeof l, "{\"ev\":\"audit\",\"enabled\":%s}", now == 1 ? "true" : "false"); if (now != before) bcast(l); } if (g_btn_audit) EnableWindow(g_btn_audit, now != 1); if (g_status) InvalidateRect(g_status, NULL, FALSE); }
static int save_window_bmp(HWND h, const wchar_t *path) {
    RECT rc; GetClientRect(h, &rc); int W = rc.right, H = rc.bottom; if (W <= 0 || H <= 0) return 0;
    HDC dc = GetDC(h); HDC mdc = CreateCompatibleDC(dc);
    BITMAPINFO bi; memset(&bi, 0, sizeof bi); bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = W; bi.bmiHeader.biHeight = -H; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    void *bits = NULL; HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0); if (!bmp) { DeleteDC(mdc); ReleaseDC(h, dc); return 0; }
    HGDIOBJ ob = SelectObject(mdc, bmp);
    if (!PrintWindow(h, mdc, PW_CLIENTONLY | PW_RENDERFULLCONTENT)) BitBlt(mdc, 0, 0, W, H, dc, 0, 0, SRCCOPY);
    int ok = 0; FILE *f = _wfopen(path, L"wb");
    if (f) { BITMAPFILEHEADER fh; memset(&fh, 0, sizeof fh); fh.bfType = 0x4D42; fh.bfOffBits = sizeof fh + sizeof bi.bmiHeader; fh.bfSize = fh.bfOffBits + (DWORD)W * H * 4; bi.bmiHeader.biSizeImage = (DWORD)W * H * 4; fwrite(&fh, sizeof fh, 1, f); fwrite(&bi.bmiHeader, sizeof bi.bmiHeader, 1, f); fwrite(bits, (size_t)W * H * 4, 1, f); fclose(f); ok = 1; }
    SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc); ReleaseDC(h, dc); return ok;
}
static void copy_text(const wchar_t *s) { if (!OpenClipboard(g_main)) return; EmptyClipboard(); size_t n = (wcslen(s) + 1) * sizeof(wchar_t); HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n); if (h) { memcpy(GlobalLock(h), s, n); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); } CloseClipboard(); }
static int selected_index(void) { int i = ListView_GetNextItem(g_list, -1, LVNI_SELECTED); return (i >= 0 && i < g_snap_n) ? i : -1; }
static void ui_kill_selected(void) { int i = selected_index(); if (i < 0) return; wchar_t q[400]; _snwprintf(q, 400, L"Kill %ls (pid %lu)?\n\n%ls", g_snap[i].name, (unsigned long)g_snap[i].pid, g_snap[i].path); if (MessageBoxW(g_main, q, L"Hodometer", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return; char err[160] = ""; if (!kill_pid(g_snap[i].pid, err, sizeof err)) { wchar_t e[200]; to_wide(err, e, 200); MessageBoxW(g_main, e, L"Hodometer", MB_OK | MB_ICONERROR); } else { char l[96]; snprintf(l, sizeof l, "{\"ev\":\"killed\",\"pid\":%lu,\"by\":\"ui\"}", (unsigned long)g_snap[i].pid); bcast(l); } }
static void ui_block_selected(int block) { int i = selected_index(); if (i < 0) return; if (!g_snap[i].path[0]) { MessageBoxW(g_main, L"No program path known for this entry.", L"Hodometer", MB_OK | MB_ICONERROR); return; } wchar_t q[500]; _snwprintf(q, 500, L"%ls all network access for\n%ls\n\n%ls", block ? L"Block" : L"Unblock", g_snap[i].name, g_snap[i].path); if (MessageBoxW(g_main, q, L"Hodometer", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return; char err[160] = ""; if (!fw_block(g_snap[i].path, block, err, sizeof err)) { wchar_t e[200]; to_wide(err, e, 200); MessageBoxW(g_main, e, L"Hodometer", MB_OK | MB_ICONERROR); } else { char p[1200]; jw(g_snap[i].path, p, sizeof p); char l[1400]; snprintf(l, sizeof l, "{\"ev\":\"%s\",\"path\":\"%s\",\"by\":\"ui\"}", block ? "blocked" : "unblocked", p); bcast(l); } }
static void layout(void) {
    RECT rc; GetClientRect(g_main, &rc); int W = rc.right, H = rc.bottom; int odoW = 600, bx = odoW + 24, bw = (W - bx - 8 - 8) / 2; if (bw < 150) bw = 150;
    MoveWindow(g_odo_tx, 8, 8, odoW, 76, TRUE); MoveWindow(g_odo_rx, 8, 90, odoW, 76, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_INSPECT), bx, 10, 2 * bw + 8, 30, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_KILL), bx, 48, bw, 30, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_BLOCK), bx + bw + 8, 48, bw, 30, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_AUDIT), bx, 86, bw, 30, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_LOCAL), bx + bw + 8, 86, bw, 30, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_COPY), bx, 124, bw, 30, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_HIDE), bx + bw + 8, 124, bw, 30, TRUE);
    MoveWindow(g_spark, 8, 174, W - 16, 86, TRUE); MoveWindow(g_status, 8, 266, W - 16, 30, TRUE); MoveWindow(g_list, 8, 304, W - 16, H - 312, TRUE); list_fill_last(g_list, 8, 260);
}
static LRESULT CALLBACK ListSubclass(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref) {
    (void)id; (void)ref;
    if (m == WM_NOTIFY) { NMHDR *nm = (NMHDR *)l; if (nm->hwndFrom == ListView_GetHeader(h) && nm->code == NM_CUSTOMDRAW) { NMCUSTOMDRAW *cd = (NMCUSTOMDRAW *)l; if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW; if (cd->dwDrawStage == CDDS_ITEMPREPAINT) { HBRUSH b = CreateSolidBrush(C_PANEL); FillRect(cd->hdc, &cd->rc, b); DeleteObject(b); wchar_t t[64] = L""; HDITEMW hi = { 0 }; hi.mask = HDI_TEXT | HDI_FORMAT; hi.pszText = t; hi.cchTextMax = 64; Header_GetItem(nm->hwndFrom, (int)cd->dwItemSpec, &hi); SetBkMode(cd->hdc, TRANSPARENT); SetTextColor(cd->hdc, C_MUTED); SelectObject(cd->hdc, g_font_b); RECT r = cd->rc; r.left += 8; r.right -= 8; DrawTextW(cd->hdc, t, -1, &r, ((hi.fmt & HDF_RIGHT) ? DT_RIGHT : DT_LEFT) | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS); HPEN p = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ op = SelectObject(cd->hdc, p); MoveToEx(cd->hdc, cd->rc.right - 1, cd->rc.top, NULL); LineTo(cd->hdc, cd->rc.right - 1, cd->rc.bottom); MoveToEx(cd->hdc, cd->rc.left, cd->rc.bottom - 1, NULL); LineTo(cd->hdc, cd->rc.right, cd->rc.bottom - 1); SelectObject(cd->hdc, op); DeleteObject(p); return CDRF_SKIPDEFAULT; } } }
    return DefSubclassProc(h, m, w, l);
}
/* ------------------------------------------------------------------ inspector window: one process, zoomed in ------------------------------------------------------------------ */
typedef struct {
    HWND h, lv[3], tab[3], bcap, bcopy, bkill, bblock; int cur, slot; DWORD pid; Profile pf;
    Conn *conns; int nconns; Pkt *pkts; int npkts; TraceEv *trace; int ntrace;
    double spark_tx[ISPARK_N], spark_rx[ISPARK_N]; int spark_i;
    uint64_t tx_total, rx_total, retx, pkts_seen; double tx_rate, rx_rate; int alive, blocked, nactive, ticks; DWORD fails; wchar_t name[64];
} Insp;
static Insp *g_insp[MAX_INSPECT];
static Insp *insp_find(DWORD pid) { for (int i = 0; i < MAX_INSPECT; i++) if (g_insp[i] && g_insp[i]->pid == pid) return g_insp[i]; return NULL; }
static HWND insp_hwnd(DWORD pid) { Insp *e = insp_find(pid); return e ? e->h : NULL; }
static int cmp_conn(const void *a, const void *b);
static void apply_dark_titlebar(HWND h);
static int build_inspect_json(DWORD pid, char *out, int n, int live_ok) {   /* everything the Inspector shows, as one JSON object (socket 'inspect', Copy JSON button) */
    char *cur = out, *end = out + n - 2; Insp *live = live_ok ? insp_find(pid) : NULL; Profile tmp, *pf; int nactive = 0; uint64_t tx_total = 0, rx_total = 0, retx = 0; double tx_rate = 0, rx_rate = 0; int blocked = 0; DWORD fails = 0;
    char sha[65] = "";
    if (live) { pf = &live->pf; if (pf->path[0]) sha256_file(pf->path, sha); } else { profile_init(&tmp, pid); profile_sample(&tmp); Sleep(150); profile_sample(&tmp); if (tmp.path[0]) tmp.sig = exe_signer_cached(tmp.path, tmp.signer, 160, sha); conns_seed(pid); estats_refresh(pid); pf = &tmp; }
    EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) { tx_total = p->tx_total; rx_total = p->rx_total; tx_rate = p->tx_rate; rx_rate = p->rx_rate; retx = p->retx; blocked = p->blocked; fails = p->fails; nactive = (int)p->nconn; } LeaveCriticalSection(&g_lock);
    char nm[200], path[1200], cmd[3200], user[400], par[200], signer[400], started[40] = "";
    jw(pf->name, nm, sizeof nm); jw(pf->path, path, sizeof path); jw(pf->cmdline, cmd, sizeof cmd); jw(pf->user, user, sizeof user); jw(pf->parent, par, sizeof par); jw(pf->signer, signer, sizeof signer);
    if (pf->created.dwLowDateTime || pf->created.dwHighDateTime) ft_iso(((ULONGLONG)pf->created.dwHighDateTime << 32) | pf->created.dwLowDateTime, started, sizeof started);
    cur += snprintf(cur, end - cur, "{\"reply\":\"inspect\",\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\",\"sha256\":\"%s\",\"cmdline\":\"%s\",\"user\":\"%s\",\"integrity\":\"%ls\",\"parent\":{\"pid\":%lu,\"name\":\"%s\"},\"started\":\"%s\",\"alive\":%s,\"protected\":%s,\"blocked\":%s,\"signer\":{\"state\":\"%s\",\"name\":\"%s\"},",
        (unsigned long)pid, nm, path, sha, cmd, user, pf->integrity, (unsigned long)pf->ppid, par, started, pf->alive ? "true" : "false", pf->protect ? "true" : "false", blocked ? "true" : "false", pf->sig == 1 ? "signed" : pf->sig == 2 ? "unsigned" : pf->sig == 3 ? "untrusted" : "pending", signer);
    cur += snprintf(cur, end - cur, "\"cpu_pct\":%.1f,\"cpu_time_ms\":%llu,\"working_set\":%llu,\"private_bytes\":%llu,\"disk_read_bps\":%.0f,\"disk_write_bps\":%.0f,\"gpu_pct\":%s%.1f%s,\"handles\":%lu,\"threads\":%lu,\"children\":%lu,",
        pf->cpu, (unsigned long long)pf->cpu_ms, (unsigned long long)pf->ws, (unsigned long long)pf->priv, pf->rd_bps, pf->wr_bps, pf->gpu_ok ? "" : "null", pf->gpu_ok ? pf->gpu : 0.0, pf->gpu_ok ? "" : "", (unsigned long)pf->handles, (unsigned long)pf->threads, (unsigned long)pf->children);
    if (!pf->gpu_ok) { char *q = strstr(out, "\"gpu_pct\":null0.0"); if (q) { memmove(q + 14, q + 17, strlen(q + 17) + 1); cur -= 3; } }
    cur += snprintf(cur, end - cur, "\"tx_bps\":%.0f,\"rx_bps\":%.0f,\"tx_total\":%llu,\"rx_total\":%llu,\"retx_bytes\":%llu,\"fails\":%lu,\"conns_active\":%d,\"zoom\":{\"state\":\"%s\",\"frames\":%lld,\"matched\":%lld,\"unmatched\":%lld},\"conns\":[",
        tx_rate, rx_rate, (unsigned long long)tx_total, (unsigned long long)rx_total, (unsigned long long)retx, (unsigned long)fails, nactive, zoom_state_str(), (long long)g_zoom_frames, (long long)g_zoom_matched, (long long)g_zoom_unmatched);
    Conn *cs = (Conn *)malloc(300 * sizeof(Conn)); int nc = 0;
    if (cs) { EnterCriticalSection(&g_lock); for (int i = 0; i < MAX_CONNS && nc < 300; i++) if (g_conns[i].used && g_conns[i].pid == pid) cs[nc++] = g_conns[i]; LeaveCriticalSection(&g_lock); qsort(cs, nc, sizeof(Conn), cmp_conn); for (int i = 0; i < nc && end - cur > 2000; i++) { if (i) *cur++ = ','; append_conn_json(&cur, end, &cs[i]); } free(cs); }
    cur += snprintf(cur, end - cur, "],\"timeline\":[");
    EnterCriticalSection(&g_zlock);
    { unsigned cnt = g_trace_head < TRACE_RING ? g_trace_head : TRACE_RING; int k2 = 0, shown = 0; unsigned idx[100]; for (unsigned k = 1; k <= cnt && k2 < 100; k++) { const TraceEv *t = &g_trace[(g_trace_head - k) % TRACE_RING]; if (t->pid == pid || (t->kind == 1 && t->ppid == pid)) idx[k2++] = (g_trace_head - k) % TRACE_RING; }
      for (int i = k2 - 1; i >= 0 && end - cur > 1500; i--) { const TraceEv *t = &g_trace[idx[i]]; char ts[40], det[600]; ft_iso(t->t, ts, sizeof ts); jw(t->detail, det, sizeof det); cur += snprintf(cur, end - cur, "%s{\"t\":\"%s\",\"kind\":\"%s\",\"pid\":%lu,\"ppid\":%lu,\"detail\":\"%s\"}", shown++ ? "," : "", ts, trace_kind_str(t->kind), (unsigned long)t->pid, (unsigned long)t->ppid, det); } }
    cur += snprintf(cur, end - cur, "],\"packets\":[");
    { unsigned cnt = g_pkt_head < PKT_RING ? g_pkt_head : PKT_RING; int k2 = 0, shown = 0; unsigned idx[100]; for (unsigned k = 1; k <= cnt && k2 < 100; k++) { const Pkt *q = &g_pkts[(g_pkt_head - k) % PKT_RING]; if (q->pid == pid) idx[k2++] = (g_pkt_head - k) % PKT_RING; }
      for (int i = k2 - 1; i >= 0 && end - cur > 1500; i--) { const Pkt *q = &g_pkts[idx[i]]; char ts[40], info[400], ip[48], fl[48]; ft_iso(q->t, ts, sizeof ts); json_escape(q->info, info, sizeof info); addr_str(q->v6, q->raddr, ip, sizeof ip); tcp_flags_str(q->flags, fl, sizeof fl); cur += snprintf(cur, end - cur, "%s{\"t\":\"%s\",\"dir\":\"%s\",\"proto\":\"%s%s\",\"lport\":%u,\"remote\":\"%s\",\"port\":%u,\"len\":%u,\"flags\":\"%s\",\"info\":\"%s\"}", shown++ ? "," : "", ts, q->out ? "out" : "in", q->udp ? "udp" : "tcp", q->v6 ? "6" : "", q->lport, ip, q->rport, q->len, fl, info); } }
    LeaveCriticalSection(&g_zlock);
    cur += snprintf(cur, end - cur, "]}");
    if (!live) profile_free(&tmp);
    return (int)(cur - out);
}
static HWND mk_list(HWND parent, int id, const wchar_t **cols, const int *widths, const int *right, int n) {
    HWND lv = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    SendMessageW(lv, WM_SETFONT, (WPARAM)g_font, 1); ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP); ListView_SetBkColor(lv, C_BG); ListView_SetTextBkColor(lv, C_BG); ListView_SetTextColor(lv, C_TEXT); SetWindowSubclass(lv, ListSubclass, 1, 0);
    { HIMAGELIST il = ImageList_Create(1, 22, ILC_COLOR32, 1, 1); ListView_SetImageList(lv, il, LVSIL_SMALL); }
    dark_mode_window(lv);
    for (int i = 0; i < n; i++) { LVCOLUMNW c = { 0 }; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.pszText = (LPWSTR)cols[i]; c.cx = widths[i]; c.fmt = right[i] ? LVCFMT_RIGHT : LVCFMT_LEFT; ListView_InsertColumn(lv, i, &c); }
    return lv;
}
static int cmp_conn(const void *a, const void *b) { const Conn *x = a, *y = b; int ax = x->state != 3 && x->state != 4, ay = y->state != 3 && y->state != 4; if (ax != ay) return ay - ax; double rx = x->tx_rate + x->rx_rate, ry = y->tx_rate + y->rx_rate; if (rx != ry) return rx < ry ? 1 : -1; uint64_t bx = x->tx + x->rx, by = y->tx + y->rx; if (bx != by) return bx < by ? 1 : -1; return x->last_seen < y->last_seen ? 1 : x->last_seen > y->last_seen ? -1 : 0; }
static void fmt_age_w(ULONGLONG ms, wchar_t *out, int n) { ULONGLONG s = ms / 1000; if (s < 60) _snwprintf(out, n, L"%I64u s", (unsigned long long)s); else if (s < 3600) _snwprintf(out, n, L"%I64u m %02I64u s", (unsigned long long)(s / 60), (unsigned long long)(s % 60)); else _snwprintf(out, n, L"%I64u h %02I64u m", (unsigned long long)(s / 3600), (unsigned long long)(s / 60 % 60)); }
static void conn_info_w(const Conn *c, wchar_t *b, int n) {
    b[0] = 0; wchar_t t[160];
    if (c->sni[0]) { _snwprintf(t, 160, L"SNI %hs  ", c->sni); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->alpn[0]) { _snwprintf(t, 160, L"ALPN %hs  ", c->alpn); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->quic) { _snwprintf(t, 160, L"QUIC %ls  ", c->quic_ver == 1 ? L"v1" : c->quic_ver == 0x6b3343cf ? L"v2" : L"draft"); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->tls_ver) { _snwprintf(t, 160, L"TLS %hs  ", tls_ver_str(c->tls_ver)); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->http[0]) { _snwprintf(t, 160, L"HTTP %hs  ", c->http); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->connect_ms >= 0) { _snwprintf(t, 160, L"connected in %d ms  ", c->connect_ms); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->reconnects) { _snwprintf(t, 160, L"%lu reconnects  ", (unsigned long)c->reconnects); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->estats && (c->timeouts || c->cong)) { _snwprintf(t, 160, L"%lu timeouts, %lu congestion signals  ", (unsigned long)c->timeouts, (unsigned long)c->cong); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->mss) { _snwprintf(t, 160, L"mss %u  ", c->mss); wcsncat(b, t, n - wcslen(b) - 1); }
    if (c->local) wcsncat(b, L"local/LAN", n - wcslen(b) - 1);
}
static void insp_cell(Insp *ins, int list, int row, int col, wchar_t *b, int n) {
    b[0] = 0;
    if (list == 0) { if (row >= ins->nconns) return; const Conn *c = &ins->conns[row]; char ip[48]; addr_str(c->v6, c->raddr, ip, sizeof ip);
        switch (col) {
        case 0: { wchar_t hn[128]; if (host_lookup(ip, hn, 128)) wcsncpy(b, hn, n - 1); else if (c->sni[0]) _snwprintf(b, n, L"%hs", c->sni); else _snwprintf(b, n, L"%hs", ip); b[n - 1] = 0; break; }
        case 1: _snwprintf(b, n, L"%hs", ip); break;
        case 2: _snwprintf(b, n, L"%u", c->rport); break;
        case 3: _snwprintf(b, n, L"%ls%ls", c->udp ? L"UDP" : L"TCP", c->v6 ? L"6" : L""); break;
        case 4: _snwprintf(b, n, L"%hs", conn_state_str(c)); break;
        case 5: if (c->tx_rate > 0) fmt_rate_w(c->tx_rate, b, n); else wcscpy(b, L"-"); break;
        case 6: if (c->rx_rate > 0) fmt_rate_w(c->rx_rate, b, n); else wcscpy(b, L"-"); break;
        case 7: fmt_bytes_w(c->tx, b, n); break;
        case 8: fmt_bytes_w(c->rx, b, n); break;
        case 9: if (c->retx || c->pretrans) { wchar_t x[32]; fmt_bytes_w(c->retx, x, 32); _snwprintf(b, n, L"%ls / %lu pk", x, (unsigned long)(c->pretrans ? c->pretrans : c->retx_events)); } else wcscpy(b, L"-"); break;
        case 10: if (c->estats && c->srtt) _snwprintf(b, n, L"%lu ms (min %lu)", (unsigned long)c->srtt, (unsigned long)(c->minrtt == 0xFFFFFFFF ? 0 : c->minrtt)); else wcscpy(b, L"-"); break;
        case 11: _snwprintf(b, n, L"%u", c->lport); break;
        case 12: fmt_age_w(GetTickCount64() - c->first_seen, b, n); break;
        default: conn_info_w(c, b, n); break;
        } }
    else if (list == 1) { if (row >= ins->npkts) return; const Pkt *q = &ins->pkts[row]; char ip[48]; addr_str(q->v6, q->raddr, ip, sizeof ip);
        switch (col) {
        case 0: ft_clock(q->t, b, n); break;
        case 1: wcscpy(b, q->out ? L"\x2192 out" : L"\x2190 in"); break;
        case 2: _snwprintf(b, n, L"%ls%ls", q->udp ? L"UDP" : L"TCP", q->v6 ? L"6" : L""); break;
        case 3: { wchar_t hn[128]; if (host_lookup(ip, hn, 128)) _snwprintf(b, n, L"%ls  (%hs)", hn, ip); else _snwprintf(b, n, L"%hs", ip); break; }
        case 4: _snwprintf(b, n, L"%u", q->rport); break;
        case 5: _snwprintf(b, n, L"%u", q->len); break;
        default: _snwprintf(b, n, L"%hs", q->info); break;
        } }
    else { if (row >= ins->ntrace) return; const TraceEv *t = &ins->trace[row];
        switch (col) {
        case 0: ft_clock(t->t, b, n); break;
        case 1: { static const wchar_t *kn[] = { L"?", L"process start", L"process exit", L"image load", L"connect", L"established", L"closed", L"connect failed", L"retransmit", L"reconnect", L"TLS hello", L"DNS", L"HTTP", L"QUIC", L"capture" }; wcsncpy(b, t->kind <= 14 ? kn[t->kind] : L"?", n - 1); b[n - 1] = 0; break; }
        case 2: _snwprintf(b, n, L"%lu", (unsigned long)t->pid); break;
        default: if (t->kind == 1 && t->ppid == ins->pid && t->pid != ins->pid) _snwprintf(b, n, L"spawned child: %ls", t->detail); else wcsncpy(b, t->detail, n - 1); b[n - 1] = 0; break;
        } }
}
static void insp_set_tab(Insp *ins, int t) { ins->cur = t; for (int i = 0; i < 3; i++) { LONG_PTR d = GetWindowLongPtrW(ins->tab[i], GWLP_USERDATA); SetWindowLongPtrW(ins->tab[i], GWLP_USERDATA, (d & ~(LONG_PTR)0x200) | (i == t ? 0x200 : 0)); InvalidateRect(ins->tab[i], NULL, TRUE); ShowWindow(ins->lv[i], i == t ? SW_SHOW : SW_HIDE); } }
static void insp_layout(Insp *ins) {
    RECT rc; GetClientRect(ins->h, &rc); int W = rc.right, H = rc.bottom, y = 166;
    for (int i = 0; i < 3; i++) MoveWindow(ins->tab[i], 8 + i * 238, y, 230, 30, TRUE);
    MoveWindow(ins->bblock, W - 8 - 90, y, 90, 30, TRUE); MoveWindow(ins->bkill, W - 8 - 90 - 8 - 80, y, 80, 30, TRUE); MoveWindow(ins->bcopy, W - 8 - 90 - 8 - 80 - 8 - 110, y, 110, 30, TRUE); MoveWindow(ins->bcap, W - 8 - 90 - 8 - 80 - 8 - 110 - 8 - 190, y, 190, 30, TRUE);
    static const int ncols[3] = { 14, 7, 4 }, minw[3] = { 240, 300, 300 };
    for (int i = 0; i < 3; i++) { MoveWindow(ins->lv[i], 8, y + 38, W - 16, H - (y + 38) - 44, TRUE); list_fill_last(ins->lv[i], ncols[i], minw[i]); }
}
static void insp_tick(Insp *ins) {
    DWORD pid = ins->pid; ULONGLONG now = GetTickCount64();
    EnterCriticalSection(&g_lock);
    Proc *p = proc_find(pid); if (p) { ins->tx_total = p->tx_total; ins->rx_total = p->rx_total; ins->tx_rate = p->tx_rate; ins->rx_rate = p->rx_rate; ins->retx = p->retx; ins->blocked = p->blocked; ins->fails = p->fails; if (!ins->name[0] && p->name[0]) wcscpy(ins->name, p->name); }
    ins->nconns = 0; ins->nactive = 0; ins->pkts_seen = 0;
    for (int i = 0; i < MAX_CONNS && ins->nconns < 512; i++) { const Conn *c = &g_conns[i]; if (c->used && c->pid == pid) { ins->conns[ins->nconns++] = *c; ins->pkts_seen += c->pkts_in + c->pkts_out; if (c->state != 3 && c->state != 4) ins->nactive++; } }
    LeaveCriticalSection(&g_lock);
    qsort(ins->conns, ins->nconns, sizeof(Conn), cmp_conn);
    if ((ins->ticks & 1) == 0) conns_seed(pid);
    estats_refresh(pid); profile_sample(&ins->pf); ins->alive = ins->pf.alive;
    ins->spark_tx[ins->spark_i] = ins->tx_rate; ins->spark_rx[ins->spark_i] = ins->rx_rate; ins->spark_i = (ins->spark_i + 1) % ISPARK_N;
    int oldp = ins->npkts, oldt = ins->ntrace;
    EnterCriticalSection(&g_zlock);
    ins->npkts = 0; unsigned cnt = g_pkt_head < PKT_RING ? g_pkt_head : PKT_RING; for (unsigned k = cnt; k >= 1; k--) { const Pkt *q = &g_pkts[(g_pkt_head - k) % PKT_RING]; if (q->pid == pid && ins->npkts < PKT_RING) ins->pkts[ins->npkts++] = *q; }
    ins->ntrace = 0; cnt = g_trace_head < TRACE_RING ? g_trace_head : TRACE_RING; for (unsigned k = cnt; k >= 1; k--) { const TraceEv *t = &g_trace[(g_trace_head - k) % TRACE_RING]; if ((t->pid == pid || (t->kind == 1 && t->ppid == pid)) && ins->ntrace < 1024) ins->trace[ins->ntrace++] = *t; }
    int cap_mine = cap_for_pid_locked(pid) >= 0;
    LeaveCriticalSection(&g_zlock);
    ListView_SetItemCountEx(ins->lv[0], ins->nconns, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    ListView_SetItemCountEx(ins->lv[1], ins->npkts, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); if (ins->npkts != oldp && ins->npkts && ListView_GetNextItem(ins->lv[1], -1, LVNI_SELECTED) < 0) ListView_EnsureVisible(ins->lv[1], ins->npkts - 1, FALSE);
    ListView_SetItemCountEx(ins->lv[2], ins->ntrace, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); if (ins->ntrace != oldt && ins->ntrace && ListView_GetNextItem(ins->lv[2], -1, LVNI_SELECTED) < 0) ListView_EnsureVisible(ins->lv[2], ins->ntrace - 1, FALSE);
    wchar_t t[64]; _snwprintf(t, 64, L"Connections   %d active \x00B7 %d", ins->nactive, ins->nconns); SetWindowTextW(ins->tab[0], t); _snwprintf(t, 64, L"Packets   %d", ins->npkts); SetWindowTextW(ins->tab[1], t); _snwprintf(t, 64, L"Timeline   %d", ins->ntrace); SetWindowTextW(ins->tab[2], t);
    SetWindowTextW(ins->bcap, cap_mine ? L"Stop capture" : L"Capture 30 s \x2192 pcapng"); SetWindowTextW(ins->bblock, ins->blocked ? L"Unblock" : L"Block");
    for (int i = 0; i < 3; i++) InvalidateRect(ins->tab[i], NULL, TRUE); InvalidateRect(ins->bcap, NULL, TRUE); InvalidateRect(ins->bblock, NULL, TRUE);
    RECT rc; GetClientRect(ins->h, &rc); RECT top = { 0, 0, rc.right, 162 }, bot = { 0, rc.bottom - 40, rc.right, rc.bottom }; InvalidateRect(ins->h, &top, FALSE); InvalidateRect(ins->h, &bot, FALSE); InvalidateRect(ins->lv[ins->cur], NULL, FALSE);
    ins->ticks++; (void)now;
}
static int pair_w(HDC dc, int x, int y, const wchar_t *label, const wchar_t *value, COLORREF vc) {   /* "LABEL value" segment; returns the x after it */
    SIZE sz; SelectObject(dc, g_font_small); SetTextColor(dc, C_MUTED); GetTextExtentPoint32W(dc, label, (int)wcslen(label), &sz); RECT r = { x, y, x + sz.cx + 4, y + 20 }; DrawTextW(dc, label, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX); x += sz.cx + 6;
    SelectObject(dc, g_font); SetTextColor(dc, vc); GetTextExtentPoint32W(dc, value, (int)wcslen(value), &sz); RECT r2 = { x, y, x + sz.cx + 4, y + 20 }; DrawTextW(dc, value, -1, &r2, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX); return x + sz.cx + 22;
}
static void insp_paint(Insp *ins, HDC dc, int W, int H) {
    HDC mdc = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, W, H); HGDIOBJ ob = SelectObject(mdc, bmp); RECT all = { 0, 0, W, H }; HBRUSH bgb = CreateSolidBrush(C_BG); FillRect(mdc, &all, bgb); DeleteObject(bgb); SetBkMode(mdc, TRANSPARENT);
    HBRUSH pb = CreateSolidBrush(C_PANEL); HPEN pp = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ obr = SelectObject(mdc, pb), op = SelectObject(mdc, pp); RoundRect(mdc, 8, 8, W - 8, 158, 14, 14); RoundRect(mdc, 8, H - 36, W - 8, H - 8, 10, 10); SelectObject(mdc, obr); SelectObject(mdc, op); DeleteObject(pb); DeleteObject(pp);
    const Profile *pf = &ins->pf; int x = 22, y = 14, right = W - 8 - 330 - 12; wchar_t t[1400], a[48], b[48];
    SelectObject(mdc, g_font_big); SetTextColor(mdc, C_TEXT); _snwprintf(t, 1400, L"%ls", ins->name[0] ? ins->name : pf->name); SIZE sz; GetTextExtentPoint32W(mdc, t, (int)wcslen(t), &sz); RECT r = { x, y, right, y + 28 }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS); x += sz.cx + 12;
    SelectObject(mdc, g_font); SetTextColor(mdc, C_MUTED); _snwprintf(t, 1400, L"pid %lu", (unsigned long)ins->pid); GetTextExtentPoint32W(mdc, t, (int)wcslen(t), &sz); r = (RECT){ x, y, x + sz.cx + 4, y + 28 }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE); x += sz.cx + 16;
    { COLORREF c = ins->blocked ? C_RED : ins->alive ? C_GREEN : C_MUTED; const wchar_t *s = ins->blocked ? L"BLOCKED (firewall)" : ins->alive ? L"running" : L"exited"; dot(mdc, x + 6, y + 14, c); SetTextColor(mdc, c); GetTextExtentPoint32W(mdc, s, (int)wcslen(s), &sz); r = (RECT){ x + 16, y, x + 16 + sz.cx + 4, y + 28 }; DrawTextW(mdc, s, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE); x += 16 + sz.cx + 18; }
    { COLORREF c = pf->sig == 1 ? C_GREEN : pf->sig == 2 ? C_AMBER : pf->sig == 3 ? C_RED : C_MUTED; if (pf->sig == 0) wcscpy(t, pf->path[0] ? L"checking signature\x2026" : L"no file"); else if (pf->sig == 1) _snwprintf(t, 1400, L"\x2714 signed: %ls", pf->signer[0] ? pf->signer : L"(unknown publisher)"); else if (pf->sig == 2) wcscpy(t, L"\x26A0 unsigned"); else _snwprintf(t, 1400, L"\x2716 signature not trusted%ls%ls", pf->signer[0] ? L": " : L"", pf->signer); SetTextColor(mdc, c); r = (RECT){ x, y, right, y + 28 }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS); }
    y = 44; SetTextColor(mdc, C_MUTED); SelectObject(mdc, g_font); r = (RECT){ 22, y, right, y + 20 }; DrawTextW(mdc, pf->path[0] ? pf->path : (pf->protect ? L"(protected process: no access to its details)" : L"(path unknown)"), -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_PATH_ELLIPSIS);
    y = 64; if (pf->cmdline[0]) { r = (RECT){ 22, y, right, y + 20 }; SetTextColor(mdc, RGB(170, 175, 188)); DrawTextW(mdc, pf->cmdline, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS); }
    y = 86; x = 22; wchar_t started[48] = L"-"; if (pf->created.dwLowDateTime || pf->created.dwHighDateTime) { FILETIME lt; SYSTEMTIME st; FileTimeToLocalFileTime(&pf->created, &lt); FileTimeToSystemTime(&lt, &st); _snwprintf(started, 48, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond); }
    x = pair_w(mdc, x, y, L"USER", pf->user[0] ? pf->user : L"-", C_TEXT); x = pair_w(mdc, x, y, L"INTEGRITY", pf->integrity[0] ? pf->integrity : L"-", C_TEXT); _snwprintf(t, 1400, L"%ls (%lu)", pf->parent[0] ? pf->parent : L"?", (unsigned long)pf->ppid); x = pair_w(mdc, x, y, L"PARENT", t, C_TEXT); x = pair_w(mdc, x, y, L"STARTED", started, C_TEXT);
    _snwprintf(t, 1400, L"%lu", (unsigned long)pf->children); x = pair_w(mdc, x, y, L"CHILDREN", t, C_TEXT); _snwprintf(t, 1400, L"%lu", (unsigned long)pf->threads); x = pair_w(mdc, x, y, L"THREADS", t, C_TEXT); _snwprintf(t, 1400, L"%lu", (unsigned long)pf->handles); x = pair_w(mdc, x, y, L"HANDLES", t, C_TEXT);
    y = 108; x = 22; _snwprintf(t, 1400, L"%.1f %%", pf->cpu); x = pair_w(mdc, x, y, L"CPU", t, pf->cpu >= 50 ? C_AMBER : C_TEXT); fmt_bytes_w(pf->ws, a, 48); fmt_bytes_w(pf->priv, b, 48); _snwprintf(t, 1400, L"%ls  (private %ls)", a, b); x = pair_w(mdc, x, y, L"MEMORY", t, C_TEXT);
    fmt_rate_w(pf->rd_bps, a, 48); fmt_rate_w(pf->wr_bps, b, 48); _snwprintf(t, 1400, L"read %ls  write %ls", a, b); x = pair_w(mdc, x, y, L"DISK", t, C_TEXT); if (pf->gpu_ok) _snwprintf(t, 1400, L"%.0f %%", pf->gpu); else wcscpy(t, L"-"); x = pair_w(mdc, x, y, L"GPU", t, C_TEXT);
    { uint64_t s = pf->cpu_ms / 1000; _snwprintf(t, 1400, s < 60 ? L"%I64u s" : L"%I64u min %I64u s", (unsigned long long)(s < 60 ? s : s / 60), (unsigned long long)(s % 60)); x = pair_w(mdc, x, y, L"CPU TIME", t, C_TEXT); }
    y = 130; x = 22; fmt_rate_w(ins->tx_rate, a, 48); x = pair_w(mdc, x, y, L"OUT", a, ins->tx_rate > 0 ? C_GREEN : C_TEXT); fmt_rate_w(ins->rx_rate, a, 48); x = pair_w(mdc, x, y, L"IN", a, ins->rx_rate > 0 ? C_BLUE : C_TEXT);
    fmt_bytes_w(ins->tx_total, a, 48); fmt_bytes_w(ins->rx_total, b, 48); _snwprintf(t, 1400, L"out %ls  in %ls", a, b); x = pair_w(mdc, x, y, L"TOTAL", t, C_TEXT); _snwprintf(t, 1400, L"%d active", ins->nactive); x = pair_w(mdc, x, y, L"CONNECTIONS", t, C_TEXT);
    fmt_bytes_w(ins->retx, a, 48); x = pair_w(mdc, x, y, L"RETRANSMITTED", a, ins->retx ? C_AMBER : C_TEXT); _snwprintf(t, 1400, L"%lu", (unsigned long)ins->fails); x = pair_w(mdc, x, y, L"FAILED CONNECTS", t, ins->fails ? C_RED : C_TEXT); _snwprintf(t, 1400, L"%I64u", (unsigned long long)ins->pkts_seen); x = pair_w(mdc, x, y, L"PACKETS", t, C_TEXT);
    { int left = W - 8 - 330, rgt = W - 20, top = 30, bottom = 148; double mx = 10240; for (int i = 0; i < ISPARK_N; i++) { if (ins->spark_tx[i] > mx) mx = ins->spark_tx[i]; if (ins->spark_rx[i] > mx) mx = ins->spark_rx[i]; } double sx = (rgt - left) / (double)(ISPARK_N - 1);
        HPEN grid = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ gop = SelectObject(mdc, grid); for (int k = 1; k < 4; k++) { int yy = top + (bottom - top) * k / 4; MoveToEx(mdc, left, yy, NULL); LineTo(mdc, rgt, yy); } SelectObject(mdc, gop); DeleteObject(grid);
        for (int series = 0; series < 2; series++) { double *v = series ? ins->spark_tx : ins->spark_rx; COLORREF col = series ? C_GREEN : C_BLUE, fillc = series ? RGB(34, 62, 46) : RGB(34, 48, 70); POINT pts[ISPARK_N + 2]; int n = 0; for (int i = 0; i < ISPARK_N; i++) { double val = v[(ins->spark_i + i) % ISPARK_N]; pts[n].x = left + (int)(i * sx); pts[n].y = bottom - (int)((bottom - top) * (val / mx)); n++; } pts[n].x = rgt; pts[n].y = bottom; n++; pts[n].x = left; pts[n].y = bottom; n++; HBRUSH fb = CreateSolidBrush(fillc); HPEN fp = CreatePen(PS_NULL, 0, 0); HGDIOBJ obr2 = SelectObject(mdc, fb), opp = SelectObject(mdc, fp); Polygon(mdc, pts, n); SelectObject(mdc, obr2); SelectObject(mdc, opp); DeleteObject(fb); DeleteObject(fp); HPEN lp = CreatePen(PS_SOLID, 2, col); opp = SelectObject(mdc, lp); Polyline(mdc, pts, n - 2); SelectObject(mdc, opp); DeleteObject(lp); }
        SelectObject(mdc, g_font_small); SetTextColor(mdc, C_MUTED); fmt_rate_w(mx, a, 48); _snwprintf(t, 1400, L"LAST 2 MINUTES   scale %ls", a); r = (RECT){ left, 12, rgt, 28 }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_SINGLELINE); }
    { SelectObject(mdc, g_font); wchar_t cap[400] = L""; EnterCriticalSection(&g_zlock); int ck = cap_for_pid_locked(ins->pid), others = cap_active_locked() - (ck >= 0); if (ck >= 0) { long long left_s = (long long)(g_caps[ck].until - now_ft()) / 10000000LL; if (left_s < 0) left_s = 0; _snwprintf(cap, 400, L"     pcapng: writing %ls  (%I64u packets, %lld s left)%ls", basename_w(g_caps[ck].path), (unsigned long long)g_caps[ck].pkts, left_s, others ? L"  +other captures running" : L""); } else if (g_cap_last.path[0]) _snwprintf(cap, 400, L"     last pcapng: %ls  (%I64u packets)", g_cap_last.path, (unsigned long long)g_cap_last.pkts); LeaveCriticalSection(&g_zlock);
        COLORREF zc = g_zoom_state == 2 ? C_GREEN : g_zoom_state == 1 ? C_AMBER : g_zoom_state == -1 ? C_RED : C_MUTED; dot(mdc, 22, H - 22, zc); SetTextColor(mdc, C_TEXT);
        if (g_zoom_state == -1) _snwprintf(t, 1400, L"Packet zoom ERROR %lu (ndiscap.sys / ETW session)%ls", (unsigned long)g_zoom_err, cap); else _snwprintf(t, 1400, L"Packet zoom %hs   frames %I64d   matched %I64d   unmatched %I64d%ls", zoom_state_str(), (long long)g_zoom_frames, (long long)g_zoom_matched, (long long)g_zoom_unmatched, cap);
        r = (RECT){ 34, H - 36, W - 16, H - 8 }; DrawTextW(mdc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS); }
    BitBlt(dc, 0, 0, W, 162, mdc, 0, 0, SRCCOPY); BitBlt(dc, 0, H - 40, W, 40, mdc, 0, H - 40, SRCCOPY); SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc);
}
static void insp_copy_line(Insp *ins, int list, int row, int only_col) { wchar_t line[3000] = L"", cell[1024]; int ncols = list == 0 ? 14 : list == 1 ? 7 : 4; for (int c = 0; c < ncols; c++) { if (only_col >= 0 && c != only_col) continue; insp_cell(ins, list, row, c, cell, 1024); if (line[0] && only_col < 0) wcsncat(line, L"\t", 2999 - wcslen(line)); wcsncat(line, cell, 2999 - wcslen(line)); } copy_text(line); }
static LRESULT CALLBACK InspProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Insp *ins = (Insp *)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_NCCREATE: { CREATESTRUCTW *cs = (CREATESTRUCTW *)l; ins = (Insp *)calloc(1, sizeof *ins); ins->h = h; ins->pid = (DWORD)(UINT_PTR)cs->lpCreateParams; ins->slot = -1; for (int i = 0; i < MAX_INSPECT; i++) if (!g_insp[i]) { ins->slot = i; g_insp[i] = ins; g_insp_pids[i] = ins->pid; break; } ins->conns = (Conn *)calloc(512, sizeof(Conn)); ins->pkts = (Pkt *)calloc(PKT_RING, sizeof(Pkt)); ins->trace = (TraceEv *)calloc(1024, sizeof(TraceEv)); SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)ins); return DefWindowProcW(h, m, w, l); }
    case WM_CREATE: {
        static const wchar_t *c0[] = { L"Remote", L"Address", L"Port", L"Proto", L"State", L"Out /s", L"In /s", L"Out", L"In", L"Retrans", L"RTT", L"Local", L"Age", L"Info  (SNI \x00B7 ALPN \x00B7 TLS \x00B7 HTTP \x00B7 connect time)" }; static const int w0[] = { 200, 135, 50, 60, 90, 80, 80, 80, 80, 95, 112, 56, 68, 240 }, r0[] = { 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 };
        static const wchar_t *c1[] = { L"Time", L"Dir", L"Proto", L"Remote", L"Port", L"Len", L"Info" }; static const int w1[] = { 105, 60, 55, 300, 55, 60, 800 }, r1[] = { 0, 0, 0, 0, 1, 1, 0 };
        static const wchar_t *c2[] = { L"Time", L"Event", L"PID", L"Detail" }; static const int w2[] = { 105, 120, 70, 1000 }, r2[] = { 0, 0, 1, 0 };
        ins->lv[0] = mk_list(h, IDC_I_LIST0, c0, w0, r0, 14); ins->lv[1] = mk_list(h, IDC_I_LIST1, c1, w1, r1, 7); ins->lv[2] = mk_list(h, IDC_I_LIST2, c2, w2, r2, 4);
        ins->tab[0] = mk_button(h, IDC_I_TAB0, L"Connections", 3); ins->tab[1] = mk_button(h, IDC_I_TAB1, L"Packets", 3); ins->tab[2] = mk_button(h, IDC_I_TAB2, L"Timeline", 3);
        ins->bcap = mk_button(h, IDC_I_CAP, L"Capture 30 s \x2192 pcapng", 0); ins->bcopy = mk_button(h, IDC_I_COPY, L"Copy JSON", 0); ins->bkill = mk_button(h, IDC_I_KILL, L"Kill", 1); ins->bblock = mk_button(h, IDC_I_BLOCK, L"Block", 1);
        profile_init(&ins->pf, ins->pid); wcsncpy(ins->name, ins->pf.name, 63); if (ins->pf.path[0]) signer_async(h, ins->pf.path);
        conns_seed(ins->pid); zoom_recalc(); insp_set_tab(ins, 0); insp_layout(ins); insp_tick(ins); SetTimer(h, 1, 1000, NULL); return 0; }
    case WM_SIZE: insp_layout(ins); InvalidateRect(h, NULL, TRUE); return 0;
    case WM_GETMINMAXINFO: { MINMAXINFO *mi = (MINMAXINFO *)l; mi->ptMinTrackSize.x = 1260; mi->ptMinTrackSize.y = 540; return 0; }
    case WM_DRAWITEM: draw_button((DRAWITEMSTRUCT *)l); return TRUE;
    case WM_ERASEBKGND: { RECT rc; GetClientRect(h, &rc); HBRUSH br = CreateSolidBrush(C_BG); FillRect((HDC)w, &rc, br); DeleteObject(br); return 1; }   /* the band behind the tabs and the gaps between buttons */
    case WM_PAINT: { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc); insp_paint(ins, dc, rc.right, rc.bottom); EndPaint(h, &ps); return 0; }
    case WM_TIMER: insp_tick(ins); return 0;
    case WM_SIGNER: { wchar_t *res = (wchar_t *)l; if (res) { ins->pf.sig = (int)res[0]; wcsncpy(ins->pf.signer, res + 1, 159); ins->pf.signer[159] = 0; free(res); RECT rc; GetClientRect(h, &rc); RECT top = { 0, 0, rc.right, 162 }; InvalidateRect(h, &top, FALSE); } return 0; }
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)l; int list = nm->idFrom == IDC_I_LIST0 ? 0 : nm->idFrom == IDC_I_LIST1 ? 1 : nm->idFrom == IDC_I_LIST2 ? 2 : -1; if (list < 0) return 0;
        if (nm->code == LVN_GETDISPINFOW) { NMLVDISPINFOW *di = (NMLVDISPINFOW *)l; if (!(di->item.mask & LVIF_TEXT)) return 0; static wchar_t bufs[16][1024]; wchar_t *b = bufs[di->item.iSubItem & 15]; insp_cell(ins, list, di->item.iItem, di->item.iSubItem, b, 1024); di->item.pszText = b; }
        else if (nm->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)l; if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) { int i = (int)cd->nmcd.dwItemSpec; cd->clrTextBk = (i & 1) ? RGB(22, 23, 29) : C_BG; cd->clrText = C_TEXT;
                if (list == 0 && i < ins->nconns) { const Conn *c = &ins->conns[i]; if (c->state == 4) cd->clrText = C_RED; else if (c->state == 3) cd->clrText = C_MUTED; else if (c->state == 1) cd->clrText = C_AMBER; else if (c->tx_rate > 0) cd->clrText = C_GREEN; else if (c->rx_rate > 0) cd->clrText = C_BLUE; else if (c->retx) cd->clrText = RGB(220, 190, 120); }
                else if (list == 1 && i < ins->npkts) { const Pkt *q = &ins->pkts[i]; if (strstr(q->info, "SNI=") || !strncmp(q->info, "DNS", 3) || !strncmp(q->info, "HTTP", 4)) cd->clrText = C_AMBER; else cd->clrText = q->out ? C_GREEN : C_BLUE; }
                else if (list == 2 && i < ins->ntrace) { int k = ins->trace[i].kind; if (k == 7) cd->clrText = C_RED; else if (k == 1 || k == 2 || k == 14) cd->clrText = C_AMBER; else if (k == 3) cd->clrText = C_MUTED; else if (k >= 10 && k <= 13) cd->clrText = RGB(200, 200, 150); else if (k == 8) cd->clrText = RGB(220, 190, 120); }
                return CDRF_NEWFONT; } }
        else if (nm->code == NM_RCLICK) { int row = ListView_GetNextItem(ins->lv[list], -1, LVNI_SELECTED); if (row < 0) return 0; POINT pt; GetCursorPos(&pt); HMENU mn = CreatePopupMenu(); if (list == 0) AppendMenuW(mn, MF_STRING, IDM_I_COPYADDR, L"Copy remote address"); if (list == 1) AppendMenuW(mn, MF_STRING, IDM_I_COPYINFO, L"Copy packet info"); AppendMenuW(mn, MF_STRING, IDM_I_COPYLINE, L"Copy row"); int cmd = TrackPopupMenu(mn, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, h, NULL); DestroyMenu(mn); if (cmd == IDM_I_COPYADDR) insp_copy_line(ins, 0, row, 1); else if (cmd == IDM_I_COPYINFO) insp_copy_line(ins, 1, row, 6); else if (cmd == IDM_I_COPYLINE) insp_copy_line(ins, list, row, -1); }
        return 0; }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_I_TAB0: insp_set_tab(ins, 0); return 0; case IDC_I_TAB1: insp_set_tab(ins, 1); return 0; case IDC_I_TAB2: insp_set_tab(ins, 2); return 0;
        case IDC_I_CAP: { int mine; EnterCriticalSection(&g_zlock); mine = cap_for_pid_locked(ins->pid) >= 0; LeaveCriticalSection(&g_zlock); if (mine) cap_stop(ins->pid, 0); else { SYSTEMTIME st; GetLocalTime(&st); wchar_t path[MAX_PATH], nm[64]; wcsncpy(nm, ins->name[0] ? ins->name : L"process", 63); nm[63] = 0; for (wchar_t *q = nm; *q; q++) if (wcschr(L"\\/:*?\"<>| ", *q)) *q = L'_'; _snwprintf(path, MAX_PATH, L"%ls\\capture_%ls_%lu_%02d%02d%02d.pcapng", g_exe_dir, nm, (unsigned long)ins->pid, st.wHour, st.wMinute, st.wSecond); char err[300]; if (!cap_start(ins->pid, 30, path, err, sizeof err)) { wchar_t e[300]; to_wide(err, e, 300); MessageBoxW(h, e, L"Hodometer", MB_OK | MB_ICONERROR); } } insp_tick(ins); return 0; }
        case IDC_I_COPY: { char *js = (char *)malloc(600000); if (js) { build_inspect_json(ins->pid, js, 600000, 1); wchar_t *wj = (wchar_t *)malloc(600000 * sizeof(wchar_t)); if (wj) { to_wide(js, wj, 600000); copy_text(wj); free(wj); } free(js); } return 0; }
        case IDC_I_KILL: { wchar_t q[400]; _snwprintf(q, 400, L"Kill %ls (pid %lu)?\n\n%ls", ins->name, (unsigned long)ins->pid, ins->pf.path); if (MessageBoxW(h, q, L"Hodometer", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return 0; char err[160] = ""; if (!kill_pid(ins->pid, err, sizeof err)) { wchar_t e[200]; to_wide(err, e, 200); MessageBoxW(h, e, L"Hodometer", MB_OK | MB_ICONERROR); } else { char js[96]; snprintf(js, sizeof js, "{\"ev\":\"killed\",\"pid\":%lu,\"by\":\"ui\"}", (unsigned long)ins->pid); bcast(js); } return 0; }
        case IDC_I_BLOCK: { if (!ins->pf.path[0]) { MessageBoxW(h, L"No program path known for this process.", L"Hodometer", MB_OK | MB_ICONERROR); return 0; } int block = !ins->blocked; wchar_t q[500]; _snwprintf(q, 500, L"%ls all network access for\n%ls\n\n%ls", block ? L"Block" : L"Unblock", ins->name, ins->pf.path); if (MessageBoxW(h, q, L"Hodometer", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return 0; char err[160] = ""; if (!fw_block(ins->pf.path, block, err, sizeof err)) { wchar_t e[200]; to_wide(err, e, 200); MessageBoxW(h, e, L"Hodometer", MB_OK | MB_ICONERROR); } else { char p[1200]; jw(ins->pf.path, p, sizeof p); char js[1400]; snprintf(js, sizeof js, "{\"ev\":\"%s\",\"path\":\"%s\",\"by\":\"ui\"}", block ? "blocked" : "unblocked", p); bcast(js); } return 0; }
        }
        return 0;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: KillTimer(h, 1); if (ins) { profile_free(&ins->pf); if (ins->slot >= 0) { g_insp[ins->slot] = NULL; g_insp_pids[ins->slot] = 0; } } zoom_recalc(); return 0;
    case WM_NCDESTROY: if (ins) { free(ins->conns); free(ins->pkts); free(ins->trace); free(ins); SetWindowLongPtrW(h, GWLP_USERDATA, 0); } return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
static void bring_front(HWND h) { ShowWindow(h, SW_SHOWNORMAL); SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SetForegroundWindow(h); }   /* a background process may not take the foreground; the topmost hop still raises the window */
static void insp_open(DWORD pid) {
    Insp *e = insp_find(pid); if (e) { bring_front(e->h); return; }
    int free_slot = -1; for (int i = 0; i < MAX_INSPECT; i++) if (!g_insp[i]) { free_slot = i; break; } if (free_slot < 0) { MessageBoxW(g_main, L"Eight inspectors are already open. Close one first.", L"Hodometer", MB_OK | MB_ICONINFORMATION); return; }
    wchar_t title[160], name[64] = L""; EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p) wcscpy(name, p->name); LeaveCriticalSection(&g_lock); _snwprintf(title, 160, L"Hodometer \x2014 %ls (pid %lu)", name[0] ? name : L"process", (unsigned long)pid);
    RECT wa = { 0, 0, 1920, 1080 }; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0); int ww = 1480, wh = 860; if (ww > wa.right - wa.left - 40) ww = wa.right - wa.left - 40; if (wh > wa.bottom - wa.top - 40) wh = wa.bottom - wa.top - 40;
    HWND hw = CreateWindowExW(0, INSPECT_CLASS, title, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, ww, wh, NULL, NULL, g_inst, (LPVOID)(UINT_PTR)pid);
    if (!hw) return; apply_dark_titlebar(hw); SendMessageW(hw, WM_SETICON, ICON_SMALL, (LPARAM)g_icon_small); SendMessageW(hw, WM_SETICON, ICON_BIG, (LPARAM)g_icon_big); bring_front(hw);
}
static void ui_inspect_selected(void) { int i = selected_index(); if (i < 0) return; insp_open(g_snap[i].pid); }

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        g_main = h;
        g_odo_tx = CreateWindowExW(0, ODO_CLASS, L"OUT", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_ODO_TX, g_inst, (LPVOID)L"BYTES OUT   sent to the internet");
        g_odo_rx = CreateWindowExW(0, ODO_CLASS, L"IN", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_ODO_RX, g_inst, (LPVOID)L"BYTES IN   received"); { Odo *o = (Odo *)GetWindowLongPtrW(g_odo_rx, GWLP_USERDATA); if (o) o->accent = C_BLUE; }
        g_spark = CreateWindowExW(0, SPARK_CLASS, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_SPARK, g_inst, NULL);
        g_status = CreateWindowExW(0, STATUS_CLASS, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_STATUS, g_inst, NULL);
        mk_button(h, IDC_BTN_INSPECT, L"Inspect selected process  \x2014  connections \x00B7 packets \x00B7 timeline", 0); mk_button(h, IDC_BTN_KILL, L"Kill selected process", 1); mk_button(h, IDC_BTN_BLOCK, L"Block program (firewall)", 1); g_btn_audit = mk_button(h, IDC_BTN_AUDIT, L"Re-enable connection auditing", 0); mk_button(h, IDC_BTN_LOCAL, L"Include local / LAN traffic", 2); mk_button(h, IDC_BTN_COPY, L"Copy snapshot (JSON)", 0); mk_button(h, IDC_BTN_HIDE, L"Hide to tray", 0);
        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER, 0, 0, 10, 10, h, (HMENU)IDC_LIST, g_inst, NULL);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, 1); ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP);
        ListView_SetBkColor(g_list, C_BG); ListView_SetTextBkColor(g_list, C_BG); ListView_SetTextColor(g_list, C_TEXT); SetWindowSubclass(g_list, ListSubclass, 1, 0);
        { HIMAGELIST il = ImageList_Create(1, 24, ILC_COLOR32, 1, 1); ListView_SetImageList(g_list, il, LVSIL_SMALL); }   /* 24 px rows */
        dark_mode_window(g_list);   /* dark scrollbars */
        const wchar_t *cols[] = { L"PID", L"Process", L"Out /s", L"In /s", L"Out total", L"In total", L"Top remote", L"Path" }; int widths[] = { 64, 190, 100, 100, 105, 105, 300, 420 };
        for (int i = 0; i < 8; i++) { LVCOLUMNW c = { 0 }; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.pszText = (LPWSTR)cols[i]; c.cx = widths[i]; c.fmt = (i >= 2 && i <= 5) ? LVCFMT_RIGHT : LVCFMT_LEFT; ListView_InsertColumn(g_list, i, &c); }
        layout(); SetTimer(h, ID_TIMER_TICK, 1000, NULL); SetTimer(h, ID_TIMER_AUDIT, 30000, NULL); SetTimer(h, ID_TIMER_TIP, 2000, NULL); return 0; }
    case WM_SIZE: layout(); return 0;
    case WM_GETMINMAXINFO: { MINMAXINFO *mi = (MINMAXINFO *)l; mi->ptMinTrackSize.x = 1000; mi->ptMinTrackSize.y = 560; return 0; }
    case WM_DRAWITEM: draw_button((DRAWITEMSTRUCT *)l); return TRUE;
    case WM_ERASEBKGND: { RECT rc; GetClientRect(h, &rc); HBRUSH br = CreateSolidBrush(C_BG); FillRect((HDC)w, &rc, br); DeleteObject(br); return 1; }
    case WM_TIMER: if (w == ID_TIMER_TICK) tick(); else if (w == ID_TIMER_AUDIT) audit_check(0); else if (w == ID_TIMER_TIP) tray_tip(); return 0;
    case WM_AUTHREQ: if ((int)(INT_PTR)w >= 0 && g_auth_qn < MAX_CLIENTS) g_auth_queue[g_auth_qn++] = (int)w; auth_show_next(); return 0;
    case WM_INSPECT: insp_open((DWORD)w); return 0;
    case WM_SNAP: { wchar_t *path = (wchar_t *)l; HWND tw = (w && IsWindow((HWND)w)) ? (HWND)w : h; int hidden = !IsWindowVisible(tw); if (hidden) ShowWindow(tw, SW_SHOWNOACTIVATE); RedrawWindow(tw, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN); Sleep(60); int ok = save_window_bmp(tw, path); if (hidden) ShowWindow(tw, SW_HIDE); char p[1200]; jw(path, p, sizeof p); char line[1400]; snprintf(line, sizeof line, "{\"ev\":\"snap\",\"path\":\"%s\",\"ok\":%s,\"window\":\"%s\"}", p, ok ? "true" : "false", tw == h ? "main" : "inspector"); bcast(line); free(path); return 0; }
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)l;
        if (nm->idFrom == IDC_LIST && nm->code == LVN_GETDISPINFOW) {
            NMLVDISPINFOW *di = (NMLVDISPINFOW *)l; int i = di->item.iItem; if (!(di->item.mask & LVIF_TEXT) || i < 0 || i >= g_snap_n) return 0;
            static wchar_t bufs[8][512]; wchar_t *b = bufs[di->item.iSubItem & 7]; const Proc *p = &g_snap[i];
            switch (di->item.iSubItem) {
            case 0: _snwprintf(b, 512, L"%lu", (unsigned long)p->pid); break;
            case 1: _snwprintf(b, 512, L"%ls%ls%ls%ls", p->name, p->blocked ? L"  [BLOCKED]" : L"", p->dead ? L"  (exited)" : L"", p->vm ? L"  (VM/host traffic)" : L""); break;
            case 2: if (p->tx_rate > 0) fmt_rate_w(p->tx_rate, b, 512); else wcscpy(b, L"-"); break;
            case 3: if (p->rx_rate > 0) fmt_rate_w(p->rx_rate, b, 512); else wcscpy(b, L"-"); break;
            case 4: fmt_bytes_w(p->tx_total, b, 512); break;
            case 5: fmt_bytes_w(p->rx_total, b, 512); break;
            case 6: { const Remote *r = proc_top_remote(p); if (r) { wchar_t hn[128]; if (host_lookup(r->addr, hn, 128)) _snwprintf(b, 512, L"%ls  (%hs:%u)", hn, r->addr, r->port); else _snwprintf(b, 512, L"%hs:%u", r->addr, r->port); } else wcscpy(b, L""); break; }
            default: wcsncpy(b, p->path, 511); b[511] = 0; break;
            }
            di->item.pszText = b;
        } else if (nm->idFrom == IDC_LIST && nm->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)l;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) { int i = (int)cd->nmcd.dwItemSpec; const Proc *p = (i >= 0 && i < g_snap_n) ? &g_snap[i] : NULL; cd->clrTextBk = (i & 1) ? RGB(22, 23, 29) : C_BG; cd->clrText = C_TEXT; if (p) { if (p->blocked) cd->clrText = C_RED; else if (p->dead) cd->clrText = C_MUTED; else if (p->tx_rate > 0) cd->clrText = C_GREEN; else if (p->rx_rate > 0) cd->clrText = C_BLUE; } return CDRF_NEWFONT; }
        } else if (nm->idFrom == IDC_LIST && nm->code == NM_DBLCLK) { ui_inspect_selected(); }
        else if (nm->idFrom == IDC_LIST && nm->code == NM_RCLICK) { POINT pt; GetCursorPos(&pt); HMENU mn = CreatePopupMenu(); int i = selected_index(); AppendMenuW(mn, MF_STRING, IDM_INSPECT, L"Inspect (zoom in: connections, packets, timeline)"); AppendMenuW(mn, MF_SEPARATOR, 0, NULL); AppendMenuW(mn, MF_STRING, IDM_KILL, L"Kill process"); AppendMenuW(mn, MF_STRING, (i >= 0 && g_snap[i].blocked) ? IDM_UNBLOCK : IDM_BLOCK, (i >= 0 && g_snap[i].blocked) ? L"Unblock program (remove firewall rules)" : L"Block program (firewall rules in+out)"); AppendMenuW(mn, MF_STRING, IDM_COPYPID, L"Copy PID"); TrackPopupMenu(mn, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, NULL); DestroyMenu(mn); }
        else if (nm->idFrom == IDC_LIST && nm->code == LVN_KEYDOWN) { if (((NMLVKEYDOWN *)l)->wVKey == VK_DELETE) ui_kill_selected(); }
        return 0; }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_BTN_INSPECT: case IDM_INSPECT: ui_inspect_selected(); return 0;
        case IDC_BTN_KILL: case IDM_KILL: ui_kill_selected(); return 0;
        case IDC_BTN_BLOCK: case IDM_BLOCK: ui_block_selected(1); return 0;
        case IDM_UNBLOCK: ui_block_selected(0); return 0;
        case IDC_BTN_AUDIT: case IDM_AUDIT: audit_enable(); audit_check(1); return 0;
        case IDC_BTN_LOCAL: InterlockedExchange(&g_include_local, !g_include_local); InvalidateRect(GetDlgItem(h, IDC_BTN_LOCAL), NULL, TRUE); InvalidateRect(g_status, NULL, FALSE); return 0;
        case IDC_BTN_COPY: { static char js[65536]; char *cur = js, *end = js + sizeof js - 2; cur += snprintf(cur, end - cur, "{\"snapshot\":\"Hodometer\",\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,\"procs\":[", g_tx_rate / 1048576.0, g_rx_rate / 1048576.0); for (int i = 0; i < g_snap_n && end - cur > 3000; i++) { if (i) *cur++ = ','; append_proc_json(&cur, end, &g_snap[i]); } *cur++ = ']'; *cur++ = '}'; *cur = 0; static wchar_t wjs[65536]; to_wide(js, wjs, 65536); copy_text(wjs); return 0; }
        case IDC_BTN_HIDE: ShowWindow(h, SW_HIDE); return 0;
        case IDM_COPYPID: { int i = selected_index(); wchar_t s[32]; _snwprintf(s, 32, L"%lu", i >= 0 ? (unsigned long)g_snap[i].pid : 0UL); copy_text(s); return 0; }
        case IDM_SHOW: if (IsWindowVisible(h)) ShowWindow(h, SW_HIDE); else { ShowWindow(h, SW_SHOWNORMAL); SetForegroundWindow(h); } return 0;
        case IDM_PAUSE: InterlockedExchange(&g_paused, !g_paused); InvalidateRect(g_status, NULL, FALSE); return 0;
        case IDM_TRUSTCLEAR: if (MessageBoxW(h, L"Forget all programs allowed with \"Allow always\"? Each will be asked again on its next connection.", L"Hodometer", MB_YESNO | MB_ICONQUESTION) == IDYES) { EnterCriticalSection(&g_tlock); g_ntrust = 0; trust_save(); LeaveCriticalSection(&g_tlock); InvalidateRect(g_status, NULL, FALSE); } return 0;
        case IDM_COPYADDR: { wchar_t s[64]; _snwprintf(s, 64, L"127.0.0.1:%d", g_port); copy_text(s); return 0; }
        case IDM_LOGDIR: ShellExecuteW(NULL, L"open", g_exe_dir, NULL, NULL, SW_SHOWNORMAL); return 0;
        case IDM_OPENREADME: { wchar_t p[MAX_PATH]; _snwprintf(p, MAX_PATH, L"%ls\\README.md", g_exe_dir); ShellExecuteW(NULL, L"open", p, NULL, NULL, SW_SHOWNORMAL); return 0; }
        case IDM_EXIT: g_quitting = 1; DestroyWindow(h); return 0;
        }
        return 0;
    case WM_TRAY: if (LOWORD(l) == WM_LBUTTONUP || LOWORD(l) == WM_LBUTTONDBLCLK) { if (IsWindowVisible(h) && LOWORD(l) == WM_LBUTTONUP) ShowWindow(h, SW_HIDE); else { ShowWindow(h, SW_SHOWNORMAL); SetForegroundWindow(h); } } else if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) tray_menu(); return 0;
    case WM_SHOWME: ShowWindow(h, SW_SHOWNORMAL); SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SetForegroundWindow(h); return 0;
    case WM_SYSCOMMAND: if ((w & 0xFFF0) == SC_MINIMIZE) { ShowWindow(h, SW_HIDE); return 0; } break;
    case WM_CLOSE: if (!g_quitting) { ShowWindow(h, SW_HIDE); return 0; } DestroyWindow(h); return 0;
    case WM_DESTROY: Shell_NotifyIconW(NIM_DELETE, &g_nid); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
static void apply_dark_titlebar(HWND h) { HMODULE dwm = LoadLibraryW(L"dwmapi.dll"); if (!dwm) return; typedef HRESULT (WINAPI *PFN)(HWND, DWORD, LPCVOID, DWORD); PFN f = (PFN)GetProcAddress(dwm, "DwmSetWindowAttribute"); if (!f) return; BOOL one = TRUE; if (FAILED(f(h, 20, &one, sizeof one))) f(h, 19, &one, sizeof one); DWORD corner = 2; f(h, 33, &corner, sizeof corner); COLORREF cap = C_PANEL; f(h, 35, &cap, sizeof cap); }

/* ------------------------------------------------------------------ entry ------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    (void)prev; (void)cmd; (void)show; g_inst = inst; g_start_tick = GetTickCount64();
    int argc = 0; LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc); int start_visible = 0;
    for (int i = 1; i < argc; i++) { if (!wcscmp(argv[i], L"--port") && i + 1 < argc) g_port = _wtoi(argv[++i]); else if (!wcscmp(argv[i], L"--tx") && i + 1 < argc) g_tx_thresh = _wtof(argv[++i]); else if (!wcscmp(argv[i], L"--rx") && i + 1 < argc) g_rx_thresh = _wtof(argv[++i]); else if (!wcscmp(argv[i], L"--auth-timeout") && i + 1 < argc) g_auth_timeout = _wtoi(argv[++i]); else if (!wcscmp(argv[i], L"--show")) start_visible = 1; else if (!wcscmp(argv[i], L"--no-audit-auto")) g_audit_auto = 0; else if (!wcscmp(argv[i], L"--local")) g_include_local = 1; }
    if (g_auth_timeout < 10) g_auth_timeout = 10;
    HANDLE mutex = CreateMutexW(NULL, TRUE, MUTEX_NAME); if (GetLastError() == ERROR_ALREADY_EXISTS) { HWND other = FindWindowW(APP_CLASS, NULL); if (other) PostMessageW(other, WM_SHOWME, 0, 0); return 0; }
    if (!is_elevated()) { wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH); wchar_t args[512] = L""; for (int i = 1; i < argc; i++) { wcscat(args, argv[i]); wcscat(args, L" "); } ReleaseMutex(mutex); CloseHandle(mutex); HINSTANCE r = ShellExecuteW(NULL, L"runas", exe, args, NULL, SW_SHOWNORMAL); if ((INT_PTR)r <= 32) MessageBoxW(NULL, L"Hodometer needs administrator rights (kernel network trace, audit policy, Security log, firewall rules).", L"Hodometer", MB_OK | MB_ICONERROR); return 0; }
    GetModuleFileNameW(NULL, g_exe_dir, MAX_PATH); { wchar_t *s = wcsrchr(g_exe_dir, L'\\'); if (s) *s = 0; }
    _snwprintf(g_log_path, MAX_PATH, L"%ls\\hodometer.log", g_exe_dir); _snwprintf(g_hist_path, MAX_PATH, L"%ls\\history.jsonl", g_exe_dir); _snwprintf(g_trust_path, MAX_PATH, L"%ls\\trusted.jsonl", g_exe_dir); _snwprintf(g_block_path, MAX_PATH, L"%ls\\blocked.jsonl", g_exe_dir);
    SetProcessDPIAware(); InitializeCriticalSection(&g_lock); InitializeCriticalSection(&g_clock); InitializeCriticalSection(&g_hlock); InitializeCriticalSection(&g_tlock); InitializeCriticalSection(&g_zlock); InitializeCriticalSection(&g_jlock); InitializeCriticalSection(&g_slock); InitializeConditionVariable(&g_jcv);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa); INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES }; InitCommonControlsEx(&icc); dark_mode_init();
    g_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); g_font_b = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); g_font_small = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    trust_load(); blocked_load(); audit_init(); audit_check(1);
    g_ptr_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    { char l[200]; snprintf(l, sizeof l, "{\"ev\":\"start\",\"version\":\"%s\",\"port\":%d,\"audit\":\"%s\",\"trusted\":%d,\"blocked\":%d}", APP_VERSION, g_port, audit_str(), g_ntrust, g_nblocked); log_json(l); }
    WNDCLASSW wc = { 0 }; wc.hInstance = inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpfnWndProc = OdoProc; wc.lpszClassName = ODO_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = SparkProc; wc.lpszClassName = SPARK_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = StatusProc; wc.lpszClassName = STATUS_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = AuthProc; wc.lpszClassName = AUTH_CLASS; RegisterClassW(&wc);
    g_font_big = CreateFontW(-21, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    { WNDCLASSW ic = { 0 }; ic.lpfnWndProc = InspProc; ic.hInstance = inst; ic.lpszClassName = INSPECT_CLASS; ic.hCursor = LoadCursor(NULL, IDC_ARROW); ic.hIcon = g_icon_big; RegisterClassW(&ic); }
    g_icon_small = make_icon(16); g_icon_big = make_icon(32);
    WNDCLASSW mc = { 0 }; mc.lpfnWndProc = MainProc; mc.hInstance = inst; mc.lpszClassName = APP_CLASS; mc.hCursor = LoadCursor(NULL, IDC_ARROW); mc.hIcon = g_icon_big; RegisterClassW(&mc);
    HWND hw = CreateWindowExW(0, APP_CLASS, L"Hodometer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1240, 760, NULL, NULL, inst, NULL);
    apply_dark_titlebar(hw); SendMessageW(hw, WM_SETICON, ICON_SMALL, (LPARAM)g_icon_small); SendMessageW(hw, WM_SETICON, ICON_BIG, (LPARAM)g_icon_big);
    tray_add();
    CloseHandle(CreateThread(NULL, 0, etw_thread, NULL, 0, NULL)); CloseHandle(CreateThread(NULL, 0, sock_thread, NULL, 0, NULL)); CloseHandle(CreateThread(NULL, 0, ptr_thread, NULL, 0, NULL)); security_subscribe();
    for (int i = 0; i < CMD_WORKERS; i++) { HANDLE t = CreateThread(NULL, 0, cmd_worker, NULL, 0, NULL); if (t) CloseHandle(t); }
    if (start_visible) { ShowWindow(hw, SW_SHOWNORMAL); UpdateWindow(hw); }
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0) > 0) { if (!g_auth_dlg || !IsDialogMessageW(g_auth_dlg, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
    g_quitting = 1; WakeAllConditionVariable(&g_jcv); etw_stop(); zoom_stop(); cap_stop(0, 1); log_json("{\"ev\":\"stop\"}"); WSACleanup(); ReleaseMutex(mutex); CloseHandle(mutex); return 0;
}
