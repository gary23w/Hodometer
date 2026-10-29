/*  Hodometer 1.1  -  system-tray network monitor for Windows 10/11 (x64). Single C file, Win32 only, no runtime.
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#define APP_VERSION      "1.1.0"
#define APP_CLASS        L"HodometerMain"
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
    DWORD pid;
    wchar_t name[64];
    wchar_t path[MAX_PATH];
    uint64_t tx_total, rx_total, tx_win, rx_win, tx_min, rx_min;
    double tx_rate, rx_rate;
    Remote rem[MAX_REMOTES]; int nrem;
    ULONGLONG last_seen, last_alive_check;
} Proc;
typedef struct { char ip[48]; wchar_t host[128]; int src; ULONGLONG when; } HostEnt;         /* src 1 dns, 2 ptr, 3 negative */
typedef struct { wchar_t path[MAX_PATH]; char sha[65]; char since[24]; } Trust;
typedef struct { wchar_t path[MAX_PATH]; int count; ULONGLONG last; int blocked; } Deny;
typedef struct { wchar_t path[MAX_PATH]; char since[24]; } Blocked;
typedef struct { char t[20]; uint64_t tx, rx; int n; struct { DWORD pid; wchar_t name[48]; uint64_t tx, rx; } p[HIST_PROCS]; } Minute;
#define OUTBUF_MAX (512 * 1024)
typedef struct { SOCKET s; int state; /* 0 free 1 pending 2 allowed 3 deny-close */ int greeted; DWORD pid, ppid; wchar_t path[MAX_PATH]; wchar_t name[64]; char sha[65]; char buf[CLIENT_LINE_MAX]; int len; ULONGLONG since; int once; char *outbuf; int outlen; int overflow; } Client;

static Proc g_procs[MAX_PROCS];
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
static HFONT g_font, g_font_b, g_font_small;
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
    if (e && (src == 1 || !e->host[0] || e->src <= 0)) { wcsncpy(e->host, name, 127); e->host[127] = 0; e->src = src; e->when = GetTickCount64(); }
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
static Proc *proc_find(DWORD pid) { for (int i = 0; i < MAX_PROCS; i++) if (g_procs[i].used && g_procs[i].pid == pid) return &g_procs[i]; return NULL; }
static Proc *proc_get(DWORD pid) {
    Proc *p = proc_find(pid); ULONGLONG now = GetTickCount64();
    if (!p) { int best = -1; ULONGLONG oldest = ~0ULL; for (int i = 0; i < MAX_PROCS; i++) { if (!g_procs[i].used) { best = i; break; } if (g_procs[i].tx_rate == 0 && g_procs[i].rx_rate == 0 && g_procs[i].last_seen < oldest) { oldest = g_procs[i].last_seen; best = i; } } if (best < 0) return NULL; p = &g_procs[best]; memset(p, 0, sizeof *p); p->used = 1; p->pid = pid; }
    else if (p->dead) { memset(p, 0, sizeof *p); p->used = 1; p->pid = pid; }
    p->last_seen = now; return p;
}
static int path_blocked(const wchar_t *path) { for (int i = 0; i < g_nblocked; i++) if (!_wcsicmp(g_blocked[i].path, path)) return 1; return 0; }
static void proc_resolve(Proc *p) {
    if (p->pid == 0) { wcscpy(p->name, L"Idle"); return; }
    if (p->pid == 4) { wcscpy(p->name, L"System"); p->vm = 1; return; }
    if (pid_path(p->pid, p->path, MAX_PATH)) { wcsncpy(p->name, basename_w(p->path), 63); p->name[63] = 0; }
    else if (!p->name[0]) _snwprintf(p->name, 64, L"pid %lu", (unsigned long)p->pid);
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
static void CALLBACK on_event(PEVENT_RECORD r) {
    if (IsEqualGUID(&r->EventHeader.ProviderId, &DnsClientGuid)) { if (r->EventHeader.EventDescriptor.Id == 3008) dns_event((const BYTE *)r->UserData, r->UserDataLength); return; }
    USHORT id = r->EventHeader.EventDescriptor.Id; int send, v6;
    switch (id) { case 10: send = 1; v6 = 0; break; case 11: send = 0; v6 = 0; break; case 26: send = 1; v6 = 1; break; case 27: send = 0; v6 = 1; break; case 42: send = 1; v6 = 0; break; case 43: send = 0; v6 = 0; break; case 58: send = 1; v6 = 1; break; case 59: send = 0; v6 = 1; break; default: return; }
    if (g_paused) return;
    const BYTE *d = (const BYTE *)r->UserData; ULONG n = r->UserDataLength; size_t alen = v6 ? 16 : 4;
    if (n < 8 + 2 * alen + 4) return;
    DWORD pid, size; memcpy(&pid, d, 4); memcpy(&size, d + 4, 4);
    const BYTE *daddr = d + 8; uint16_t dport_n; memcpy(&dport_n, d + 8 + 2 * alen, 2); uint16_t dport = ntohs(dport_n);
    int local = v6 ? is_local6(daddr) : is_local4(daddr);
    if (local && !g_include_local) return;
    char addr[48]; if (!inet_ntop(v6 ? AF_INET6 : AF_INET, (void *)daddr, addr, sizeof addr)) strcpy(addr, "?");
    EnterCriticalSection(&g_lock);
    Proc *p = proc_get(pid);
    if (p) { if (send) { p->tx_total += size; p->tx_win += size; p->tx_min += size; g_tx_total += size; g_tx_win += size; } else { p->rx_total += size; p->rx_win += size; p->rx_min += size; g_rx_total += size; g_rx_win += size; } remote_add(p, addr, dport, send ? size : 0, send ? 0 : size); }
    LeaveCriticalSection(&g_lock);
}
static EVENT_TRACE_PROPERTIES *etw_props(void) { ULONG sz = sizeof(EVENT_TRACE_PROPERTIES) + 2048; EVENT_TRACE_PROPERTIES *p = (EVENT_TRACE_PROPERTIES *)calloc(1, sz); p->Wnode.BufferSize = sz; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID; p->Wnode.ClientContext = 1; p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); p->BufferSize = 64; p->MinimumBuffers = 8; p->MaximumBuffers = 48; p->FlushTimer = 1; return p; }
static DWORD WINAPI etw_thread(LPVOID a) {
    (void)a; EVENT_TRACE_PROPERTIES *p = etw_props(); TRACEHANDLE h = 0; ULONG rc = StartTraceW(&h, SESSION_NAME, p);
    if (rc == ERROR_ALREADY_EXISTS) { ControlTraceW(0, SESSION_NAME, p, EVENT_TRACE_CONTROL_STOP); free(p); p = etw_props(); rc = StartTraceW(&h, SESSION_NAME, p); }
    if (rc != ERROR_SUCCESS) { g_etw_err = rc; InterlockedExchange(&g_etw_state, -1); free(p); return 0; }
    g_session = h;
    rc = EnableTraceEx2(h, &KernelNetworkGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) { g_etw_err = rc; InterlockedExchange(&g_etw_state, -2); free(p); return 0; }
    EnableTraceEx2(h, &DnsClientGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    EVENT_TRACE_LOGFILEW lf; memset(&lf, 0, sizeof lf); lf.LoggerName = (LPWSTR)SESSION_NAME; lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; lf.EventRecordCallback = on_event;
    TRACEHANDLE th = OpenTraceW(&lf); if (th == (TRACEHANDLE)INVALID_HANDLE_VALUE) { g_etw_err = GetLastError(); InterlockedExchange(&g_etw_state, -3); free(p); return 0; }
    InterlockedExchange(&g_etw_state, 1); ProcessTrace(&th, 1, NULL, NULL); CloseTrace(th); free(p);
    if (!g_quitting) InterlockedExchange(&g_etw_state, -4); return 0;
}
static void etw_stop(void) { if (!g_session) return; EVENT_TRACE_PROPERTIES *p = etw_props(); ControlTraceW(g_session, NULL, p, EVENT_TRACE_CONTROL_STOP); free(p); g_session = 0; }

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
static void client_drop(int i) { Client *c = &g_clients[i]; if (c->s != INVALID_SOCKET) { closesocket(c->s); c->s = INVALID_SOCKET; c->state = 0; c->len = 0; } free(c->outbuf); c->outbuf = NULL; c->outlen = 0; c->overflow = 0; }
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
    int n = snprintf(*cur, end - *cur, "{\"pid\":%lu,\"name\":\"%s\",\"tx_bps\":%.0f,\"rx_bps\":%.0f,\"tx_total\":%llu,\"rx_total\":%llu,\"remote\":\"%s\",\"host\":\"%s\",\"blocked\":%s,\"vm\":%s,\"path\":\"%s\"}",
        (unsigned long)p->pid, esc, p->tx_rate, p->rx_rate, (unsigned long long)p->tx_total, (unsigned long long)p->rx_total, rem, hostu, p->blocked ? "true" : "false", p->vm ? "true" : "false", pesc);
    if (n > 0 && *cur + n < end) *cur += n; else **cur = 0;
}
static void build_status(char *out, int n) {
    snprintf(out, n, "{\"reply\":\"status\",\"version\":\"%s\",\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,\"tx_total\":%llu,\"rx_total\":%llu,\"audit\":\"%s\",\"audit_auto\":%s,\"etw\":\"%s\",\"etw_error\":%lu,\"include_local\":%s,\"paused\":%s,\"threshold_tx_mbps\":%.2f,\"threshold_rx_mbps\":%.2f,\"clients\":%d,\"trusted\":%d,\"blocked\":%d,\"conn_events\":%llu,\"history_minutes\":%d,\"uptime_s\":%llu,\"port\":%d}",
        APP_VERSION, g_tx_rate / 1048576.0, g_rx_rate / 1048576.0, (unsigned long long)g_tx_total, (unsigned long long)g_rx_total, audit_str(), g_audit_auto ? "true" : "false", etw_str(), (unsigned long)g_etw_err, g_include_local ? "true" : "false", g_paused ? "true" : "false", g_tx_thresh, g_rx_thresh, client_count(), g_ntrust, g_nblocked, (unsigned long long)g_conn_events, g_hist_n, (unsigned long long)((GetTickCount64() - g_start_tick) / 1000), g_port);
}
static int resolve_target(const char *arg, wchar_t *path, int n) {   /* pid or path -> path */
    path[0] = 0; if (!arg[0]) return 0;
    if (isdigit((unsigned char)arg[0]) && strspn(arg, "0123456789") == strlen(arg)) { DWORD pid = (DWORD)strtoul(arg, NULL, 10); EnterCriticalSection(&g_lock); Proc *p = proc_find(pid); if (p && p->path[0]) wcsncpy(path, p->path, n - 1); LeaveCriticalSection(&g_lock); if (!path[0]) pid_path(pid, path, n); return path[0] != 0; }
    to_wide(arg, path, n); return path[0] != 0;
}
static void handle_command(int ci, char *line) {
    static char big[262144];
    char cmd[32] = "", arg1[1200] = "", arg2[64] = "";
    while (*line == ' ' || *line == '\t') line++; size_t L = strlen(line); while (L && (line[L - 1] == '\r' || line[L - 1] == ' ')) line[--L] = 0; if (!L) return;
    if (line[0] == '{') { json_get_str(line, "cmd", cmd, sizeof cmd); if (!json_get_str(line, "pid", arg1, sizeof arg1)) if (!json_get_str(line, "path", arg1, sizeof arg1)) json_get_str(line, "value", arg1, sizeof arg1); json_get_str(line, "rx", arg2, sizeof arg2); if (!arg2[0]) json_get_str(line, "arg", arg2, sizeof arg2); }
    else { char *sp = strchr(line, ' '); if (sp) { *sp = 0; strncpy(cmd, line, 31); char *rest = sp + 1; while (*rest == ' ') rest++; char *sp2 = (rest[0] == '"') ? NULL : strchr(rest, ' '); if (rest[0] == '"') { char *q = strchr(rest + 1, '"'); if (q) { *q = 0; strncpy(arg1, rest + 1, sizeof arg1 - 1); sp2 = q + 1; while (*sp2 == ' ') sp2++; strncpy(arg2, sp2, 63); } } else if (sp2) { *sp2 = 0; strncpy(arg1, rest, sizeof arg1 - 1); strncpy(arg2, sp2 + 1, 63); } else strncpy(arg1, rest, sizeof arg1 - 1); } else strncpy(cmd, line, 31); }
    for (char *c = cmd; *c; c++) *c = (char)tolower((unsigned char)*c);
    char out[4096];
    if (!strcmp(cmd, "status")) { build_status(out, sizeof out); send_line(ci, out); }
    else if (!strcmp(cmd, "whoami")) { char p[1200], nm[200]; jw(g_clients[ci].path, p, sizeof p); jw(g_clients[ci].name, nm, sizeof nm); snprintf(out, sizeof out, "{\"reply\":\"whoami\",\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\",\"sha256\":\"%s\",\"trusted\":%s}", (unsigned long)g_clients[ci].pid, nm, p, g_clients[ci].sha, g_clients[ci].once ? "false" : "true"); send_line(ci, out); }
    else if (!strcmp(cmd, "clients")) { char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"clients\",\"clients\":["); int first = 1; for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s != INVALID_SOCKET) { char nm[200]; jw(g_clients[i].name, nm, sizeof nm); cur += snprintf(cur, end - cur, "%s{\"pid\":%lu,\"name\":\"%s\",\"state\":\"%s\",\"since_s\":%llu}", first ? "" : ",", (unsigned long)g_clients[i].pid, nm, g_clients[i].state == 2 ? "allowed" : g_clients[i].state == 1 ? "pending" : "closing", (unsigned long long)((GetTickCount64() - g_clients[i].since) / 1000)); first = 0; } cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "list")) {
        char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"list\",\"procs\":["); int first = 1;
        EnterCriticalSection(&g_lock); for (int i = 0; i < MAX_PROCS; i++) { const Proc *p = &g_procs[i]; if (!p->used || (p->tx_total == 0 && p->rx_total == 0)) continue; if (!first) { if (cur < end) *cur++ = ','; } first = 0; append_proc_json(&cur, end, p); if (end - cur < 3000) break; } LeaveCriticalSection(&g_lock);
        if (cur < end) { *cur++ = ']'; *cur++ = '}'; } *cur = 0; send_line(ci, big);
    }
    else if (!strcmp(cmd, "kill")) { DWORD pid = (DWORD)strtoul(arg1, NULL, 10); char err[160] = ""; int ok = pid ? kill_pid(pid, err, sizeof err) : 0; if (!pid) strcpy(err, "usage: kill <pid>"); char e[320]; json_escape(err, e, sizeof e); snprintf(out, sizeof out, "{\"reply\":\"kill\",\"pid\":%lu,\"ok\":%s,\"error\":\"%s\"}", (unsigned long)pid, ok ? "true" : "false", e); send_line(ci, out); if (ok) { char nm[200]; jw(g_clients[ci].name, nm, sizeof nm); snprintf(out, sizeof out, "{\"ev\":\"killed\",\"pid\":%lu,\"by\":\"socket:%s\"}", (unsigned long)pid, nm); bcast(out); } }
    else if (!strcmp(cmd, "block") || !strcmp(cmd, "unblock")) { wchar_t path[MAX_PATH]; char err[160] = ""; int ok = 0; if (resolve_target(arg1, path, MAX_PATH)) ok = fw_block(path, cmd[0] == 'b', err, sizeof err); else strcpy(err, "usage: block <pid|path> (path quoted if it has spaces)"); char p[1200], e[320]; jw(path, p, sizeof p); json_escape(err, e, sizeof e); snprintf(out, sizeof out, "{\"reply\":\"%s\",\"path\":\"%s\",\"ok\":%s,\"error\":\"%s\"}", cmd, p, ok ? "true" : "false", e); send_line(ci, out); if (ok) { snprintf(out, sizeof out, "{\"ev\":\"%sed\",\"path\":\"%s\"}", cmd, p); bcast(out); } }
    else if (!strcmp(cmd, "blocks")) { char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"blocks\",\"blocked\":["); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_nblocked; i++) { char p[1200]; jw(g_blocked[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"since\":\"%s\"}", i ? "," : "", p, g_blocked[i].since); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "trust")) {
        if (!strcmp(arg1, "clear")) { EnterCriticalSection(&g_tlock); g_ntrust = 0; trust_save(); LeaveCriticalSection(&g_tlock); send_line(ci, "{\"reply\":\"trust\",\"ok\":true,\"trusted\":0}"); }
        else if (!strcmp(arg1, "remove")) { int removed = 0; wchar_t w[300]; to_wide(arg2, w, 300); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ntrust; i++) { wchar_t lp[MAX_PATH], lw[300]; wcscpy(lp, g_trust[i].path); wcscpy(lw, w); _wcslwr(lp); _wcslwr(lw); if (lw[0] && wcsstr(lp, lw)) { g_trust[i] = g_trust[--g_ntrust]; i--; removed++; } } trust_save(); LeaveCriticalSection(&g_tlock); snprintf(out, sizeof out, "{\"reply\":\"trust\",\"removed\":%d,\"trusted\":%d}", removed, g_ntrust); send_line(ci, out); }
        else { char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"trust\",\"trusted\":["); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ntrust; i++) { char p[1200]; jw(g_trust[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"sha256\":\"%s\",\"since\":\"%s\"}", i ? "," : "", p, g_trust[i].sha, g_trust[i].since); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    }
    else if (!strcmp(cmd, "snap")) {   /* capture the main window to a .bmp (default: snapshot.bmp next to the exe); an AI can look at the GUI */
        wchar_t *path = (wchar_t *)calloc(MAX_PATH, sizeof(wchar_t)); if (arg1[0]) to_wide(arg1, path, MAX_PATH); else _snwprintf(path, MAX_PATH, L"%ls\\snapshot.bmp", g_exe_dir);
        char p[1200]; jw(path, p, sizeof p); snprintf(out, sizeof out, "{\"reply\":\"snap\",\"path\":\"%s\",\"scheduled\":true,\"note\":\"a 'snap' event follows when the file is written\"}", p); send_line(ci, out);
        PostMessageW(g_main, WM_SNAP, 0, (LPARAM)path);
    }
    else if (!strcmp(cmd, "denials")) { char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"denials\",\"suspended\":%s,\"denied\":[", GetTickCount64() < g_auth_suspended_until ? "true" : "false"); EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ndeny; i++) { char p[1200]; jw(g_deny[i].path, p, sizeof p); cur += snprintf(cur, end - cur, "%s{\"path\":\"%s\",\"count\":%d,\"blocked\":%s,\"cooldown_s\":%lld}", i ? "," : "", p, g_deny[i].count, g_deny[i].blocked ? "true" : "false", (long long)((600000 - (GetTickCount64() - g_deny[i].last)) / 1000 > 0 ? (600000 - (GetTickCount64() - g_deny[i].last)) / 1000 : 0)); } LeaveCriticalSection(&g_tlock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big); }
    else if (!strcmp(cmd, "pardon")) {   /* clear denial record (and firewall block) for programs whose path contains the argument */
        int n = 0; wchar_t w[300]; to_wide(arg1, w, 300); _wcslwr(w);
        EnterCriticalSection(&g_tlock); for (int i = 0; i < g_ndeny && w[0]; i++) { wchar_t lp[MAX_PATH]; wcscpy(lp, g_deny[i].path); _wcslwr(lp); if (wcsstr(lp, w)) { wchar_t path[MAX_PATH]; wcscpy(path, g_deny[i].path); int wasblocked = g_deny[i].blocked; g_deny[i] = g_deny[--g_ndeny]; i--; n++; LeaveCriticalSection(&g_tlock); if (wasblocked) { char err[160]; fw_block(path, 0, err, sizeof err); } EnterCriticalSection(&g_tlock); } } LeaveCriticalSection(&g_tlock);
        snprintf(out, sizeof out, "{\"reply\":\"pardon\",\"cleared\":%d}", n); send_line(ci, out);
    }
    else if (!strcmp(cmd, "history")) {
        int mins = atoi(arg1); if (mins <= 0) mins = 60; if (mins > HIST_MIN) mins = HIST_MIN;
        char *cur = big, *end = big + sizeof big - 2; cur += snprintf(cur, end - cur, "{\"reply\":\"history\",\"minutes\":[");
        EnterCriticalSection(&g_lock); int n = g_hist_n < mins ? g_hist_n : mins; int first = 1;
        for (int k = n; k >= 1 && end - cur > 4000; k--) { const Minute *m = &g_hist[(g_hist_i - k + HIST_MIN) % HIST_MIN]; cur += snprintf(cur, end - cur, "%s{\"t\":\"%s\",\"tx\":%llu,\"rx\":%llu,\"procs\":[", first ? "" : ",", m->t, (unsigned long long)m->tx, (unsigned long long)m->rx); first = 0; for (int j = 0; j < m->n && j < 10; j++) { char nm[160]; jw(m->p[j].name, nm, sizeof nm); cur += snprintf(cur, end - cur, "%s{\"pid\":%lu,\"name\":\"%s\",\"tx\":%llu,\"rx\":%llu}", j ? "," : "", (unsigned long)m->p[j].pid, nm, (unsigned long long)m->p[j].tx, (unsigned long long)m->p[j].rx); } cur += snprintf(cur, end - cur, "]}"); }
        LeaveCriticalSection(&g_lock); cur += snprintf(cur, end - cur, "]}"); send_line(ci, big);
    }
    else if (!strcmp(cmd, "resolve")) { wchar_t h[128]; int src = host_lookup(arg1, h, 128); char hu[300]; jw(h, hu, sizeof hu); char ip[64]; json_escape(arg1, ip, sizeof ip); snprintf(out, sizeof out, "{\"reply\":\"resolve\",\"ip\":\"%s\",\"host\":\"%s\",\"source\":\"%s\"}", ip, hu, src == 1 ? "dns" : src == 2 ? "ptr" : "pending"); send_line(ci, out); }
    else if (!strcmp(cmd, "audit")) { if (!strcmp(arg1, "on")) { int ok = audit_enable(); InterlockedExchange(&g_audit_ok, audit_query()); snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"set_ok\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", ok ? "true" : "false", g_audit_auto ? "true" : "false"); } else if (!strcmp(arg1, "auto")) { g_audit_auto = strcmp(arg2, "off") != 0; snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", g_audit_auto ? "true" : "false"); } else { InterlockedExchange(&g_audit_ok, audit_query()); snprintf(out, sizeof out, "{\"reply\":\"audit\",\"enabled\":%s,\"auto\":%s}", g_audit_ok == 1 ? "true" : "false", g_audit_auto ? "true" : "false"); } send_line(ci, out); }
    else if (!strcmp(cmd, "threshold")) { double tx = atof(arg1), rx = atof(arg2); if (tx > 0) g_tx_thresh = tx; if (rx > 0) g_rx_thresh = rx; snprintf(out, sizeof out, "{\"reply\":\"threshold\",\"tx_mbps\":%.2f,\"rx_mbps\":%.2f}", g_tx_thresh, g_rx_thresh); send_line(ci, out); }
    else if (!strcmp(cmd, "local")) { InterlockedExchange(&g_include_local, !strcmp(arg1, "on")); if (g_main) InvalidateRect(g_main, NULL, TRUE); snprintf(out, sizeof out, "{\"reply\":\"local\",\"include_local\":%s}", g_include_local ? "true" : "false"); send_line(ci, out); }
    else if (!strcmp(cmd, "pause")) { InterlockedExchange(&g_paused, strcmp(arg1, "off") != 0); snprintf(out, sizeof out, "{\"reply\":\"pause\",\"paused\":%s}", g_paused ? "true" : "false"); send_line(ci, out); }
    else if (!strcmp(cmd, "reset")) { EnterCriticalSection(&g_lock); memset(g_procs, 0, sizeof g_procs); g_tx_total = g_rx_total = 0; LeaveCriticalSection(&g_lock); send_line(ci, "{\"reply\":\"reset\",\"ok\":true}"); }
    else if (!strcmp(cmd, "show")) { if (g_main) PostMessageW(g_main, WM_SHOWME, 0, 0); send_line(ci, "{\"reply\":\"show\",\"ok\":true}"); }
    else if (!strcmp(cmd, "help")) send_line(ci, "{\"reply\":\"help\",\"commands\":[\"status\",\"whoami\",\"clients\",\"list\",\"kill <pid>\",\"block <pid|path>\",\"unblock <pid|path>\",\"blocks\",\"trust [list|remove <substr>|clear]\",\"denials\",\"pardon <path-substr>\",\"history [minutes]\",\"snap [file.bmp]\",\"resolve <ip>\",\"audit [on|status|auto on|auto off]\",\"threshold <tx_mbps> [rx_mbps]\",\"local on|off\",\"pause on|off\",\"reset\",\"show\",\"help\"],\"events\":[\"hello\",\"auth\",\"tick\",\"spike\",\"conn\",\"killed\",\"blocked\",\"unblocked\",\"intruder\",\"audit\"],\"json_form\":\"{\\\"cmd\\\":\\\"kill\\\",\\\"pid\\\":123}\"}");
    else { char cesc[80]; json_escape(cmd, cesc, sizeof cesc); snprintf(out, sizeof out, "{\"reply\":\"error\",\"error\":\"unknown command '%s' (try help)\"}", cesc); send_line(ci, out); }
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
                for (int i = 0; i < MAX_CLIENTS; i++) if (g_clients[i].s == INVALID_SOCKET) { Client *cl = &g_clients[i]; memset(cl, 0, sizeof *cl); cl->s = c; cl->since = now; cl->pid = pid; cl->ppid = parent_pid(pid); wcscpy(cl->path, path); wcsncpy(cl->name, path[0] ? basename_w(path) : L"(unknown)", 63); strcpy(cl->sha, sha); cl->state = decision == 2 ? 2 : decision == 3 ? 3 : 1; placed = i; break; }
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
            static char lines[16][CLIENT_LINE_MAX]; int nl = 0, allowed = cl->state == 2;
            for (int k = 0; k < n; k++) { char ch = tmp[k]; if (ch == '\n') { cl->buf[cl->len] = 0; if (nl < 16) strcpy(lines[nl++], cl->buf); cl->len = 0; } else if (cl->len < CLIENT_LINE_MAX - 1) cl->buf[cl->len++] = ch; else cl->len = 0; }
            LeaveCriticalSection(&g_clock);
            for (int k = 0; k < nl; k++) { if (allowed) handle_command(i, lines[k]); else send_line(i, "{\"reply\":\"error\",\"error\":\"not allowed yet\"}"); }   /* commands run outside the client lock (they may take seconds) */
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
static LRESULT CALLBACK BtnSubclass(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref) {   /* hover tracking for owner-drawn buttons */
    (void)id; (void)ref;
    if (m == WM_MOUSEMOVE) { LONG_PTR d = GetWindowLongPtrW(h, GWLP_USERDATA); if (!(d & 0x100)) { SetWindowLongPtrW(h, GWLP_USERDATA, d | 0x100); TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, h, 0 }; TrackMouseEvent(&t); InvalidateRect(h, NULL, TRUE); } }
    else if (m == WM_MOUSELEAVE) { LONG_PTR d = GetWindowLongPtrW(h, GWLP_USERDATA); SetWindowLongPtrW(h, GWLP_USERDATA, d & ~(LONG_PTR)0x100); InvalidateRect(h, NULL, TRUE); }
    return DefSubclassProc(h, m, w, l);
}
static void draw_button(DRAWITEMSTRUCT *di) {
    LONG_PTR data = GetWindowLongPtrW(di->hwndItem, GWLP_USERDATA); int kind = (int)(data & 0xff), hot = (data & 0x100) != 0;   /* kind: 0 normal, 1 danger, 2 toggle */
    int pressed = di->itemState & ODS_SELECTED, disabled = di->itemState & ODS_DISABLED, focus = di->itemState & ODS_FOCUS;
    HDC dc = di->hDC; RECT r = di->rcItem;
    COLORREF accent = kind == 1 ? C_RED : C_BLUE;
    COLORREF fill = pressed ? RGB(38, 41, 52) : hot ? RGB(40, 44, 56) : C_CELL, border = (focus || hot) ? accent : C_BORDER, text = disabled ? C_MUTED : (kind == 1 ? C_RED : C_TEXT);
    if (kind == 2 && g_include_local) { fill = RGB(34, 52, 44); border = C_GREEN; }
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
    for (int i = 0; i < MAX_PROCS; i++) { Proc *p = &g_procs[i]; if (!p->used) continue; p->tx_rate = (double)p->tx_win; p->rx_rate = (double)p->rx_win; p->tx_win = p->rx_win = 0; if (!p->name[0] || (!p->path[0] && now - p->last_alive_check > 5000)) { proc_resolve(p); p->last_alive_check = now; } else if (now - p->last_alive_check > 7000) { p->last_alive_check = now; if (!p->dead && !proc_alive(p->pid)) p->dead = 1; } }
    SYSTEMTIME st; GetLocalTime(&st); int minute = st.wHour * 60 + st.wMinute; if (g_cur_minute >= 0 && minute != g_cur_minute) history_rotate_minute(); g_cur_minute = minute;
    g_snap_n = 0; for (int i = 0; i < MAX_PROCS; i++) { const Proc *p = &g_procs[i]; if (p->used && (p->tx_total || p->rx_total)) g_snap[g_snap_n++] = *p; }
    LeaveCriticalSection(&g_lock);
    qsort(g_snap, g_snap_n, sizeof(Proc), cmp_snap); InterlockedExchange(&g_conn_this_sec, 0);
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
    MoveWindow(GetDlgItem(g_main, IDC_BTN_KILL), bx, 12, bw, 36, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_BLOCK), bx + bw + 8, 12, bw, 36, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_AUDIT), bx, 60, bw, 36, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_LOCAL), bx + bw + 8, 60, bw, 36, TRUE);
    MoveWindow(GetDlgItem(g_main, IDC_BTN_COPY), bx, 108, bw, 36, TRUE); MoveWindow(GetDlgItem(g_main, IDC_BTN_HIDE), bx + bw + 8, 108, bw, 36, TRUE);
    MoveWindow(g_spark, 8, 174, W - 16, 86, TRUE); MoveWindow(g_status, 8, 266, W - 16, 30, TRUE); MoveWindow(g_list, 8, 304, W - 16, H - 312, TRUE);
}
static LRESULT CALLBACK ListSubclass(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref) {
    (void)id; (void)ref;
    if (m == WM_NOTIFY) { NMHDR *nm = (NMHDR *)l; if (nm->hwndFrom == ListView_GetHeader(h) && nm->code == NM_CUSTOMDRAW) { NMCUSTOMDRAW *cd = (NMCUSTOMDRAW *)l; if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW; if (cd->dwDrawStage == CDDS_ITEMPREPAINT) { HBRUSH b = CreateSolidBrush(C_PANEL); FillRect(cd->hdc, &cd->rc, b); DeleteObject(b); wchar_t t[64] = L""; HDITEMW hi = { 0 }; hi.mask = HDI_TEXT | HDI_FORMAT; hi.pszText = t; hi.cchTextMax = 64; Header_GetItem(nm->hwndFrom, (int)cd->dwItemSpec, &hi); SetBkMode(cd->hdc, TRANSPARENT); SetTextColor(cd->hdc, C_MUTED); SelectObject(cd->hdc, g_font_b); RECT r = cd->rc; r.left += 8; r.right -= 8; DrawTextW(cd->hdc, t, -1, &r, ((hi.fmt & HDF_RIGHT) ? DT_RIGHT : DT_LEFT) | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS); HPEN p = CreatePen(PS_SOLID, 1, C_BORDER); HGDIOBJ op = SelectObject(cd->hdc, p); MoveToEx(cd->hdc, cd->rc.right - 1, cd->rc.top, NULL); LineTo(cd->hdc, cd->rc.right - 1, cd->rc.bottom); MoveToEx(cd->hdc, cd->rc.left, cd->rc.bottom - 1, NULL); LineTo(cd->hdc, cd->rc.right, cd->rc.bottom - 1); SelectObject(cd->hdc, op); DeleteObject(p); return CDRF_SKIPDEFAULT; } } }
    return DefSubclassProc(h, m, w, l);
}
static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        g_main = h;
        g_odo_tx = CreateWindowExW(0, ODO_CLASS, L"OUT", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_ODO_TX, g_inst, (LPVOID)L"BYTES OUT   sent to the internet");
        g_odo_rx = CreateWindowExW(0, ODO_CLASS, L"IN", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_ODO_RX, g_inst, (LPVOID)L"BYTES IN   received"); { Odo *o = (Odo *)GetWindowLongPtrW(g_odo_rx, GWLP_USERDATA); if (o) o->accent = C_BLUE; }
        g_spark = CreateWindowExW(0, SPARK_CLASS, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_SPARK, g_inst, NULL);
        g_status = CreateWindowExW(0, STATUS_CLASS, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, h, (HMENU)IDC_STATUS, g_inst, NULL);
        mk_button(h, IDC_BTN_KILL, L"Kill selected process", 1); mk_button(h, IDC_BTN_BLOCK, L"Block program (firewall)", 1); g_btn_audit = mk_button(h, IDC_BTN_AUDIT, L"Re-enable connection auditing", 0); mk_button(h, IDC_BTN_LOCAL, L"Include local / LAN traffic", 2); mk_button(h, IDC_BTN_COPY, L"Copy snapshot (JSON)", 0); mk_button(h, IDC_BTN_HIDE, L"Hide to tray", 0);
        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER, 0, 0, 10, 10, h, (HMENU)IDC_LIST, g_inst, NULL);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, 1); ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP);
        ListView_SetBkColor(g_list, C_BG); ListView_SetTextBkColor(g_list, C_BG); ListView_SetTextColor(g_list, C_TEXT); SetWindowSubclass(g_list, ListSubclass, 1, 0);
        { HIMAGELIST il = ImageList_Create(1, 24, ILC_COLOR32, 1, 1); ListView_SetImageList(g_list, il, LVSIL_SMALL); }   /* 24 px rows */
        { HMODULE ux = LoadLibraryW(L"uxtheme.dll"); if (ux) { typedef HRESULT (WINAPI *PFN)(HWND, LPCWSTR, LPCWSTR); PFN swt = (PFN)GetProcAddress(ux, "SetWindowTheme"); if (swt) swt(g_list, L"DarkMode_Explorer", NULL); } }   /* dark scrollbars */
        const wchar_t *cols[] = { L"PID", L"Process", L"Out /s", L"In /s", L"Out total", L"In total", L"Top remote", L"Path" }; int widths[] = { 64, 190, 100, 100, 105, 105, 300, 420 };
        for (int i = 0; i < 8; i++) { LVCOLUMNW c = { 0 }; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.pszText = (LPWSTR)cols[i]; c.cx = widths[i]; c.fmt = (i >= 2 && i <= 5) ? LVCFMT_RIGHT : LVCFMT_LEFT; ListView_InsertColumn(g_list, i, &c); }
        layout(); SetTimer(h, ID_TIMER_TICK, 1000, NULL); SetTimer(h, ID_TIMER_AUDIT, 30000, NULL); SetTimer(h, ID_TIMER_TIP, 2000, NULL); return 0; }
    case WM_SIZE: layout(); return 0;
    case WM_GETMINMAXINFO: { MINMAXINFO *mi = (MINMAXINFO *)l; mi->ptMinTrackSize.x = 1000; mi->ptMinTrackSize.y = 560; return 0; }
    case WM_DRAWITEM: draw_button((DRAWITEMSTRUCT *)l); return TRUE;
    case WM_ERASEBKGND: { RECT rc; GetClientRect(h, &rc); HBRUSH br = CreateSolidBrush(C_BG); FillRect((HDC)w, &rc, br); DeleteObject(br); return 1; }
    case WM_TIMER: if (w == ID_TIMER_TICK) tick(); else if (w == ID_TIMER_AUDIT) audit_check(0); else if (w == ID_TIMER_TIP) tray_tip(); return 0;
    case WM_AUTHREQ: if ((int)(INT_PTR)w >= 0 && g_auth_qn < MAX_CLIENTS) g_auth_queue[g_auth_qn++] = (int)w; auth_show_next(); return 0;
    case WM_SNAP: { wchar_t *path = (wchar_t *)l; int hidden = !IsWindowVisible(h); if (hidden) ShowWindow(h, SW_SHOWNOACTIVATE); RedrawWindow(h, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN); Sleep(60); int ok = save_window_bmp(h, path); if (hidden) ShowWindow(h, SW_HIDE); char p[1200]; jw(path, p, sizeof p); char line[1400]; snprintf(line, sizeof line, "{\"ev\":\"snap\",\"path\":\"%s\",\"ok\":%s}", p, ok ? "true" : "false"); bcast(line); free(path); return 0; }
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
        } else if (nm->idFrom == IDC_LIST && nm->code == NM_RCLICK) { POINT pt; GetCursorPos(&pt); HMENU mn = CreatePopupMenu(); int i = selected_index(); AppendMenuW(mn, MF_STRING, IDM_KILL, L"Kill process"); AppendMenuW(mn, MF_STRING, (i >= 0 && g_snap[i].blocked) ? IDM_UNBLOCK : IDM_BLOCK, (i >= 0 && g_snap[i].blocked) ? L"Unblock program (remove firewall rules)" : L"Block program (firewall rules in+out)"); AppendMenuW(mn, MF_STRING, IDM_COPYPID, L"Copy PID"); TrackPopupMenu(mn, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, NULL); DestroyMenu(mn); }
        else if (nm->idFrom == IDC_LIST && nm->code == LVN_KEYDOWN) { if (((NMLVKEYDOWN *)l)->wVKey == VK_DELETE) ui_kill_selected(); }
        return 0; }
    case WM_COMMAND:
        switch (LOWORD(w)) {
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
    SetProcessDPIAware(); InitializeCriticalSection(&g_lock); InitializeCriticalSection(&g_clock); InitializeCriticalSection(&g_hlock); InitializeCriticalSection(&g_tlock);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa); INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES }; InitCommonControlsEx(&icc);
    g_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); g_font_b = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); g_font_small = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    trust_load(); blocked_load(); audit_init(); audit_check(1);
    g_ptr_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    { char l[200]; snprintf(l, sizeof l, "{\"ev\":\"start\",\"version\":\"%s\",\"port\":%d,\"audit\":\"%s\",\"trusted\":%d,\"blocked\":%d}", APP_VERSION, g_port, audit_str(), g_ntrust, g_nblocked); log_json(l); }
    WNDCLASSW wc = { 0 }; wc.hInstance = inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpfnWndProc = OdoProc; wc.lpszClassName = ODO_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = SparkProc; wc.lpszClassName = SPARK_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = StatusProc; wc.lpszClassName = STATUS_CLASS; RegisterClassW(&wc); wc.lpfnWndProc = AuthProc; wc.lpszClassName = AUTH_CLASS; RegisterClassW(&wc);
    g_icon_small = make_icon(16); g_icon_big = make_icon(32);
    WNDCLASSW mc = { 0 }; mc.lpfnWndProc = MainProc; mc.hInstance = inst; mc.lpszClassName = APP_CLASS; mc.hCursor = LoadCursor(NULL, IDC_ARROW); mc.hIcon = g_icon_big; RegisterClassW(&mc);
    HWND hw = CreateWindowExW(0, APP_CLASS, L"Hodometer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1240, 760, NULL, NULL, inst, NULL);
    apply_dark_titlebar(hw); SendMessageW(hw, WM_SETICON, ICON_SMALL, (LPARAM)g_icon_small); SendMessageW(hw, WM_SETICON, ICON_BIG, (LPARAM)g_icon_big);
    tray_add();
    CloseHandle(CreateThread(NULL, 0, etw_thread, NULL, 0, NULL)); CloseHandle(CreateThread(NULL, 0, sock_thread, NULL, 0, NULL)); CloseHandle(CreateThread(NULL, 0, ptr_thread, NULL, 0, NULL)); security_subscribe();
    if (start_visible) { ShowWindow(hw, SW_SHOWNORMAL); UpdateWindow(hw); }
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0) > 0) { if (!g_auth_dlg || !IsDialogMessageW(g_auth_dlg, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
    g_quitting = 1; etw_stop(); log_json("{\"ev\":\"stop\"}"); WSACleanup(); ReleaseMutex(mutex); CloseHandle(mutex); return 0;
}
