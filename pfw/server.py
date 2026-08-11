"""PrivateFirewall — a user-mode control plane on top of Windows Firewall (WFP).

Architecture: Windows Firewall / WFP already sits in the kernel as the entry
point for ALL wired + wireless traffic. This engine does not re-route packets
(fail-open by design: if this process dies, WFP keeps enforcing the configured
policy). It provides:

  * live connection table (TCP v4/v6 + UDP listeners) with process attribution
  * per-interface throughput statistics
  * kill switch for individual TCP connections (SetTcpEntry)
  * dynamic block/allow rules managed in the Windows Firewall rule group
    "PrivateFirewall" (so one command can revert everything this app created)
  * firewall drop-log tailing (blocked-connection feed)
  * alert engine: port scans, brute-force repeats, new listening ports,
    suspicious executable paths, plaintext-DNS bypass, fan-out, upload surges
  * localhost-only JSON API + dashboard, token-authenticated

Requires: Python 3.x (stdlib only), Windows 10/11. Admin for kill/block/lockdown.
"""

import ctypes
import ctypes.wintypes as wt
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import tempfile
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config as cfgmod   # pfw/config.py — editable profile (bundled)

# The app ships as a WINDOWED (no-console) exe so nothing can accidentally
# close it. PyInstaller windowed mode leaves sys.stdout/stderr as None, which
# makes any print() raise — redirect them to a sink so the engine never crashes.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")

# --------------------------------------------------------------------------
# constants / config
# --------------------------------------------------------------------------

FROZEN = getattr(sys, "frozen", False)
if FROZEN:
    RES_DIR = sys._MEIPASS                      # PyInstaller-bundled dashboard.html
    APP_DIR = os.path.dirname(sys.executable)   # where the installed exe lives
else:
    RES_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = os.path.dirname(RES_DIR)          # repo root
# logs: override with PFW_LOG_DIR; installed default is %ProgramData%, else repo
LOG_DIR = os.environ.get("PFW_LOG_DIR") or (
    os.path.join(os.environ.get("ProgramData", APP_DIR), "PrivateFirewall", "logs")
    if FROZEN else os.path.join(APP_DIR, "logs"))
CONFIG_PATH = os.environ.get("PFW_CONFIG") or \
    os.path.join(os.path.dirname(LOG_DIR), "config.json")
RULE_GROUP = "PrivateFirewall"
BIND_HOST = "127.0.0.1"
BIND_PORT = int(os.environ.get("PFW_PORT", "58730"))
POLL_SECS = 2.0
PS_REFRESH_SECS = 60.0
HISTORY_LEN = 240          # 240 * 2s = 8 minutes of throughput history
EVENT_KEEP = 400
ALERT_KEEP = 200

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

iphlpapi = ctypes.WinDLL("iphlpapi")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

IS_ADMIN = bool(shell32.IsUserAnAdmin())

# --------------------------------------------------------------------------
# ctypes structures
# --------------------------------------------------------------------------

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
                ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
                ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]

class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wt.DWORD),
                ("dwLocalPort", wt.DWORD), ("ucRemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wt.DWORD), ("dwRemotePort", wt.DWORD),
                ("dwState", wt.DWORD), ("dwOwningPid", wt.DWORD)]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwOwningPid", wt.DWORD)]

class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
                ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
                ("dwRemotePort", wt.DWORD)]

MAX_INTERFACE_NAME_LEN = 256
MAXLEN_IFDESCR = 256
MAXLEN_PHYSADDR = 8

class MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", wt.WCHAR * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", wt.DWORD), ("dwType", wt.DWORD), ("dwMtu", wt.DWORD),
        ("dwSpeed", wt.DWORD), ("dwPhysAddrLen", wt.DWORD),
        ("bPhysAddr", ctypes.c_ubyte * MAXLEN_PHYSADDR),
        ("dwAdminStatus", wt.DWORD), ("dwOperStatus", wt.DWORD),
        ("dwLastChange", wt.DWORD), ("dwInOctets", wt.DWORD),
        ("dwInUcastPkts", wt.DWORD), ("dwInNUcastPkts", wt.DWORD),
        ("dwInDiscards", wt.DWORD), ("dwInErrors", wt.DWORD),
        ("dwInUnknownProtos", wt.DWORD), ("dwOutOctets", wt.DWORD),
        ("dwOutUcastPkts", wt.DWORD), ("dwOutNUcastPkts", wt.DWORD),
        ("dwOutDiscards", wt.DWORD), ("dwOutErrors", wt.DWORD),
        ("dwOutQLen", wt.DWORD), ("dwDescrLen", wt.DWORD),
        ("bDescr", ctypes.c_char * (MAXLEN_IFDESCR + 1)),
    ]

# --------------------------------------------------------------------------
# low-level snapshots
# --------------------------------------------------------------------------

def _get_table(fn, af, table_class, row_type):
    size = wt.DWORD(0)
    fn(None, ctypes.byref(size), False, af, table_class, 0)
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if fn(buf, ctypes.byref(size), False, af, table_class, 0) != 0:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    rows = ctypes.cast(ctypes.byref(buf, 8 if row_type is MIB_TCP6ROW_OWNER_PID
                                    else 4), ctypes.POINTER(row_type * count)).contents
    return list(rows)

def _v4(dw):
    return socket.inet_ntoa(struct.pack("<I", dw))

def _port(dw):
    return socket.ntohs(dw & 0xFFFF)

def snapshot_tcp():
    out = []
    for row in _get_table(iphlpapi.GetExtendedTcpTable, AF_INET,
                          TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID):
        out.append({
            "proto": "TCP", "pid": row.dwOwningPid,
            "laddr": _v4(row.dwLocalAddr), "lport": _port(row.dwLocalPort),
            "raddr": _v4(row.dwRemoteAddr), "rport": _port(row.dwRemotePort),
            "state": TCP_STATES.get(row.dwState, str(row.dwState)),
            # raw values so /api/kill can rebuild the exact MIB_TCPROW
            "kill": [row.dwLocalAddr, row.dwLocalPort,
                     row.dwRemoteAddr, row.dwRemotePort],
        })
    for row in _get_table(iphlpapi.GetExtendedTcpTable, AF_INET6,
                          TCP_TABLE_OWNER_PID_ALL, MIB_TCP6ROW_OWNER_PID):
        out.append({
            "proto": "TCP6", "pid": row.dwOwningPid,
            "laddr": socket.inet_ntop(socket.AF_INET6, bytes(row.ucLocalAddr)),
            "lport": _port(row.dwLocalPort),
            "raddr": socket.inet_ntop(socket.AF_INET6, bytes(row.ucRemoteAddr)),
            "rport": _port(row.dwRemotePort),
            "state": TCP_STATES.get(row.dwState, str(row.dwState)),
            "kill": None,   # SetTcpEntry has no IPv6 counterpart
        })
    return out

def snapshot_udp():
    out = []
    for row in _get_table(iphlpapi.GetExtendedUdpTable, AF_INET,
                          UDP_TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID):
        out.append({"proto": "UDP", "pid": row.dwOwningPid,
                    "laddr": _v4(row.dwLocalAddr), "lport": _port(row.dwLocalPort),
                    "raddr": "*", "rport": 0, "state": "LISTEN", "kill": None})
    return out

def kill_tcp(l_addr, l_port, r_addr, r_port):
    """Terminate a TCP v4 connection. Values are the raw DWORDs from snapshot."""
    row = MIB_TCPROW(12, l_addr, l_port, r_addr, r_port)   # 12 = DELETE_TCB
    rc = iphlpapi.SetTcpEntry(ctypes.byref(row))
    return rc

# interface stats -----------------------------------------------------------

_if_prev = {}   # index -> (ts, in_octets, out_octets)

def snapshot_interfaces():
    """Sum throughput across physical (ethernet=6, wifi=71) operational NICs."""
    size = wt.DWORD(0)
    iphlpapi.GetIfTable(None, ctypes.byref(size), False)
    if size.value == 0:
        return 0.0, 0.0, []
    buf = ctypes.create_string_buffer(size.value)
    if iphlpapi.GetIfTable(buf, ctypes.byref(size), False) != 0:
        return 0.0, 0.0, []
    count = struct.unpack_from("<I", buf, 0)[0]
    rows = ctypes.cast(ctypes.byref(buf, 4),
                       ctypes.POINTER(MIB_IFROW * count)).contents
    now = time.time()
    down = up = 0.0
    names, seen = [], set()
    for r in rows:
        if r.dwType not in (6, 71) or r.dwOperStatus < 4 or r.dwIndex in seen:
            continue
        seen.add(r.dwIndex)
        descr = r.bDescr[: r.dwDescrLen].decode("mbcs", "replace").rstrip("\x00")
        low = descr.lower()
        # skip loopback + virtual/tunnel adapters that mirror physical traffic
        # (miniports, WFP filter shims, VPN/VM taps) to avoid double counting
        if any(w in low for w in ("loopback", "miniport", "filter", "virtual",
                                  "vethernet", "tap", "tunnel", "pseudo")):
            continue
        prev = _if_prev.get(r.dwIndex)
        if prev:
            dt = now - prev[0]
            if dt > 0:
                d_in = (r.dwInOctets - prev[1]) % (1 << 32)
                d_out = (r.dwOutOctets - prev[2]) % (1 << 32)
                down += d_in / dt
                up += d_out / dt
        _if_prev[r.dwIndex] = (now, r.dwInOctets, r.dwOutOctets)
        names.append(descr)
    return down, up, names

# process attribution -------------------------------------------------------

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_proc_cache = {}   # pid -> (name, path)

def proc_info(pid):
    if pid in _proc_cache:
        return _proc_cache[pid]
    if pid == 0:
        info = ("Idle", "")
    elif pid == 4:
        info = ("System", "")
    else:
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            buf = ctypes.create_unicode_buffer(1024)
            n = wt.DWORD(1024)
            ok = kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
            kernel32.CloseHandle(h)
            path = buf.value if ok else ""
            info = (os.path.basename(path) or f"pid:{pid}", path)
        else:
            info = (f"pid:{pid}", "")
    _proc_cache[pid] = info
    return info

def prune_proc_cache(live_pids):
    for pid in list(_proc_cache):
        if pid not in live_pids:
            del _proc_cache[pid]

# --------------------------------------------------------------------------
# PowerShell bridge (rules, profiles, firewall logging config)
# --------------------------------------------------------------------------

CREATE_NO_WINDOW = 0x08000000

def run_ps(script, timeout=45):
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
           "Bypass", "-Command",
           "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return p.returncode, p.stdout.decode("utf-8", "replace"), \
               p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 1, "", "powershell timeout"

def ps_json(script, timeout=45):
    rc, out, err = run_ps(script, timeout)
    if rc != 0 or not out.strip():
        return None
    try:
        val = json.loads(out)
    except ValueError:
        return None
    return val

def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]

PS_STATUS = r"""
$profiles = Get-NetFirewallProfile | Select-Object Name, Enabled,
    DefaultInboundAction, DefaultOutboundAction, LogFileName, LogBlocked
$conn = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, Name, NetworkCategory)
$rules = @(Get-NetFirewallRule -Group '%GROUP%' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $af = $_ | Get-NetFirewallAddressFilter
        $ap = $_ | Get-NetFirewallApplicationFilter
        [pscustomobject]@{
            name = $_.DisplayName; enabled = [string]$_.Enabled
            dir = [string]$_.Direction; action = [string]$_.Action
            remote = ($af.RemoteAddress -join ',')
            program = $ap.Program
        }
    })
# IPv6 is "blocked" when the ms_tcpip6 binding is disabled on every physical
# (non-virtual, hardware) adapter that is Up.
$ipv6 = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
    Where-Object { (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).Status -eq 'Up' } |
    Select-Object Name, Enabled)
$dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Data -and ($_.Data -match '^\d{1,3}(\.\d{1,3}){3}$' -or $_.Data -match ':') } |
    Select-Object Entry, Data)
$gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)
$neigh = @(Get-NetNeighbor -ErrorAction SilentlyContinue |
    Where-Object { $_.LinkLayerAddress -and $_.State -in 'Reachable','Stale','Permanent' } |
    Select-Object IPAddress, LinkLayerAddress)
@{ profiles = $profiles; connection = $conn; rules = $rules; ipv6 = $ipv6;
   dns = $dns; gateway = $gw; neighbors = $neigh } |
    ConvertTo-Json -Depth 5 -Compress
""".replace("%GROUP%", RULE_GROUP)

CATEGORY_NAMES = {0: "Public", 1: "Private", 2: "Domain"}

class RulesManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.rules = []
        self.profiles = []
        self.connection = []
        self.log_path = os.path.expandvars(
            r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")
        self.log_blocked = False
        self.lockdown = False
        self.ipv6_blocked = False
        self.dns_names = {}      # ip -> hostname (from the DNS client cache)
        self.gateway_ip = ""
        self.neighbors = {}      # ip -> mac
        self.last_refresh = 0.0
        self.last_error = ""

    def refresh(self):
        data = ps_json(PS_STATUS)
        if data is None:
            self.last_error = "status query failed"
            return
        with self.lock:
            self.profiles = as_list(data.get("profiles"))
            self.connection = []
            for c in as_list(data.get("connection")):
                cat = c.get("NetworkCategory")
                self.connection.append({
                    "alias": c.get("InterfaceAlias"), "name": c.get("Name"),
                    "category": CATEGORY_NAMES.get(cat, str(cat)),
                })
            self.rules = as_list(data.get("rules"))
            for p in self.profiles:
                if p.get("LogFileName"):
                    self.log_path = os.path.expandvars(p["LogFileName"])
                    break
            self.log_blocked = any(p.get("LogBlocked") for p in self.profiles)
            # NetSecurity Action enum: NotConfigured=0, Allow=2, Block=4
            self.lockdown = all(
                str(p.get("DefaultOutboundAction")) in ("4", "Block")
                for p in self.profiles) if self.profiles else False
            ipv6 = as_list(data.get("ipv6"))
            # blocked = at least one Up adapter, and none still have IPv6 enabled
            self.ipv6_blocked = bool(ipv6) and not any(
                b.get("Enabled") for b in ipv6)
            # DNS cache -> ip:hostname (last writer wins; fine for a hint)
            names = {}
            for d in as_list(data.get("dns")):
                ip, entry = d.get("Data"), d.get("Entry")
                if ip and entry:
                    names[ip] = entry
            self.dns_names = names
            gw = data.get("gateway")
            self.gateway_ip = (gw[0] if isinstance(gw, list) and gw else
                               (gw if isinstance(gw, str) else ""))
            self.neighbors = {n["IPAddress"]: n["LinkLayerAddress"]
                              for n in as_list(data.get("neighbors"))
                              if n.get("IPAddress") and n.get("LinkLayerAddress")}
            self.last_refresh = time.time()
            self.last_error = ""

    # -- mutations (validated inputs only — nothing user-typed reaches PS raw)

    def block_ip(self, ip, ttl_minutes=None):
        addr = ipaddress.ip_address(ip)          # raises on garbage
        if ttl_minutes:
            exp = int(time.time()) + int(ttl_minutes) * 60
            name = f"PFW AutoBlock {addr} until {exp}"
        else:
            name = f"PFW Block {addr}"
        rc, _, err = run_ps(
            f"New-NetFirewallRule -DisplayName '{name}' -Group '{RULE_GROUP}' "
            f"-Direction Outbound -Action Block -RemoteAddress {addr} | Out-Null; "
            f"New-NetFirewallRule -DisplayName '{name}' -Group '{RULE_GROUP}' "
            f"-Direction Inbound -Action Block -RemoteAddress {addr} | Out-Null")
        return rc == 0, err.strip()

    def reap_expired(self):
        """Remove any timed AutoBlock rules whose 'until <epoch>' has passed."""
        now = int(time.time())
        removed = 0
        for r in list(self.rules):
            m = re.search(r" until (\d+)$", r.get("name", ""))
            if m and int(m.group(1)) <= now:
                ok, _ = self.remove_rule(r["name"])
                removed += 1 if ok else 0
        return removed

    def rule_for_app(self, path, action):
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return False, "no such program"
        safe = path.replace("'", "''")
        name = f"PFW {action} {os.path.basename(path)}"
        rc, _, err = run_ps(
            f"New-NetFirewallRule -DisplayName '{name}' -Group '{RULE_GROUP}' "
            f"-Direction Outbound -Action {action} -Program '{safe}' | Out-Null")
        return rc == 0, err.strip()

    def remove_rule(self, display_name):
        if not re.fullmatch(r"[\w .:\-\[\]()]{1,120}", display_name):
            return False, "bad rule name"
        rc, _, err = run_ps(
            f"Remove-NetFirewallRule -Group '{RULE_GROUP}' "
            f"-DisplayName '{display_name}'")
        return rc == 0, err.strip()

    def set_lockdown(self, enable):
        """Zero-trust outbound: default-deny unknown apps. Core Windows
        services (DNS cache incl. the DoH chain, DHCP) get explicit allows so
        the network layer keeps working; everything else needs an Allow rule."""
        if enable:
            rc, _, err = run_ps(
                f"New-NetFirewallRule -DisplayName 'PFW Core DNS' -Group '{RULE_GROUP}' "
                f"-Direction Outbound -Action Allow -Service Dnscache | Out-Null; "
                f"New-NetFirewallRule -DisplayName 'PFW Core DHCP' -Group '{RULE_GROUP}' "
                f"-Direction Outbound -Action Allow -Service Dhcp | Out-Null; "
                f"Set-NetFirewallProfile -All -DefaultOutboundAction Block")
        else:
            rc, _, err = run_ps(
                "Set-NetFirewallProfile -All -DefaultOutboundAction Allow")
        return rc == 0, err.strip()

    def set_block_ipv6(self, enable):
        """Block/allow ALL IPv6 by binding/unbinding the ms_tcpip6 protocol on
        every adapter. Immediate, no reboot, fully reversible. Unbinding stops
        IPv6 flowing without touching IPv4 (unlike a catch-all firewall rule,
        which risks matching everything)."""
        verb = "Disable" if enable else "Enable"
        rc, _, err = run_ps(
            f"{verb}-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 "
            f"-ErrorAction Stop")
        return rc == 0, err.strip()

# --------------------------------------------------------------------------
# firewall drop-log tailer
# --------------------------------------------------------------------------

class FwLogTailer:
    """Tails pfirewall.log for DROP lines (blocked-connection feed)."""

    def __init__(self):
        self.offset = 0
        self.primed = False

    def read_new(self, path):
        drops = []
        try:
            size = os.path.getsize(path)
        except OSError:
            return drops
        if not self.primed:
            # start near the end: replay at most the last 64 KB on startup
            self.offset = max(0, size - 65536)
            self.primed = True
        if size < self.offset:          # log rotated
            self.offset = 0
        if size == self.offset:
            return drops
        try:
            with open(path, "r", encoding="ascii", errors="replace") as f:
                f.seek(self.offset)
                chunk = f.read(1 << 20)
                self.offset = f.tell()
        except OSError:
            return drops
        for line in chunk.splitlines():
            if " DROP " not in line:
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            # date time action protocol src-ip dst-ip src-port dst-port ... path
            drops.append({
                "ts": f"{parts[0]} {parts[1]}", "proto": parts[3],
                "src": parts[4], "dst": parts[5],
                "sport": parts[6], "dport": parts[7],
                "dir": parts[-1] if parts[-1] in ("SEND", "RECEIVE") else "?",
            })
        return drops

# --------------------------------------------------------------------------
# alert engine
# --------------------------------------------------------------------------

def classify_ip(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "?"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "private"
    if a.is_multicast:
        return "multicast"
    if a.is_unspecified:
        return "any"
    return "public"

SUSPICIOUS_PATH = re.compile(
    r"\\appdata\\local\\temp\\|\\downloads\\|\\users\\public\\|\\\$recycle",
    re.IGNORECASE)

class AlertEngine:
    """Sliding-window heuristics over drop events + connection events. All
    thresholds and enable flags are read live from state.config, so editing the
    profile takes effect on the next event without a restart."""

    COOLDOWN = 600                                # 10 min per (rule, key)

    def __init__(self, state):
        self.state = state
        self.drop_by_src = {}                     # src -> deque[(ts, dport)]
        self.brute = {}                           # (src, dport) -> deque[ts]
        self.fanout = {}                          # proc -> deque[(ts, ip)]
        self.listeners = set()
        self.listeners_primed = False
        self.cooldowns = {}

    # -- config helpers -----------------------------------------------------
    def _alerts(self):
        return self.state.config.get("alerts", {})

    def _on(self, name):
        return self._alerts().get(name, {}).get("enabled", True)

    def _trusted(self, ip):
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False
        for entry in self.state.config.get("trusted_ips", []):
            try:
                if "/" in str(entry):
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def _fire(self, key, severity, rule, title, detail):
        now = time.time()
        if now - self.cooldowns.get(key, 0) < self.COOLDOWN:
            return
        self.cooldowns[key] = now
        self.state._emit_alert(severity, rule, title, detail)

    def feed_drops(self, drops):
        now = time.time()
        a = self._alerts()
        scan_on, brute_on = self._on("portscan"), self._on("bruteforce")
        scan_ports = int(a.get("portscan", {}).get("ports", 8))
        scan_win = int(a.get("portscan", {}).get("window_secs", 60))
        brute_hits = int(a.get("bruteforce", {}).get("hits", 15))
        brute_win = int(a.get("bruteforce", {}).get("window_secs", 300))
        for d in drops:
            src, dport = d["src"], d["dport"]
            if d["dir"] != "RECEIVE" or self._trusted(src):
                continue
            if scan_on:
                dq = self.drop_by_src.setdefault(src, deque(maxlen=400))
                dq.append((now, dport))
                recent = {p for t, p in dq if now - t <= scan_win}
                if len(recent) >= scan_ports:
                    self._fire(("scan", src), "critical", "port-scan",
                               f"Port scan from {src}",
                               f"{len(recent)} distinct ports probed in "
                               f"{scan_win}s (all dropped by firewall)")
                    self.state.request_auto_block(src, "port scan", "on_portscan")
            if brute_on:
                bq = self.brute.setdefault((src, dport), deque(maxlen=200))
                bq.append(now)
                hits = [t for t in bq if now - t <= brute_win]
                if len(hits) >= brute_hits:
                    self._fire(("brute", src, dport), "serious", "brute-force",
                               f"Repeated blocked attempts from {src}",
                               f"{len(hits)} drops on port {dport} in "
                               f"{brute_win // 60} min")
                    self.state.request_auto_block(src, "brute force", "on_bruteforce")

    def feed_listeners(self, listen_set_with_proc):
        current = set(listen_set_with_proc)
        if not self.listeners_primed:
            self.listeners = current
            self.listeners_primed = True
            return
        if self._on("new_listener"):
            for port, proc in current - self.listeners:
                self._fire(("listen", port), "warning", "new-listener",
                           f"New listening port {port}",
                           f"{proc} started accepting inbound connections "
                           f"on port {port}")
        self.listeners |= current

    def feed_new_connection(self, ev):
        now = time.time()
        path, proc = ev.get("path", ""), ev.get("proc", "?")
        raddr, rport = ev.get("raddr", ""), ev.get("rport", 0)
        if self._trusted(raddr):
            return
        a = self._alerts()
        if self._on("suspicious_path") and path and SUSPICIOUS_PATH.search(path):
            self._fire(("path", path), "serious", "suspicious-path",
                       f"Network activity from unusual location: {proc}",
                       f"{path} connected to {raddr}:{rport}")
        if self._on("plaintext_dns") and rport == 53 and classify_ip(raddr) == "public":
            self._fire(("dns", proc), "warning", "plaintext-dns",
                       f"Plaintext DNS by {proc}",
                       f"TCP to {raddr}:53 bypasses the encrypted DoH chain")
        if self._on("fanout") and classify_ip(raddr) == "public":
            fan_ips = int(a.get("fanout", {}).get("ips", 30))
            fan_win = int(a.get("fanout", {}).get("window_secs", 300))
            fq = self.fanout.setdefault(proc, deque(maxlen=800))
            fq.append((now, raddr))
            ips = {ip for t, ip in fq if now - t <= fan_win}
            if len(ips) >= fan_ips:
                self._fire(("fanout", proc), "warning", "fan-out",
                           f"{proc} contacting many hosts",
                           f"{len(ips)} distinct public IPs in "
                           f"{fan_win // 60} min - possible scanning, "
                           f"C2 or exfiltration")

    def feed_throughput(self, history):
        if not self._on("upload_surge"):
            return
        a = self._alerts().get("upload_surge", {})
        win = int(a.get("window_secs", 60))
        samples = max(2, int(win / max(0.5, self.state.config.get("poll_secs", 2))))
        if len(history) < samples:
            return
        recent = [h["up"] for h in list(history)[-samples:]]
        avg = sum(recent) / len(recent)
        if avg > float(a.get("mbps", 4)) * 1e6:
            self._fire(("upload",), "warning", "upload-surge",
                       "Sustained high upload",
                       f"Average {avg / 1e6:.1f} MB/s upstream for the last "
                       f"{win}s - check for large transfers or exfiltration")

# --------------------------------------------------------------------------
# state manager (background poller)
# --------------------------------------------------------------------------

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.conns = []
        self.history = deque(maxlen=HISTORY_LEN)
        self.events = deque(maxlen=EVENT_KEEP)
        self.alerts = deque(maxlen=ALERT_KEEP)
        self.if_names = []
        self.drop_count_today = 0
        self.started = time.time()
        self.rules = RulesManager()
        self.tailer = FwLogTailer()
        os.makedirs(LOG_DIR, exist_ok=True)
        self.config = cfgmod.load_config(CONFIG_PATH)
        self.config_mtime = self._cfg_mtime()
        self.active_profile = None            # current network category name
        self.auto_blocks = {}                 # ip -> expiry epoch (recent)
        self.alert_engine = AlertEngine(self)
        self._known_flows = set()
        self._flows_primed = False
        self._alert_seq = 0
        self._gw_mac = None

    def _cfg_mtime(self):
        try:
            return os.path.getmtime(CONFIG_PATH)
        except OSError:
            return 0

    # -- config -------------------------------------------------------------
    def reload_config(self):
        self.config = cfgmod.load_config(CONFIG_PATH)
        self.config_mtime = self._cfg_mtime()
        self._emit_event("action", "config reloaded")

    def save_config(self, cfg):
        ok, cleaned, err = cfgmod.validate(cfg)
        if not ok:
            return False, err
        cfgmod.save_config(CONFIG_PATH, cleaned)
        self.config = cleaned
        self.config_mtime = self._cfg_mtime()
        self._emit_event("action", "config saved from dashboard")
        return True, "saved"

    def _hot_reload_if_changed(self):
        m = self._cfg_mtime()
        if m and m != self.config_mtime:
            self.reload_config()

    # -- network profile ----------------------------------------------------
    def _profile(self):
        if not self.active_profile:
            return {}
        return self.config.get("network_profiles", {}).get(self.active_profile, {})

    def auto_block_allowed(self):
        return bool(self._profile().get("auto_block", True))

    def effective_min_severity(self):
        return self._profile().get("min_severity",
                                   self.config.get("notifications", {})
                                   .get("min_severity", "warning"))

    def apply_network_profile(self, category):
        if category == self.active_profile:
            return
        self.active_profile = category
        if not self.config.get("auto_apply_network_profile", True):
            return
        prof = self._profile()
        note = prof.get("note", "")
        self._emit_event("action",
                         f"network profile -> {category}"
                         f"{(' (' + note + ')') if note else ''}")

    # -- auto-block ---------------------------------------------------------
    def request_auto_block(self, ip, reason, flag):
        ab = self.config.get("auto_block", {})
        if not ab.get(flag) or not self.auto_block_allowed():
            return
        now = time.time()
        prev = self.auto_blocks.get(ip, 0)
        if prev > now:                        # already blocked and not expired
            return
        ttl = int(ab.get("ttl_minutes", 60))
        self.auto_blocks[ip] = now + ttl * 60

        def _do():
            ok, msg = self.rules.block_ip(ip, ttl_minutes=ttl)
            self.rules.refresh()
            self._emit_event("action",
                             f"auto-blocked {ip} for {ttl}m ({reason}) ok={ok}")
            if ok:
                self._emit_alert("serious", "auto-block",
                                 f"Auto-blocked {ip}",
                                 f"{reason} - blocked for {ttl} min "
                                 f"(expires automatically)")
        threading.Thread(target=_do, daemon=True).start()

    # -- ARP spoof watch ----------------------------------------------------
    def check_arp(self):
        if not (self.config.get("features", {}).get("arp_spoof", True)
                and self.config.get("alerts", {}).get("arp_spoof", {})
                .get("enabled", True)):
            return
        gw, neigh = self.rules.gateway_ip, self.rules.neighbors
        if not gw:
            return
        mac = neigh.get(gw)
        if mac:
            if self._gw_mac and mac != self._gw_mac:
                self.alert_engine._fire(
                    ("arp", gw), "critical", "arp-spoof",
                    "Gateway MAC changed",
                    f"Default gateway {gw} MAC changed "
                    f"{self._gw_mac} -> {mac}. Possible man-in-the-middle "
                    f"on this network.")
            self._gw_mac = mac
        # gateway sharing a MAC with another host = impersonation
        shared = [ip for ip, m in neigh.items() if m == mac and ip != gw]
        if mac and shared:
            self.alert_engine._fire(
                ("arpdup", mac), "serious", "arp-spoof",
                "Gateway MAC shared with another host",
                f"{gw} and {', '.join(shared[:3])} share MAC {mac} "
                f"- possible ARP spoofing.")

    def _append_jsonl(self, name, obj):
        try:
            fn = os.path.join(LOG_DIR, f"{name}-{time.strftime('%Y%m%d')}.jsonl")
            with open(fn, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
        except OSError:
            pass

    def _emit_alert(self, severity, rule, title, detail):
        self._alert_seq += 1
        a = {"id": self._alert_seq, "ts": time.time(), "severity": severity,
             "rule": rule, "title": title, "detail": detail}
        with self.lock:
            self.alerts.append(a)
        self._append_jsonl("alerts", a)

    def _emit_event(self, kind, text, meta=None):
        ev = {"ts": time.time(), "kind": kind, "text": text}
        if meta:
            ev.update(meta)
        with self.lock:
            self.events.append(ev)
        self._append_jsonl("events", ev)

    def poll_once(self):
        tcp = snapshot_tcp()
        udp = snapshot_udp()
        conns = tcp + udp
        live_pids = set()
        dns = self.rules.dns_names
        for c in conns:
            name, path = proc_info(c["pid"])
            c["proc"], c["path"] = name, path
            c["class"] = classify_ip(c["raddr"]) if c["raddr"] not in ("*",) else ""
            c["host"] = dns.get(c["raddr"], "") if c["raddr"] not in ("*",) else ""
            live_pids.add(c["pid"])
        prune_proc_cache(live_pids)

        down, up, names = snapshot_interfaces()
        point = {"t": time.time(), "down": round(down), "up": round(up),
                 "conns": sum(1 for c in conns if c["state"] == "ESTABLISHED")}

        # new-connection events (established TCP with a real remote)
        flows = {(c["proto"], c["pid"], c["raddr"], c["rport"])
                 for c in conns
                 if c["state"] == "ESTABLISHED" and c["class"] in ("public", "private")}
        if self._flows_primed:
            for f in flows - self._known_flows:
                proto, pid, raddr, rport = f
                name, path = proc_info(pid)
                ev = {"proc": name, "path": path, "raddr": raddr, "rport": rport}
                self._emit_event("connect",
                                 f"{name} → {raddr}:{rport} ({proto})", ev)
                self.alert_engine.feed_new_connection(ev)
        self._known_flows = flows
        self._flows_primed = True

        # listener tracking (TCP LISTEN on non-loopback)
        listeners = {(c["lport"], c["proc"]) for c in conns
                     if c["state"] == "LISTEN" and
                     not c["laddr"].startswith("127.") and c["laddr"] != "::1"}
        self.alert_engine.feed_listeners(listeners)

        # firewall drop feed
        drops = self.tailer.read_new(self.rules.log_path)
        for d in drops:
            self._emit_event("drop",
                             f"DROP {d['proto']} {d['src']}:{d['sport']} → "
                             f"{d['dst']}:{d['dport']} ({d['dir']})", d)
        self.alert_engine.feed_drops(drops)

        with self.lock:
            self.conns = conns
            self.if_names = names
            self.history.append(point)
            self.drop_count_today += len(drops)
        self.alert_engine.feed_throughput(self.history)

    def _current_category(self):
        # strictest present wins (a laptop should harden to its least-trusted net)
        cats = {c.get("category") for c in self.rules.connection}
        for c in ("Public", "Private", "Domain"):
            if c in cats:
                return c
        return None

    def loop(self):
        while True:
            try:
                self.poll_once()
            except Exception as e:                       # keep the poller alive
                self._emit_event("error", f"poller: {e!r}")
            self._hot_reload_if_changed()
            if time.time() - self.rules.last_refresh > PS_REFRESH_SECS:
                try:
                    self.rules.refresh()
                    cat = self._current_category()
                    if cat:
                        self.apply_network_profile(cat)
                    self.check_arp()
                    self.rules.reap_expired()
                except Exception as e:
                    self._emit_event("error", f"rules: {e!r}")
            time.sleep(max(0.5, float(self.config.get("poll_secs", POLL_SECS))))

    def to_json(self):
        with self.lock:
            r = self.rules
            return json.dumps({
                "admin": IS_ADMIN,
                "uptime": round(time.time() - self.started),
                "interfaces": self.if_names,
                "profiles": [{"alias": c["alias"], "category": c["category"],
                              "name": c["name"]} for c in r.connection],
                "lockdown": r.lockdown,
                "ipv6_blocked": r.ipv6_blocked,
                "log_blocked": r.log_blocked,
                "rules": r.rules,
                "conns": self.conns,
                "history": list(self.history),
                "events": list(self.events)[-EVENT_KEEP:],
                "alerts": list(self.alerts),
                "drops_today": self.drop_count_today,
                "active_profile": self.active_profile,
                "gateway": r.gateway_ip,
                "notify": {
                    "balloons": self.config.get("notifications", {})
                                .get("balloons", True),
                    "min_severity": self.effective_min_severity(),
                },
            })

    def config_json(self):
        return json.dumps(self.config, indent=2)

STATE = State()

# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------

TOKEN = os.environ.get("PFW_TOKEN") or secrets.token_urlsafe(24)

with open(os.path.join(RES_DIR, "dashboard.html"), "rb") as _f:
    DASHBOARD = _f.read()

class Handler(BaseHTTPRequestHandler):
    server_version = "PrivateFirewall/1.0"

    def log_message(self, *a):                       # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        tok = self.headers.get("X-PFW-Token", "")
        return hmac.compare_digest(tok, TOKEN)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/#"):
            return self._send(200, DASHBOARD, "text/html; charset=utf-8")
        if not self._authed():
            return self._send(401, '{"error":"bad token"}')
        if self.path == "/api/state":
            return self._send(200, STATE.to_json())
        if self.path == "/api/config":
            return self._send(200, STATE.config_json())
        return self._send(404, '{"error":"not found"}')

    def do_POST(self):
        if not self._authed():
            return self._send(401, '{"error":"bad token"}')
        if not IS_ADMIN:
            return self._send(403, '{"error":"server not elevated — '
                                   'restart via Start-PrivateFirewall.ps1"}')
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, '{"error":"bad json"}')
        try:
            ok, msg = self._dispatch(self.path, body)
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, json.dumps({"error": str(e)}))
        # refresh rule cache after any mutation
        if ok and self.path != "/api/kill":
            threading.Thread(target=STATE.rules.refresh, daemon=True).start()
        return self._send(200 if ok else 500,
                          json.dumps({"ok": ok, "msg": msg}))

    def _dispatch(self, path, body):
        r = STATE.rules
        if path == "/api/kill":
            k = body["kill"]
            if not (isinstance(k, list) and len(k) == 4 and
                    all(isinstance(x, int) and 0 <= x < 2**32 for x in k)):
                raise ValueError("bad kill tuple")
            rc = kill_tcp(*k)
            # 317 = ERROR_MR_MID_NOT_FOUND: connection already gone
            ok = rc in (0, 317)
            STATE._emit_event("action", f"kill connection rc={rc}")
            return ok, f"SetTcpEntry rc={rc}"
        if path == "/api/config":
            ok, msg = STATE.save_config(body.get("config"))
            return ok, msg
        if path == "/api/reload":
            STATE.reload_config()
            return True, "config reloaded"
        if path == "/api/block-ip":
            ttl = body.get("ttl_minutes")
            ok, msg = r.block_ip(str(body["ip"]), ttl_minutes=ttl)
            STATE._emit_event("action",
                              f"block ip {body['ip']}"
                              f"{(' for '+str(ttl)+'m') if ttl else ''} ok={ok}")
            return ok, msg
        if path == "/api/block-app":
            ok, msg = r.rule_for_app(str(body["path"]), "Block")
            STATE._emit_event("action", f"block app {body['path']} ok={ok}")
            return ok, msg
        if path == "/api/allow-app":
            ok, msg = r.rule_for_app(str(body["path"]), "Allow")
            STATE._emit_event("action", f"allow app {body['path']} ok={ok}")
            return ok, msg
        if path == "/api/unblock":
            ok, msg = r.remove_rule(str(body["name"]))
            STATE._emit_event("action", f"remove rule {body['name']} ok={ok}")
            return ok, msg
        if path == "/api/lockdown":
            ok, msg = r.set_lockdown(bool(body["enable"]))
            STATE._emit_event("action",
                              f"lockdown {'ON' if body['enable'] else 'OFF'} ok={ok}")
            return ok, msg
        if path == "/api/block-ipv6":
            ok, msg = r.set_block_ipv6(bool(body["enable"]))
            STATE._emit_event("action",
                              f"block-ipv6 {'ON' if body['enable'] else 'OFF'} ok={ok}")
            return ok, msg
        raise ValueError("unknown endpoint")

def open_external(path):
    """Open a URL or folder as the normal user. explorer.exe hands the request
    to the user's shell, so nothing is spawned with our elevation.

    For http(s) URLs we must NOT pass the URL to explorer.exe directly: on
    Windows 11 explorer doesn't recognise a URL argument (especially with a
    '#fragment') and silently opens the Documents folder instead. Writing a
    tiny .url internet shortcut and opening THAT makes explorer launch the
    default browser, de-elevated, with the fragment intact."""
    if path.startswith("http://") or path.startswith("https://"):
        try:
            shortcut = os.path.join(tempfile.gettempdir(), "PrivateFirewall.url")
            with open(shortcut, "w", encoding="ascii", errors="replace") as f:
                f.write("[InternetShortcut]\r\nURL=%s\r\n" % path)
            subprocess.Popen(["explorer.exe", shortcut])
        except Exception:
            os.startfile(path)                  # last resort (may inherit elevation)
    else:
        subprocess.Popen(["explorer.exe", path])

_INSTANCE_MUTEX = None   # kept alive for the process lifetime

def _acquire_single_instance():
    """Return True if we are the only instance; False if one is already running.
    Uses a named mutex so a second launch (shortcut, task, manual) can't stack a
    second engine/tray on top of a running one."""
    global _INSTANCE_MUTEX
    if os.environ.get("PFW_NO_SINGLETON"):     # testing: allow concurrent runs
        return True
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    _INSTANCE_MUTEX = kernel32.CreateMutexW(None, False, "PrivateFirewallEngine")
    return ctypes.get_last_error() != 183      # 183 = ERROR_ALREADY_EXISTS

def main():
    if not _acquire_single_instance():
        print("PrivateFirewall is already running; this instance will exit.",
              flush=True)
        return
    STATE.rules.refresh()
    threading.Thread(target=STATE.loop, daemon=True).start()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    url = f"http://{BIND_HOST}:{BIND_PORT}/#t={TOKEN}"
    print(f"PrivateFirewall engine  admin={IS_ADMIN}  {url}", flush=True)

    if "--tray" in sys.argv:
        # tray owns the main thread's Win32 message loop; HTTP serves in back.
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        if "--open" in sys.argv:
            open_external(url)
        try:
            import tray
            tray.run_tray(STATE, url, LOG_DIR, open_external, IS_ADMIN, CONFIG_PATH)
        except Exception as e:                  # never let a tray failure kill
            print(f"tray unavailable ({e!r}); serving headless", flush=True)
            srv.serve_forever()
        return

    if "--open" in sys.argv:
        open_external(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
