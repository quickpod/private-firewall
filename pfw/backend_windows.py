"""Windows implementation of the PrivateFirewall backend.

This is the ORIGINAL engine code (WFP control plane over ctypes/iphlpapi +
PowerShell) moved behind the FirewallBackend interface — behaviour unchanged.
The only structural change: the WinDLL handles load lazily via _winapi(), so
this module imports cleanly on any OS (the Windows-path unit tests run at mock
level on Linux CI); nothing Windows-only executes until the backend is
instantiated on an actual Windows box.
"""

import ctypes
import ctypes.wintypes as wt   # pure declarations — imports fine off Windows
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

from backend import FirewallBackend, TCP_STATES

RULE_GROUP = "PrivateFirewall"

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

# --------------------------------------------------------------------------
# lazy Win32 DLL handles (module must import on non-Windows)
# --------------------------------------------------------------------------

_dlls = None


def _winapi():
    """Load iphlpapi/kernel32/shell32 once, on first use, on Windows only."""
    global _dlls
    if _dlls is None:
        _dlls = (ctypes.WinDLL("iphlpapi"),
                 ctypes.WinDLL("kernel32", use_last_error=True),
                 ctypes.WinDLL("shell32"))
    return _dlls


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
    iphlpapi = _winapi()[0]
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
    iphlpapi = _winapi()[0]
    out = []
    for row in _get_table(iphlpapi.GetExtendedUdpTable, AF_INET,
                          UDP_TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID):
        out.append({"proto": "UDP", "pid": row.dwOwningPid,
                    "laddr": _v4(row.dwLocalAddr), "lport": _port(row.dwLocalPort),
                    "raddr": "*", "rport": 0, "state": "LISTEN", "kill": None})
    return out

def kill_tcp(l_addr, l_port, r_addr, r_port):
    """Terminate a TCP v4 connection. Values are the raw DWORDs from snapshot."""
    iphlpapi = _winapi()[0]
    row = MIB_TCPROW(12, l_addr, l_port, r_addr, r_port)   # 12 = DELETE_TCB
    rc = iphlpapi.SetTcpEntry(ctypes.byref(row))
    return rc

# interface stats -----------------------------------------------------------

_if_prev = {}   # index -> (ts, in_octets, out_octets)

def snapshot_interfaces():
    """Sum throughput across physical (ethernet=6, wifi=71) operational NICs."""
    iphlpapi = _winapi()[0]
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
    kernel32 = _winapi()[1]
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
    """Windows Firewall control via PowerShell — original code, verbatim.
    Holds the last status query results as plain attributes."""

    def __init__(self):
        self.log_path = os.path.expandvars(
            r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")

    def query_status(self):
        """One PS round-trip -> status dict per FirewallBackend.refresh_status."""
        data = ps_json(PS_STATUS)
        if data is None:
            return {"error": "status query failed"}
        profiles = as_list(data.get("profiles"))
        connection = []
        for c in as_list(data.get("connection")):
            cat = c.get("NetworkCategory")
            connection.append({
                "alias": c.get("InterfaceAlias"), "name": c.get("Name"),
                "category": CATEGORY_NAMES.get(cat, str(cat)),
            })
        for p in profiles:
            if p.get("LogFileName"):
                self.log_path = os.path.expandvars(p["LogFileName"])
                break
        rules = as_list(data.get("rules"))
        for r in rules:
            r["ours"] = True          # group-filtered: every rule is ours
        ipv6 = as_list(data.get("ipv6"))
        gw = data.get("gateway")
        return {
            "profiles": profiles,
            "connection": connection,
            "rules": rules,
            "log_blocked": any(p.get("LogBlocked") for p in profiles),
            # NetSecurity Action enum: NotConfigured=0, Allow=2, Block=4
            "lockdown": all(
                str(p.get("DefaultOutboundAction")) in ("4", "Block")
                for p in profiles) if profiles else False,
            # blocked = at least one Up adapter, and none still have IPv6 enabled
            "ipv6_blocked": bool(ipv6) and not any(
                b.get("Enabled") for b in ipv6),
            "dns_names": {d["Data"]: d["Entry"]
                          for d in as_list(data.get("dns"))
                          if d.get("Data") and d.get("Entry")},
            "gateway": (gw[0] if isinstance(gw, list) and gw else
                        (gw if isinstance(gw, str) else "")),
            "neighbors": {n["IPAddress"]: n["LinkLayerAddress"]
                          for n in as_list(data.get("neighbors"))
                          if n.get("IPAddress") and n.get("LinkLayerAddress")},
            "error": "",
        }

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


SUSPICIOUS_PATH_WIN = re.compile(
    r"\\appdata\\local\\temp\\|\\downloads\\|\\users\\public\\|\\\$recycle",
    re.IGNORECASE)


# --------------------------------------------------------------------------
# the backend adapter
# --------------------------------------------------------------------------

class WindowsBackend(FirewallBackend):
    platform = "windows"

    def __init__(self):
        self.rules = RulesManager()
        self.tailer = FwLogTailer()
        self._mutex = None
        shell32 = _winapi()[2]
        self._admin = bool(shell32.IsUserAnAdmin())

    def capabilities(self):
        return {
            "platform": "windows",
            "firewall": "Windows Firewall (WFP)",
            "kill_conn": True,
            "app_rules": True,
            "port_rules": False,
            "net_profiles": True,
            "ipv6_toggle": True,
            "ipv6_how": "unbinds the IPv6 protocol from every network adapter",
            "dns_names": True,
            "rules_shared": False,
            "elevate_live": False,
            "elevate_hint": "Relaunch with Start-PrivateFirewall.ps1 "
                            "(runs elevated via UAC).",
        }

    def is_admin(self):
        return self._admin

    # -- observation --------------------------------------------------------
    def snapshot_connections(self):
        conns = snapshot_tcp() + snapshot_udp()
        live = set()
        for c in conns:
            name, path = proc_info(c["pid"])
            c["proc"], c["path"] = name, path
            live.add(c["pid"])
        prune_proc_cache(live)
        return conns

    def snapshot_throughput(self):
        return snapshot_interfaces()

    def refresh_status(self):
        return self.rules.query_status()

    def read_new_drops(self):
        return self.tailer.read_new(self.rules.log_path)

    # -- actions ------------------------------------------------------------
    def kill_conn(self, kill):
        if not (isinstance(kill, list) and len(kill) == 4 and
                all(isinstance(x, int) and 0 <= x < 2**32 for x in kill)):
            raise ValueError("bad kill tuple")
        rc = kill_tcp(*kill)
        # 317 = ERROR_MR_MID_NOT_FOUND: connection already gone
        return rc in (0, 317), f"SetTcpEntry rc={rc}"

    def block_ip(self, ip, ttl_minutes=None):
        return self.rules.block_ip(ip, ttl_minutes)

    def rule_for_app(self, path, action):
        return self.rules.rule_for_app(path, action)

    def remove_rule(self, name, number=None):
        return self.rules.remove_rule(name)

    def set_lockdown(self, enable):
        return self.rules.set_lockdown(enable)

    def set_block_ipv6(self, enable):
        return self.rules.set_block_ipv6(enable)

    # -- environment --------------------------------------------------------
    def acquire_single_instance(self):
        """Named mutex so a second launch can't stack a second engine/tray."""
        if os.environ.get("PFW_NO_SINGLETON"):     # testing: allow concurrency
            return True
        kernel32 = _winapi()[1]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                          ctypes.c_wchar_p]
        self._mutex = kernel32.CreateMutexW(None, False, "PrivateFirewallEngine")
        return ctypes.get_last_error() != 183      # 183 = ERROR_ALREADY_EXISTS

    def open_external(self, path):
        """Open a URL or folder as the normal user. explorer.exe hands the
        request to the user's shell, so nothing is spawned with our elevation.

        For http(s) URLs we must NOT pass the URL to explorer.exe directly: on
        Windows 11 explorer doesn't recognise a URL argument (especially with a
        '#fragment') and silently opens the Documents folder instead. Writing a
        tiny .url internet shortcut and opening THAT makes explorer launch the
        default browser, de-elevated, with the fragment intact."""
        if path.startswith("http://") or path.startswith("https://"):
            try:
                shortcut = os.path.join(tempfile.gettempdir(),
                                        "PrivateFirewall.url")
                with open(shortcut, "w", encoding="ascii", errors="replace") as f:
                    f.write("[InternetShortcut]\r\nURL=%s\r\n" % path)
                subprocess.Popen(["explorer.exe", shortcut])
            except Exception:
                os.startfile(path)          # last resort (may inherit elevation)
        else:
            subprocess.Popen(["explorer.exe", path])

    def suspicious_path_re(self):
        return SUSPICIOUS_PATH_WIN

    # -- start at login ------------------------------------------------------
    @staticmethod
    def _has_logon_task():
        """The installer's scheduled task (elevated tray + watchdog) is the
        preferred Windows autostart; when it exists the Run key must NOT be
        added on top of it (the mutex would make the second launch a no-op,
        but two mechanisms is one too many)."""
        try:
            p = subprocess.run(["schtasks", "/Query", "/TN", "PrivateFirewall"],
                               capture_output=True, timeout=15,
                               creationflags=CREATE_NO_WINDOW)
            return p.returncode == 0
        except OSError:
            return False

    def set_autostart(self, enabled):
        """Per-user Run key fallback for installs without the scheduled task.
        Only meaningful for the frozen exe (source-mode users have the
        PowerShell installer for this)."""
        if self._has_logon_task():
            return True, "autostart already handled by the logon task"
        if not getattr(sys, "frozen", False):
            return False, "source mode: use Setup-PrivateFirewall.ps1 -Startup"
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_SET_VALUE)
            try:
                if enabled:
                    winreg.SetValueEx(
                        key, "PrivateFirewall", 0, winreg.REG_SZ,
                        f'"{sys.executable}" --tray --no-open')
                else:
                    try:
                        winreg.DeleteValue(key, "PrivateFirewall")
                    except FileNotFoundError:
                        pass
            finally:
                winreg.CloseKey(key)
        except OSError as e:
            return False, str(e)
        return True, "autostart " + ("enabled" if enabled else "removed")
