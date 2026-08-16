"""PrivateFirewall — a user-mode control plane on top of the OS firewall.

Architecture: the OS firewall (Windows Firewall/WFP on Windows, ufw/netfilter
on Linux) already sits in the kernel as the entry point for ALL wired +
wireless traffic. This engine does not re-route packets (fail-open by design:
if this process dies, the kernel firewall keeps enforcing the configured
policy). It provides:

  * live connection table (TCP v4/v6 + UDP listeners) with process attribution
  * per-interface throughput statistics
  * kill switch for individual TCP connections
  * dynamic block/allow rules managed in a dedicated, tagged rule set
    (group "PrivateFirewall" on Windows, "PFW"-commented ufw rules on Linux)
    so one command can revert everything this app created
  * firewall drop-log tailing (blocked-connection feed)
  * alert engine: port scans, brute-force repeats, new listening ports,
    suspicious executable paths, plaintext-DNS bypass, fan-out, upload surges
  * localhost-only JSON API + dashboard, token-authenticated

All platform specifics live behind ONE interface — see backend.py (and
backend_windows.py / backend_linux.py). This file is platform-neutral.

Requires: Python 3.x (stdlib only). Admin for kill/block/lockdown
(UAC-elevated process on Windows; pkexec root helper on Linux).
"""

import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config as cfgmod   # pfw/config.py — editable profile (bundled)
import backend as backend_mod

# The app ships windowed/no-console so nothing can accidentally close it.
# PyInstaller windowed mode leaves sys.stdout/stderr as None, which makes any
# print() raise — redirect them to a sink so the engine never crashes.
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


def _default_log_dir():
    if os.name == "nt":
        # installed default is %ProgramData%, else repo (original behaviour)
        if FROZEN:
            return os.path.join(os.environ.get("ProgramData", APP_DIR),
                                "PrivateFirewall", "logs")
        return os.path.join(APP_DIR, "logs")
    # Linux: the app dir (/opt/quickopen/private-firewall) is root-owned —
    # per-user state goes to the XDG data dir.
    base = os.environ.get("XDG_DATA_HOME") or \
        os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "PrivateFirewall", "logs")


LOG_DIR = os.environ.get("PFW_LOG_DIR") or _default_log_dir()
CONFIG_PATH = os.environ.get("PFW_CONFIG") or \
    os.path.join(os.path.dirname(LOG_DIR), "config.json")
BIND_HOST = "127.0.0.1"
BIND_PORT = int(os.environ.get("PFW_PORT", "58730"))
POLL_SECS = 2.0
STATUS_REFRESH_SECS = 60.0
HISTORY_LEN = 240          # 240 * 2s = 8 minutes of throughput history
EVENT_KEEP = 400
ALERT_KEEP = 200

# --------------------------------------------------------------------------
# helpers
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


def _parse_ip(ip):
    try:
        return ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return None


# IP protocol numbers as they appear in firewall logs when the traffic is not
# TCP/UDP. User-facing text must show the protocol NAME — never "port 0".
PROTO_NAMES = {
    "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "41": "IPv6",
    "44": "fragment", "47": "GRE", "50": "ESP", "51": "AH", "58": "ICMPv6",
    "112": "VRRP", "132": "SCTP",
}


def proto_name(p):
    p = str(p or "?").strip()
    if p.isdigit():
        return PROTO_NAMES.get(p, f"protocol {p}")
    return p.upper() if p.isalpha() else p


def is_background_drop(d):
    """True for benign local-network chatter the firewall drops as a matter of
    course: link-local sources (IPv6 NDP/RA, IPv4 APIPA), multicast/broadcast
    destinations, and non-TCP/UDP protocols (ICMPv6, IGMP, fragments...).
    These are shown in the feed as low-key background noise — never presented
    as attack attempts, never fed to the attack heuristics."""
    src, dst = _parse_ip(d.get("src")), _parse_ip(d.get("dst"))
    if src is not None and src.is_link_local:
        return True
    if dst is not None and (dst.is_multicast or
                            (dst.version == 4 and str(dst).endswith(".255"))):
        return True
    if proto_name(d.get("proto")) not in ("TCP", "UDP"):
        return True
    return False


def _local_macs():
    """MAC addresses of this machine's own interfaces (best effort)."""
    macs = set()
    try:
        for name in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{name}/address") as f:
                    mac = f.read().strip().lower()
                if mac and mac != "00:00:00:00:00:00":
                    macs.add(mac)
            except OSError:
                continue
    except OSError:
        pass
    return macs


def mac_from_eui64(ip):
    """Recover the MAC from an EUI-64 IPv6 address (…ff:fe… pattern), or ""."""
    a = _parse_ip(ip)
    if a is None or a.version != 6:
        return ""
    b = a.packed
    if b[11] != 0xFF or b[12] != 0xFE:
        return ""
    mac = bytes([b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]])
    return ":".join(f"{x:02x}" for x in mac)

# --------------------------------------------------------------------------
# alert engine
# --------------------------------------------------------------------------

class AlertEngine:
    """Sliding-window heuristics over drop events + connection events. All
    thresholds and enable flags are read live from state.config, so editing the
    profile takes effect on the next event without a restart."""

    COOLDOWN = 600                                # 10 min per (rule, key)

    def __init__(self, state):
        self.state = state
        self.suspicious_re = state.backend.suspicious_path_re()
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

    def _fire(self, key, severity, rule, title, detail, origin="system"):
        now = time.time()
        if now - self.cooldowns.get(key, 0) < self.COOLDOWN:
            return
        self.cooldowns[key] = now
        self.state._emit_alert(severity, rule, title, detail, origin)

    @staticmethod
    def _origin_of(ip):
        return "local" if classify_ip(ip) in ("private", "loopback",
                                              "multicast") else "internet"

    def describe_source(self, ip):
        """Plain-language origin for alert copy: 'your router', 'a device on
        your local network', 'an internet address' — never a bare address."""
        cls = classify_ip(ip)
        gw = self.state.fw.get("gateway", "")
        if gw and ip.split("%")[0] == gw:
            return f"your router ({ip})"
        if cls == "loopback":
            return f"this computer ({ip})"
        if cls in ("private", "multicast"):
            mac = self.state.fw.get("neighbors", {}).get(ip.split("%")[0], "") \
                or mac_from_eui64(ip)
            mac = mac.replace("-", ":").lower()
            if mac:
                if mac in self.state.local_macs:
                    return f"a network adapter on this PC ({ip})"
                if gw and mac == self.state.fw.get("neighbors", {}) \
                        .get(gw, "").replace("-", ":").lower():
                    return f"your router ({ip})"
                return f"a device on your local network ({ip}, MAC {mac})"
            return f"a device on your local network ({ip})"
        if cls == "public":
            return f"an internet address ({ip})"
        return str(ip)

    def feed_drops(self, drops):
        """Attack heuristics run ONLY on non-background TCP/UDP drops with a
        real destination port — link-local/NDP/multicast chatter never reaches
        them (see is_background_drop), so routine local-network noise cannot
        trip a 'repeated attempts' alert."""
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
            if d.get("bg") or is_background_drop(d) or str(dport) in ("0", ""):
                continue
            if scan_on:
                dq = self.drop_by_src.setdefault(src, deque(maxlen=400))
                dq.append((now, dport))
                recent = {p for t, p in dq if now - t <= scan_win}
                if len(recent) >= scan_ports:
                    self._fire(("scan", src), "critical", "port-scan",
                               f"Port scan from {self.describe_source(src)}",
                               f"{len(recent)} different ports probed in "
                               f"{scan_win}s - every attempt was blocked by "
                               f"the firewall", origin=self._origin_of(src))
                    self.state.request_auto_block(src, "port scan", "on_portscan")
            if brute_on:
                bq = self.brute.setdefault((src, dport), deque(maxlen=200))
                bq.append(now)
                hits = [t for t in bq if now - t <= brute_win]
                # sustained-gated: many hits AND spread over at least a minute,
                # so a short benign burst can't raise an alarming alert
                if len(hits) >= brute_hits and hits[-1] - hits[0] >= 60:
                    self._fire(("brute", src, dport), "serious", "brute-force",
                               f"Repeated blocked attempts from "
                               f"{self.describe_source(src)}",
                               f"{len(hits)} blocked connection attempts to "
                               f"port {dport} in {brute_win // 60} min",
                               origin=self._origin_of(src))
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
        if self._on("suspicious_path") and path and self.suspicious_re.search(path):
            self._fire(("path", path), "serious", "suspicious-path",
                       f"Network activity from unusual location: {proc}",
                       f"{path} connected to {raddr}:{rport}")
        if self._on("plaintext_dns") and rport == 53 and classify_ip(raddr) == "public":
            self._fire(("dns", proc), "warning", "plaintext-dns",
                       f"Plaintext DNS by {proc}",
                       f"TCP to {raddr}:53 bypasses the system's encrypted "
                       f"DNS path")
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

# firewall-status fields carried between refreshes (backend may omit keys)
_FW_DEFAULTS = {
    "profiles": [], "connection": [], "rules": [], "lockdown": False,
    "ipv6_blocked": False, "log_blocked": False, "dns_names": {},
    "gateway": "", "neighbors": {}, "fw_active": True, "defaults": {},
    "error": "",
}


class State:
    def __init__(self, backend=None):
        self.backend = backend or backend_mod.get_backend()
        self.caps = self.backend.capabilities()
        self.lock = threading.Lock()
        self.conns = []
        self.history = deque(maxlen=HISTORY_LEN)
        self.events = deque(maxlen=EVENT_KEEP)
        self.alerts = deque(maxlen=ALERT_KEEP)
        self.if_names = []
        self.drop_count_today = 0
        self.started = time.time()
        self.fw = dict(_FW_DEFAULTS)
        self.last_refresh = 0.0
        os.makedirs(LOG_DIR, exist_ok=True)
        self.config = cfgmod.load_config(CONFIG_PATH)
        self.config_mtime = self._cfg_mtime()
        self.active_profile = None            # current network category name
        self.local_macs = _local_macs()       # to recognise our own adapters
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
        prev_auto = self.config.get("autostart", {}).get("enabled", None)
        try:
            cfgmod.save_config(CONFIG_PATH, cleaned)
        except OSError as e:
            return False, f"could not write config: {e}"
        self.config = cleaned
        self.config_mtime = self._cfg_mtime()
        self._emit_event("action", "config saved from dashboard")
        new_auto = cleaned.get("autostart", {}).get("enabled", None)
        if new_auto is not None and new_auto != prev_auto:
            ok_a, msg_a = self.backend.set_autostart(bool(new_auto))
            self._emit_event("action",
                             f"start-at-login {'ON' if new_auto else 'OFF'} "
                             f"({msg_a})")
        return True, "saved"

    def note_elevated(self):
        """First successful elevation = the user has genuinely set the app
        up: default start-at-login ON (owner directive). Never flips a value
        the user has already decided, and never fires on a fresh install
        that was never elevated."""
        if self.config.get("autostart", {}).get("enabled", None) is None:
            cfg = json.loads(json.dumps(self.config))
            cfg["autostart"]["enabled"] = True
            self.save_config(cfg)

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
        if not self.backend.is_admin():
            return
        now = time.time()
        prev = self.auto_blocks.get(ip, 0)
        if prev > now:                        # already blocked and not expired
            return
        ttl = int(ab.get("ttl_minutes", 60))
        self.auto_blocks[ip] = now + ttl * 60

        def _do():
            ok, msg = self.backend.block_ip(ip, ttl_minutes=ttl)
            self.refresh_fw()
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
        gw, neigh = self.fw.get("gateway", ""), self.fw.get("neighbors", {})
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
                    f"on this network.", origin="local")
            self._gw_mac = mac
        # gateway sharing a MAC with another host = impersonation
        shared = [ip for ip, m in neigh.items() if m == mac and ip != gw]
        if mac and shared:
            self.alert_engine._fire(
                ("arpdup", mac), "serious", "arp-spoof",
                "Gateway MAC shared with another host",
                f"{gw} and {', '.join(shared[:3])} share MAC {mac} "
                f"- possible ARP spoofing.", origin="local")

    def _append_jsonl(self, name, obj):
        try:
            fn = os.path.join(LOG_DIR, f"{name}-{time.strftime('%Y%m%d')}.jsonl")
            with open(fn, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
        except OSError:
            pass

    def _emit_alert(self, severity, rule, title, detail, origin="system"):
        self._alert_seq += 1
        a = {"id": self._alert_seq, "ts": time.time(), "severity": severity,
             "rule": rule, "title": title, "detail": detail, "origin": origin}
        with self.lock:
            self.alerts.append(a)
        self._append_jsonl("alerts", a)

    def should_notify(self, alert):
        """Notification (popup) gate — NOT the alert-recording gate. Alerts are
        always recorded and visible in the dashboard; popups are opt-in
        (muted by default) and filtered by severity + origin category."""
        notif = self.config.get("notifications", {})
        if not notif.get("enabled", False) or not notif.get("balloons", True):
            return False
        try:
            min_rank = cfgmod.SEVERITIES.index(self.effective_min_severity())
        except ValueError:
            min_rank = 2
        if cfgmod.sev_rank(alert.get("severity", "info")) < min_rank:
            return False
        cats = notif.get("categories", {})
        origin = alert.get("origin", "system")
        if origin == "local" and not cats.get("local", False):
            return False
        if origin == "internet" and not cats.get("internet", True):
            return False
        return True

    def _emit_event(self, kind, text, meta=None):
        ev = {"ts": time.time(), "kind": kind, "text": text}
        if meta:
            ev.update(meta)
        with self.lock:
            self.events.append(ev)
        self._append_jsonl("events", ev)

    # -- firewall status ----------------------------------------------------
    def refresh_fw(self):
        st = self.backend.refresh_status()
        with self.lock:
            merged = dict(self.fw)
            for k, v in st.items():
                merged[k] = v
            self.fw = merged
            self.last_refresh = time.time()

    def poll_once(self):
        conns = self.backend.snapshot_connections()
        dns = self.fw.get("dns_names", {})
        for c in conns:
            c["class"] = classify_ip(c["raddr"]) if c["raddr"] not in ("*",) else ""
            c["host"] = dns.get(c["raddr"], "") if c["raddr"] not in ("*",) else ""

        down, up, names = self.backend.snapshot_throughput()
        point = {"t": time.time(), "down": round(down), "up": round(up),
                 "conns": sum(1 for c in conns if c["state"] == "ESTABLISHED")}

        # new-connection events (established TCP with a real remote)
        flows = {(c["proto"], c["pid"], c["raddr"], c["rport"])
                 for c in conns
                 if c["state"] == "ESTABLISHED" and c["class"] in ("public", "private")}
        if self._flows_primed:
            by_flow = {(c["proto"], c["pid"], c["raddr"], c["rport"]): c
                       for c in conns}
            for f in flows - self._known_flows:
                proto, pid, raddr, rport = f
                c = by_flow.get(f, {})
                ev = {"proc": c.get("proc", "?"), "path": c.get("path", ""),
                      "raddr": raddr, "rport": rport}
                self._emit_event("connect",
                                 f"{ev['proc']} → {raddr}:{rport} ({proto})", ev)
                self.alert_engine.feed_new_connection(ev)
        self._known_flows = flows
        self._flows_primed = True

        # listener tracking (TCP LISTEN on non-loopback)
        listeners = {(c["lport"], c["proc"]) for c in conns
                     if c["state"] == "LISTEN" and
                     not c["laddr"].startswith("127.") and c["laddr"] != "::1"}
        self.alert_engine.feed_listeners(listeners)

        # firewall drop feed. Background chatter (link-local NDP/RA, multicast,
        # non-TCP/UDP) is shown low-key and NEVER counted or alerted as an
        # attack; "port 0" never reaches user-facing text — the protocol name
        # is shown instead.
        drops = self.backend.read_new_drops()
        real_drops = 0
        for d in drops:
            d["proto"] = proto_name(d.get("proto"))
            d["bg"] = is_background_drop(d)
            with_ports = (d["proto"] in ("TCP", "UDP")
                          and str(d.get("dport", "0")) not in ("0", ""))
            src = f"{d['src']}:{d['sport']}" if with_ports else d["src"]
            dst = f"{d['dst']}:{d['dport']}" if with_ports else d["dst"]
            if d["bg"]:
                self._emit_event("noise",
                                 f"local background traffic blocked "
                                 f"({d['proto']})  {src} → {dst}", d)
            else:
                real_drops += 1
                self._emit_event("drop",
                                 f"DROP {d['proto']} {src} → {dst} "
                                 f"({d['dir']})", d)
        self.alert_engine.feed_drops(drops)

        with self.lock:
            self.conns = conns
            self.if_names = names
            self.history.append(point)
            self.drop_count_today += real_drops
        self.alert_engine.feed_throughput(self.history)

    def _current_category(self):
        # strictest present wins (a laptop should harden to its least-trusted net)
        cats = {c.get("category") for c in self.fw.get("connection", [])}
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
            if time.time() - self.last_refresh > STATUS_REFRESH_SECS:
                try:
                    self.refresh_fw()
                    if self.caps.get("net_profiles"):
                        cat = self._current_category()
                        if cat:
                            self.apply_network_profile(cat)
                    self.check_arp()
                    if self.backend.is_admin():
                        self.backend.reap_expired(self.fw.get("rules", []))
                except Exception as e:
                    self._emit_event("error", f"rules: {e!r}")
            time.sleep(max(0.5, float(self.config.get("poll_secs", POLL_SECS))))

    def to_json(self):
        with self.lock:
            fw = self.fw
            return json.dumps({
                "admin": self.backend.is_admin(),
                "caps": self.caps,
                "uptime": round(time.time() - self.started),
                "interfaces": self.if_names,
                "profiles": [{"alias": c["alias"], "category": c["category"],
                              "name": c["name"]}
                             for c in fw.get("connection", [])],
                "lockdown": fw.get("lockdown", False),
                "ipv6_blocked": fw.get("ipv6_blocked", False),
                "log_blocked": fw.get("log_blocked", False),
                "fw_active": fw.get("fw_active", True),
                "defaults": fw.get("defaults", {}),
                "rules": fw.get("rules", []),
                "conns": self.conns,
                "history": list(self.history),
                "events": list(self.events)[-EVENT_KEEP:],
                "alerts": list(self.alerts),
                "drops_today": self.drop_count_today,
                "active_profile": self.active_profile,
                "gateway": fw.get("gateway", ""),
                "notify": {
                    "enabled": self.config.get("notifications", {})
                               .get("enabled", False),
                    "balloons": self.config.get("notifications", {})
                                .get("balloons", True),
                    "min_severity": self.effective_min_severity(),
                    "categories": self.config.get("notifications", {})
                                  .get("categories", {}),
                },
            })

    def config_json(self):
        return json.dumps(self.config, indent=2)


STATE = None      # created in main() (or by tests with a fake backend)


def init_state(backend=None):
    global STATE
    if STATE is None:
        STATE = State(backend)
    return STATE

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

    # endpoints that only touch the per-user config file — never privileged
    UNPRIVILEGED = ("/api/config", "/api/reload", "/api/elevate")

    def do_POST(self):
        if not self._authed():
            return self._send(401, '{"error":"bad token"}')
        if not STATE.backend.is_admin() and self.path not in self.UNPRIVILEGED:
            # deferred elevation: no prompt at login — the FIRST action that
            # actually needs privileges raises the system prompt, right here,
            # then the helper stays for the session.
            if STATE.caps.get("elevate_live"):
                ok, _msg = STATE.backend.elevate()
                if ok:
                    STATE.note_elevated()
                    threading.Thread(target=STATE.refresh_fw,
                                     daemon=True).start()
            if not STATE.backend.is_admin():
                hint = STATE.caps.get("elevate_hint", "restart elevated")
                return self._send(403, json.dumps(
                    {"error": f"server not elevated — {hint}"}))
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, '{"error":"bad json"}')
        try:
            ok, msg = self._dispatch(self.path, body)
        except backend_mod.Unsupported as e:
            return self._send(400, json.dumps({"error": str(e)}))
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, json.dumps({"error": str(e)}))
        # refresh rule cache after any mutation
        if ok and self.path not in ("/api/kill", "/api/elevate"):
            threading.Thread(target=STATE.refresh_fw, daemon=True).start()
        return self._send(200 if ok else 500,
                          json.dumps({"ok": ok, "msg": msg}))

    def _dispatch(self, path, body):
        b = STATE.backend
        if path == "/api/kill":
            ok, msg = b.kill_conn(body["kill"])
            STATE._emit_event("action", f"kill connection {msg}")
            return ok, msg
        if path == "/api/config":
            ok, msg = STATE.save_config(body.get("config"))
            return ok, msg
        if path == "/api/reload":
            STATE.reload_config()
            return True, "config reloaded"
        if path == "/api/elevate":
            ok, msg = b.elevate()
            STATE._emit_event("action", f"elevate requested: {msg}")
            if ok:
                STATE.note_elevated()
                threading.Thread(target=STATE.refresh_fw, daemon=True).start()
            return ok, msg
        if path == "/api/block-ip":
            ttl = body.get("ttl_minutes")
            ok, msg = b.block_ip(str(body["ip"]), ttl_minutes=ttl)
            STATE._emit_event("action",
                              f"block ip {body['ip']}"
                              f"{(' for '+str(ttl)+'m') if ttl else ''} ok={ok}")
            return ok, msg
        if path == "/api/block-app":
            ok, msg = b.rule_for_app(str(body["path"]), "Block")
            STATE._emit_event("action", f"block app {body['path']} ok={ok}")
            return ok, msg
        if path == "/api/allow-app":
            ok, msg = b.rule_for_app(str(body["path"]), "Allow")
            STATE._emit_event("action", f"allow app {body['path']} ok={ok}")
            return ok, msg
        if path == "/api/add-rule":
            ok, msg = b.add_port_rule(str(body["action"]), str(body["port"]),
                                      body.get("proto"),
                                      str(body.get("direction", "in")))
            STATE._emit_event("action",
                              f"add rule {body.get('action')} "
                              f"{body.get('port')} ok={ok}")
            return ok, msg
        if path == "/api/unblock":
            ok, msg = b.remove_rule(str(body["name"]), body.get("number"))
            STATE._emit_event("action", f"remove rule {body['name']} ok={ok}")
            return ok, msg
        if path == "/api/lockdown":
            ok, msg = b.set_lockdown(bool(body["enable"]))
            STATE._emit_event("action",
                              f"lockdown {'ON' if body['enable'] else 'OFF'} ok={ok}")
            return ok, msg
        if path == "/api/block-ipv6":
            ok, msg = b.set_block_ipv6(bool(body["enable"]))
            STATE._emit_event("action",
                              f"block-ipv6 {'ON' if body['enable'] else 'OFF'} ok={ok}")
            return ok, msg
        raise ValueError("unknown endpoint")


def main():
    state = init_state()
    backend = state.backend
    if not backend.acquire_single_instance():
        # menu-launch safety net: never a dead click — hand the user the
        # already-running dashboard instead of silently exiting
        if backend.activate_existing():
            print("PrivateFirewall is already running — opened the existing "
                  "dashboard.", flush=True)
        else:
            print("PrivateFirewall is already running; this instance will "
                  "exit.", flush=True)
        return

    # Deferred elevation (owner directive): NEVER prompt at login/launch.
    # The engine starts fully functional read-only — connections, throughput,
    # drop feed and the unprivileged firewall status are all readable without
    # root — and the FIRST privileged action (rule add/remove, lockdown,
    # kill...) raises the system prompt via do_POST, once per session.
    threading.Thread(target=state.refresh_fw, daemon=True).start()

    # start-at-login repair: keep the login entry consistent with the saved
    # preference (e.g. after an OS reinstall the config survives in $HOME)
    auto = state.config.get("autostart", {}).get("enabled", None)
    if auto is not None:
        backend.set_autostart(bool(auto))

    threading.Thread(target=state.loop, daemon=True).start()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    url = f"http://{BIND_HOST}:{BIND_PORT}/#t={TOKEN}"
    backend.publish_instance_url(url)
    print(f"PrivateFirewall engine  admin={backend.is_admin()}  {url}",
          flush=True)

    if "--tray" in sys.argv:
        # tray owns the main thread's message loop; HTTP serves in back.
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        if "--open" in sys.argv:
            backend.open_external(url)
        try:
            if os.name == "nt":
                import tray
                tray.run_tray(state, url, LOG_DIR, backend.open_external,
                              backend.is_admin(), CONFIG_PATH)
            else:
                import tray_linux
                tray_linux.run_tray(state, url, LOG_DIR, backend.open_external,
                                    CONFIG_PATH)
        except Exception as e:                  # never let a tray failure kill
            print(f"tray unavailable ({e!r}); serving headless", flush=True)
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                pass
        backend.shutdown()
        return

    if "--open" in sys.argv:
        backend.open_external(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    backend.shutdown()


if __name__ == "__main__":
    main()
