"""Linux implementation of the PrivateFirewall backend — drives ufw.

Quick OS (and stock Ubuntu server/desktop setups) ship **ufw enabled** as the
system firewall (default deny incoming / allow outgoing).  This backend is a
control plane ON TOP of that, exactly like the Windows backend sits on top of
WFP: it never re-routes packets, never disables ufw, and tags every rule it
creates with a ``PFW ...`` comment so one action can revert everything and the
user's / OS's own rules are never touched.

Privilege model: the engine runs as the logged-in user.  All privileged work
(ufw itself needs root even for ``status``) goes through ONE helper process
(root_helper.py) started via pkexec — a single graphical authorization per
session, the analog of the Windows UAC prompt at launch.  If the user declines,
the dashboard runs read-only on what /proc and world-readable config expose.

Honest feature mapping (see capabilities()):
  * per-APPLICATION rules (a WFP concept) do not exist in netfilter/ufw — there
    is no per-binary match.  ``app_rules`` is False; the nearest equivalents
    offered instead are port/protocol rules and ufw application *profiles*
    (named port sets), via ``port_rules``.
  * network categories (Public/Private/Domain) are a Windows concept ->
    ``net_profiles`` False.
  * "block all IPv6" maps to the ipv6.disable_ipv6 sysctl (immediate,
    reversible) rather than adapter unbinding.
  * connection kill uses ``ss -K`` (kernel CONFIG_INET_DIAG_DESTROY, present in
    Ubuntu kernels) and works for v4 AND v6 (better than Windows' v4-only).
"""

import fcntl
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

from backend import FirewallBackend

RULE_TAG = "PFW"          # every comment we write starts with this

# /proc/net/tcp "st" values (differ from the Windows MIB numbering!)
LINUX_TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RCVD", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSED", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "SYN_RCVD",
}

SUSPICIOUS_PATH_LINUX = re.compile(
    r"^/tmp/|^/var/tmp/|^/dev/shm/|/Downloads/", re.IGNORECASE)

# interfaces that mirror or virtualize traffic — skip for throughput totals
_VIRTUAL_IF = re.compile(
    r"^(lo|veth|docker|br-|virbr|vnet|tap|tun|wg|ppp0:|zt|flannel|cni|kube)")

_ACTION_WORD = {"ALLOW": "Allow", "DENY": "Block", "REJECT": "Block",
                "LIMIT": "Limit"}
_RULE_RE = re.compile(
    r"^(?:\[\s*(\d+)\]\s+)?(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s*(.*)$")
_DEFAULT_RE = re.compile(
    r"(allow|deny|reject|disabled)\s*\((incoming|outgoing|routed)\)", re.I)


# --------------------------------------------------------------------------
# ufw status parsing (pure — unit tested without root)
# --------------------------------------------------------------------------

def parse_ufw_status(verbose_text, numbered_text):
    """Parse ``ufw status verbose`` + ``ufw status numbered`` into a dict:
    {active, logging, default_incoming, default_outgoing, rules:[...]}. Rules
    come from the numbered output (they carry the [ n] used for deletion);
    comments after '#' become the rule name."""
    st = {"active": False, "logging": "", "default_incoming": "",
          "default_outgoing": "", "rules": []}
    for raw in (verbose_text or "").splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith("status:"):
            st["active"] = "inactive" not in low and "active" in low
        elif low.startswith("logging:"):
            st["logging"] = line.split(":", 1)[1].strip()
        elif low.startswith("default:"):
            for policy, direction in _DEFAULT_RE.findall(line):
                st["default_" + direction.lower()] = policy.lower()
    for raw in (numbered_text or "").splitlines():
        line = raw.strip()
        low = line.lower()
        if (not line or low.startswith(("status:", "logging:", "default:",
                                        "new profiles:", "to ", "--"))):
            continue
        comment = ""
        if "#" in line:
            line, _, comment = line.partition("#")
            line, comment = line.rstrip(), comment.strip()
        m = _RULE_RE.match(line)
        if not m:
            continue
        num, to_col, verb, direction, from_col = m.groups()
        to_col = (to_col or "").strip()
        from_col = (from_col or "").strip() or "Anywhere"
        v6 = "(v6)" in to_col or "(v6)" in from_col
        target = to_col if direction == "OUT" else (
            from_col if from_col not in ("Anywhere", "Anywhere (v6)") else to_col)
        st["rules"].append({
            "number": int(num) if num else None,
            "name": comment or f"{to_col} {verb} {direction} {from_col}",
            "enabled": "True",
            "dir": {"IN": "Inbound", "OUT": "Outbound", "FWD": "Forward"}[direction],
            "action": _ACTION_WORD.get(verb, verb),
            "remote": target,
            "program": "",
            "ours": comment.startswith(RULE_TAG),
            "v6": v6,
            "to": to_col, "from": from_col,
        })
    return st


def parse_ufw_log_chunk(chunk):
    """Extract [UFW BLOCK] records from a kernel/ufw log chunk."""
    drops = []
    for line in chunk.splitlines():
        if "[UFW BLOCK]" not in line:
            continue
        fields = dict(m.group(1, 2) for m in
                      re.finditer(r"\b(IN|OUT|SRC|DST|PROTO|SPT|DPT)=(\S*)", line))
        src, dst = fields.get("SRC", ""), fields.get("DST", "")
        if not src or not dst:
            continue
        ts = " ".join(line.split()[:3])          # syslog "Aug 16 07:33:21"
        drops.append({
            "ts": ts, "proto": fields.get("PROTO", "?"),
            "src": src, "dst": dst,
            "sport": fields.get("SPT", "0"), "dport": fields.get("DPT", "0"),
            "dir": "RECEIVE" if fields.get("IN") else
                   ("SEND" if fields.get("OUT") else "?"),
        })
    return drops


# --------------------------------------------------------------------------
# /proc/net parsing (pure-ish — unit tested with fixture text)
# --------------------------------------------------------------------------

def _v4_from_hex(h):
    return socket.inet_ntoa(struct.pack("<I", int(h, 16)))


def _v6_from_hex(h):
    # 4 little-endian 32-bit groups
    raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_proc_net(text, proto, v6):
    """Parse /proc/net/{tcp,tcp6,udp,udp6} text into raw rows:
    (laddr, lport, raddr, rport, state_verb, inode)."""
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            lh, lp = parts[1].rsplit(":", 1)
            rh, rp = parts[2].rsplit(":", 1)
            st = int(parts[3], 16)
            inode = parts[9]
            laddr = _v6_from_hex(lh) if v6 else _v4_from_hex(lh)
            raddr = _v6_from_hex(rh) if v6 else _v4_from_hex(rh)
            rows.append((laddr, int(lp, 16), raddr, int(rp, 16),
                         LINUX_TCP_STATES.get(st, str(st)), inode))
        except (ValueError, OSError):
            continue
    return rows


def parse_route_gateway(text):
    """Default gateway IPv4 from /proc/net/route content."""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":
            try:
                return _v4_from_hex(parts[2])
            except (ValueError, OSError):
                return ""
    return ""


# --------------------------------------------------------------------------
# the pkexec root-helper client
# --------------------------------------------------------------------------

class HelperClient:
    """Client half of root_helper.py. One process per engine session; requests
    are serialized. If the helper dies (or authorization is declined) every
    call cleanly reports failure and is_alive() turns False."""

    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self._buf = b""
        self._seq = 0
        self.last_error = ""

    # -- lifecycle ----------------------------------------------------------
    def _prefix(self):
        env_cmd = os.environ.get("PFW_HELPER_CMD")
        if env_cmd is not None:                    # tests / SSH validation
            return env_cmd.split() if env_cmd else []
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return []
        pkexec = shutil.which("pkexec")
        if pkexec:
            return [pkexec]
        sudo = shutil.which("sudo")
        if sudo:
            return [sudo, "-n"]
        return None

    def start(self, timeout=180):
        """Spawn + ping the helper. Long timeout: the user may be typing an
        admin password into the polkit prompt. Returns (ok, message)."""
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return True, "already running"
            prefix = self._prefix()
            if prefix is None:
                self.last_error = "no pkexec or sudo available"
                return False, self.last_error
            helper = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "root_helper.py")
            python = shutil.which("python3") or sys.executable
            try:
                self.proc = subprocess.Popen(
                    [*prefix, python, helper],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL)
            except OSError as e:
                self.last_error = str(e)
                return False, self.last_error
            self._buf = b""
            resp = self._request_locked("ping", {}, timeout=timeout)
            if resp.get("ok") and resp.get("data", {}).get("uid") == 0:
                self.last_error = ""
                return True, "elevated"
            self._kill_locked()
            self.last_error = resp.get("err") or "authorization declined"
            return False, self.last_error

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        with self.lock:
            self._kill_locked()

    def _kill_locked(self):
        if self.proc:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                self.proc.stdout.close()
            except OSError:
                pass
            self.proc = None

    # -- request/response ---------------------------------------------------
    def _read_line(self, timeout):
        end = time.time() + timeout
        while b"\n" not in self._buf:
            remain = end - time.time()
            if remain <= 0:
                return None
            r, _, _ = select.select([self.proc.stdout], [], [], min(remain, 1.0))
            if not r:
                if self.proc.poll() is not None:
                    return None
                continue
            data = os.read(self.proc.stdout.fileno(), 65536)
            if not data:                           # EOF — helper exited
                return None
            self._buf += data
        line, _, self._buf = self._buf.partition(b"\n")
        return line

    def _request_locked(self, op, args, timeout=30):
        if not self.is_alive():
            return {"ok": False, "err": "helper not running"}
        self._seq += 1
        req = {"id": self._seq, "op": op, "args": args}
        try:
            self.proc.stdin.write((json.dumps(req) + "\n").encode())
            self.proc.stdin.flush()
        except (OSError, ValueError):
            self._kill_locked()
            return {"ok": False, "err": "helper pipe broken"}
        line = self._read_line(timeout)
        if line is None:
            self._kill_locked()
            return {"ok": False, "err": "helper timed out or exited "
                                        "(authorization declined?)"}
        try:
            return json.loads(line)
        except ValueError:
            return {"ok": False, "err": "bad helper response"}

    def request(self, op, args=None, timeout=30):
        with self.lock:
            return self._request_locked(op, args or {}, timeout)


# --------------------------------------------------------------------------
# the backend
# --------------------------------------------------------------------------

class LinuxBackend(FirewallBackend):
    platform = "linux"

    def __init__(self):
        self.helper = HelperClient()
        self._proc_cache = {}       # inode -> (pid, name, path)
        self._if_prev = {}          # ifname -> (ts, rx, tx)
        self._log_offset = -1       # -1 = prime near end on first read
        self._log_path = None
        self._lock_fd = None
        self._ufw = shutil.which("ufw") or "/usr/sbin/ufw"

    # -- meta ---------------------------------------------------------------
    def capabilities(self):
        return {
            "platform": "linux",
            "firewall": "ufw (Uncomplicated Firewall)",
            "kill_conn": True,          # via ss -K, v4 + v6
            "app_rules": False,         # netfilter has no per-executable match
            "app_rules_note": "Per-application rules are a Windows (WFP) "
                              "concept; Linux/ufw filters by port, address and "
                              "application profile instead.",
            "port_rules": True,
            "net_profiles": False,
            "ipv6_toggle": True,
            "ipv6_how": "sets the ipv6.disable_ipv6 sysctl on all interfaces "
                        "(immediate, reversible)",
            "dns_names": False,
            "rules_shared": True,       # the rule list includes system rules
            "elevate_live": True,
            "elevate_hint": "Click “Enable admin” and authorize in "
                            "the system prompt.",
        }

    def is_admin(self):
        return self.helper.is_alive()

    def elevate(self):
        return self.helper.start()

    # -- connections --------------------------------------------------------
    def _read_proc_net(self):
        rows = []
        for fn, proto, v6, is_tcp in (("tcp", "TCP", False, True),
                                      ("tcp6", "TCP6", True, True),
                                      ("udp", "UDP", False, False),
                                      ("udp6", "UDP6", True, False)):
            try:
                with open(f"/proc/net/{fn}") as f:
                    text = f.read()
            except OSError:
                continue
            for laddr, lport, raddr, rport, state, inode in \
                    parse_proc_net(text, proto, v6):
                if is_tcp:
                    if state == "CLOSED":
                        continue
                else:
                    state = "LISTEN"
                    raddr, rport = "*", 0
                rows.append({"proto": proto, "laddr": laddr, "lport": lport,
                             "raddr": raddr if is_tcp else "*",
                             "rport": rport if is_tcp else 0,
                             "state": state, "inode": inode})
        return rows

    def _attribute_local(self, wanted):
        """inode -> (pid, name, path) for processes we can read as this user."""
        out = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            info = None
            for fd in fds:
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    inode = target[8:-1]
                    if inode in wanted:
                        if info is None:
                            info = self._pid_info(pid)
                        out[inode] = info
            if len(out) >= len(wanted):
                break
        return out

    @staticmethod
    def _pid_info(pid):
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
        except OSError:
            name = f"pid:{pid}"
        try:
            path = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            path = ""
        return (int(pid), name, path)

    def snapshot_connections(self):
        rows = self._read_proc_net()
        wanted = {r["inode"] for r in rows if r["inode"] != "0"}
        resolved = {i: self._proc_cache[i] for i in wanted
                    if i in self._proc_cache}
        missing = wanted - set(resolved)
        if missing:
            resolved.update(self._attribute_local(missing))
            missing = wanted - set(resolved)
        if missing and self.helper.is_alive():
            resp = self.helper.request("pids", {"inodes": sorted(missing)})
            if resp.get("ok"):
                for inode, (pid, name, path) in (
                        (k, tuple(v)) for k, v in resp["data"].items()):
                    resolved[inode] = (pid, name, path)
        # cache only what resolved; prune entries for inodes gone from the table
        self._proc_cache = {i: v for i, v in resolved.items()}
        conns = []
        for r in rows:
            pid, name, path = resolved.get(r["inode"], (0, "?", ""))
            killable = (r["proto"].startswith("TCP")
                        and r["state"] == "ESTABLISHED")
            conns.append({
                "proto": r["proto"], "pid": pid, "proc": name, "path": path,
                "laddr": r["laddr"], "lport": r["lport"],
                "raddr": r["raddr"], "rport": r["rport"], "state": r["state"],
                "kill": [r["laddr"], r["lport"], r["raddr"], r["rport"]]
                        if killable else None,
            })
        return conns

    # -- throughput ---------------------------------------------------------
    def snapshot_throughput(self):
        try:
            with open("/proc/net/dev") as f:
                lines = f.read().splitlines()[2:]
        except OSError:
            return 0.0, 0.0, []
        now = time.time()
        down = up = 0.0
        names = []
        for line in lines:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if _VIRTUAL_IF.match(name):
                continue
            parts = rest.split()
            if len(parts) < 16:
                continue
            rx, tx = int(parts[0]), int(parts[8])
            prev = self._if_prev.get(name)
            if prev:
                dt = now - prev[0]
                if dt > 0:
                    d_rx, d_tx = rx - prev[1], tx - prev[2]
                    if d_rx >= 0:
                        down += d_rx / dt
                    if d_tx >= 0:
                        up += d_tx / dt
            self._if_prev[name] = (now, rx, tx)
            names.append(name)
        return down, up, names

    # -- firewall status ----------------------------------------------------
    def _status_unprivileged(self):
        """What we can see without root: enabled flag + default policies from
        world-readable config, IPv6 sysctl, gateway + neighbors."""
        st = {"active": False, "logging": "", "default_incoming": "",
              "default_outgoing": "", "rules": []}
        try:
            with open("/etc/ufw/ufw.conf") as f:
                st["active"] = re.search(r"^ENABLED\s*=\s*yes", f.read(),
                                         re.M) is not None
        except OSError:
            pass
        try:
            with open("/etc/default/ufw") as f:
                text = f.read()
            for key, field in (("DEFAULT_INPUT_POLICY", "default_incoming"),
                               ("DEFAULT_OUTPUT_POLICY", "default_outgoing")):
                m = re.search(rf'^{key}\s*=\s*"?(\w+)"?', text, re.M)
                if m:
                    st[field] = {"ACCEPT": "allow", "DROP": "deny",
                                 "REJECT": "reject"}.get(m.group(1), m.group(1))
        except OSError:
            pass
        return st

    def refresh_status(self):
        if self.helper.is_alive():
            resp = self.helper.request("status", {}, timeout=45)
            if resp.get("ok"):
                d = resp["data"]
                st = parse_ufw_status(d["verbose"]["out"], d["numbered"]["out"])
                err = "" if d["verbose"]["rc"] == 0 else \
                    (d["verbose"]["err"].strip() or "ufw status failed")
            else:
                st = self._status_unprivileged()
                err = resp.get("err", "helper error")
        else:
            st = self._status_unprivileged()
            err = ""
        return {
            "profiles": [],
            "connection": [],
            "rules": st["rules"],
            "fw_active": st["active"],
            "log_blocked": st.get("logging", "") not in ("", "off"),
            "lockdown": st.get("default_outgoing") in ("deny", "reject"),
            "ipv6_blocked": self._ipv6_disabled(),
            "dns_names": {},
            "gateway": self._gateway(),
            "neighbors": self._neighbors(),
            "defaults": {"incoming": st.get("default_incoming", ""),
                         "outgoing": st.get("default_outgoing", "")},
            "error": err,
        }

    @staticmethod
    def _ipv6_disabled():
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
                return f.read().strip() == "1"
        except OSError:
            return True       # no IPv6 stack at all
    @staticmethod
    def _gateway():
        try:
            with open("/proc/net/route") as f:
                return parse_route_gateway(f.read())
        except OSError:
            return ""

    @staticmethod
    def _neighbors():
        ip = shutil.which("ip") or "/usr/sbin/ip"
        try:
            p = subprocess.run([ip, "neigh", "show"], capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return {}
        out = {}
        for line in p.stdout.splitlines():
            m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+(\S+)\s+.*"
                         r"(REACHABLE|STALE|PERMANENT|DELAY)", line)
            if m:
                out[m.group(1)] = m.group(2)
        return out

    # -- drop feed ----------------------------------------------------------
    def _find_log(self):
        if self._log_path:
            return self._log_path
        for p in ("/var/log/ufw.log", "/var/log/kern.log", "/var/log/syslog"):
            if os.path.exists(p):
                self._log_path = p
                return p
        return None

    def read_new_drops(self):
        path = self._find_log()
        if not path:
            return []
        chunk = ""
        try:
            size = os.path.getsize(path)
            if self._log_offset < 0:
                self._log_offset = max(0, size - 65536)
            if size < self._log_offset:            # rotated
                self._log_offset = 0
            if size > self._log_offset:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._log_offset)
                    chunk = f.read(1 << 20)
                    self._log_offset = f.tell()
        except PermissionError:
            if not self.helper.is_alive():
                return []
            resp = self.helper.request(
                "tail", {"path": path, "offset": self._log_offset})
            if not resp.get("ok"):
                return []
            d = resp["data"]
            if self._log_offset < 0 or d["size"] < 0:
                self._log_offset = d["offset"]
                return []                          # primed; report from now on
            chunk, self._log_offset = d["data"], d["offset"]
        except OSError:
            return []
        return parse_ufw_log_chunk(chunk)

    # -- actions ------------------------------------------------------------
    def _ufw_do(self, argv):
        resp = self.helper.request("ufw", {"argv": argv}, timeout=45)
        if not resp.get("ok"):
            return False, resp.get("err", "helper error")
        d = resp["data"]
        ok = d["rc"] == 0
        msg = (d["err"].strip() or d["out"].strip())
        return ok, msg if not ok else (msg.splitlines()[0] if msg else "ok")

    def kill_conn(self, kill):
        if not (isinstance(kill, list) and len(kill) == 4):
            raise ValueError("bad kill tuple")
        laddr, lport, raddr, rport = kill
        args = {"laddr": str(laddr), "lport": int(lport),
                "raddr": str(raddr), "rport": int(rport)}
        ipaddress.ip_address(args["laddr"])        # raises on garbage
        ipaddress.ip_address(args["raddr"])
        resp = self.helper.request("kill", args)
        if not resp.get("ok"):
            return False, resp.get("err", "helper error")
        return resp["data"]["rc"] == 0, f"ss -K rc={resp['data']['rc']}"

    def block_ip(self, ip, ttl_minutes=None):
        addr = ipaddress.ip_address(str(ip))       # raises on garbage
        if ttl_minutes:
            exp = int(time.time()) + int(ttl_minutes) * 60
            name = f"{RULE_TAG} AutoBlock {addr} until {exp}"
        else:
            name = f"{RULE_TAG} Block {addr}"
        ok1, m1 = self._ufw_do(["prepend", "deny", "from", str(addr),
                                "comment", name])
        ok2, m2 = self._ufw_do(["prepend", "deny", "out", "to", str(addr),
                                "comment", name])
        return ok1 and ok2, (m1 if not ok1 else m2)

    def add_port_rule(self, action, port, proto=None, direction="in"):
        action = str(action).lower()
        if action not in ("allow", "deny", "limit", "reject"):
            return False, "action must be allow/deny/limit/reject"
        direction = str(direction).lower()
        if direction not in ("in", "out"):
            return False, "direction must be in or out"
        proto = (str(proto).lower() or None) if proto else None
        if proto and proto not in ("tcp", "udp"):
            return False, "protocol must be tcp or udp"
        port = str(port).strip()
        if re.fullmatch(r"\d{1,5}(:\d{1,5})?", port):
            spec = f"{port}/{proto}" if proto else port
            label = spec
        elif re.fullmatch(r"[A-Za-z][\w.+-]{0,39}", port):
            spec = port                            # ufw application profile
            label = f"profile {port}"
        else:
            return False, "give a port, port range (a:b) or app profile name"
        name = f"{RULE_TAG} {action.capitalize()} {label} {direction}"
        argv = [action] + (["out"] if direction == "out" else []) + [spec] \
            + ["comment", name]
        return self._ufw_do(argv)

    def remove_rule(self, name, number=None):
        """Remove every rule tagged with our comment *name*. Deletion is by
        rule number, re-resolved before each delete (numbers shift), and only
        PFW-tagged rules are ever deleted — a system rule (e.g. the OS's SSH
        allow) can never be removed through this API."""
        name = str(name)
        if not name.startswith(RULE_TAG):
            return False, "only PrivateFirewall (PFW) rules can be removed here"
        if not re.fullmatch(r"[\w .:\-\[\]()/]{1,120}", name):
            return False, "bad rule name"
        removed = 0
        for _ in range(16):                        # in+out pairs, v4+v6 shadows
            resp = self.helper.request("status", {}, timeout=45)
            if not resp.get("ok"):
                return removed > 0, resp.get("err", "helper error")
            st = parse_ufw_status("", resp["data"]["numbered"]["out"])
            match = next((r for r in st["rules"]
                          if r["ours"] and r["name"] == name
                          and r["number"]), None)
            if match is None:
                break
            ok, msg = self._ufw_do(["--force", "delete", str(match["number"])])
            if not ok:
                return removed > 0, msg
            removed += 1
        return removed > 0, f"removed {removed} rule(s)"

    def set_lockdown(self, enable):
        """Zero-trust outbound: ufw default deny outgoing, with DNS + DHCP kept
        open so the network layer works; everything else needs an Allow rule.
        Mirrors the Windows behaviour (DefaultOutboundAction Block)."""
        if enable:
            for argv in ((["allow", "out", "53", "comment",
                           f"{RULE_TAG} Core DNS"]),
                         (["allow", "out", "67:68/udp", "comment",
                           f"{RULE_TAG} Core DHCP"])):
                ok, msg = self._ufw_do(argv)
                if not ok:
                    return False, msg
            return self._ufw_do(["default", "deny", "outgoing"])
        return self._ufw_do(["default", "allow", "outgoing"])

    def set_block_ipv6(self, enable):
        resp = self.helper.request("sysctl_ipv6", {"disable": bool(enable)})
        if not resp.get("ok"):
            return False, resp.get("err", "helper error")
        d = resp["data"]
        return bool(d.get("ok")), d.get("err", "")

    # -- environment --------------------------------------------------------
    def acquire_single_instance(self):
        if os.environ.get("PFW_NO_SINGLETON"):
            return True
        run_dir = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
        path = os.path.join(run_dir, f"private-firewall-{os.getuid()}.lock")
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self._lock_fd = fd                         # keep open for process life
        return True

    def open_external(self, path):
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen([opener, path],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        else:
            import webbrowser
            webbrowser.open(path)

    def suspicious_path_re(self):
        return SUSPICIOUS_PATH_LINUX

    def shutdown(self):
        self.helper.stop()
