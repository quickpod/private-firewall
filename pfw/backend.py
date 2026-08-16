"""Platform abstraction for PrivateFirewall.

The engine (server.py) is platform-neutral: state manager, alert engine and the
localhost HTTP API all talk to ONE FirewallBackend object obtained from
:func:`get_backend`.  The two implementations are:

* ``backend_windows`` — the original implementation on top of Windows Firewall
  (WFP) via ctypes + PowerShell.  Moved behind this interface unchanged; its
  WinDLL handles load lazily so the module *imports* cleanly on any OS.
* ``backend_linux``  — drives ufw (the firewall Quick OS / Ubuntu actually ship
  enabled) plus /proc for connections and throughput.  Privileged operations go
  through one pkexec-launched root helper (see root_helper.py), so the user
  authorizes once per session — the Linux analog of the Windows UAC prompt.

Feature parity is *honest*: what a platform cannot express is declared in
:meth:`FirewallBackend.capabilities` and the dashboard hides or re-labels the
control instead of faking it.  See README "Windows / Linux feature map".
"""

import os
import re
import sys

#: conn dict schema every backend's snapshot_connections() must produce:
#:   proto ("TCP"/"TCP6"/"UDP"/"UDP6"), pid (int), proc (name), path (exe path)
#:   laddr, lport, raddr, rport, state (TCP_STATES verb / "LISTEN"),
#:   kill (opaque token the backend's kill_conn accepts, or None)

TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


class Unsupported(Exception):
    """Raised by a backend for an operation its platform cannot express."""


class FirewallBackend:
    """The contract server.py codes against. All methods are synchronous;
    long-running ones are called off the UI/HTTP threads by the poller."""

    platform = "?"

    # -- meta ---------------------------------------------------------------
    def capabilities(self):
        """Static feature flags the dashboard uses to show/hide controls.

        Keys (all optional, default False/""):
          platform        "windows" | "linux"
          firewall        human name of the enforcing firewall
          kill_conn       can terminate a single TCP connection
          app_rules       per-EXECUTABLE allow/block rules (WFP concept;
                          netfilter/ufw has no per-binary match -> False there)
          port_rules      allow/deny by port/protocol/direction (ufw's model)
          net_profiles    Public/Private/Domain network categories
          ipv6_toggle     can block all IPv6 (with a note how)
          ipv6_how        one-line description of the IPv6 mechanism
          dns_names       connection rows annotated from a DNS cache
          rules_shared    rule list includes rules NOT created by this app
                          (ufw is the OS firewall; we must coexist, not own it)
          elevate_live    engine can gain admin without a restart (/api/elevate)
          elevate_hint    what the user should do when unelevated
        """
        raise NotImplementedError

    def is_admin(self):
        raise NotImplementedError

    def elevate(self):
        """Try to gain privileges now (Linux: spawn the pkexec helper).
        Returns (ok, message). Platforms that need a restart return False."""
        return False, "restart required"

    # -- observation --------------------------------------------------------
    def snapshot_connections(self):
        raise NotImplementedError

    def snapshot_throughput(self):
        """-> (down_Bps, up_Bps, [interface names])"""
        raise NotImplementedError

    def refresh_status(self):
        """Query the firewall itself. Returns a dict:
        profiles, connection ([{alias,name,category}]), rules ([{name,enabled,
        dir,action,remote,program,ours,number}]), lockdown (bool),
        ipv6_blocked (bool), log_blocked (bool), dns_names ({ip: host}),
        gateway (ip str), neighbors ({ip: mac}), error ("" on success).
        Missing keys keep their previous value engine-side."""
        raise NotImplementedError

    def read_new_drops(self):
        """New blocked-connection records since last call:
        [{ts, proto, src, dst, sport, dport, dir(SEND|RECEIVE|?)}]"""
        raise NotImplementedError

    # -- actions (all return (ok, msg)) -------------------------------------
    def kill_conn(self, kill):
        raise Unsupported("kill not supported")

    def block_ip(self, ip, ttl_minutes=None):
        raise NotImplementedError

    def rule_for_app(self, path, action):
        raise Unsupported("per-application rules not supported")

    def add_port_rule(self, action, port, proto=None, direction="in"):
        raise Unsupported("port rules not supported")

    def remove_rule(self, name, number=None):
        raise NotImplementedError

    def set_lockdown(self, enable):
        raise NotImplementedError

    def set_block_ipv6(self, enable):
        raise Unsupported("IPv6 toggle not supported")

    # -- environment --------------------------------------------------------
    def acquire_single_instance(self):
        return True

    def publish_instance_url(self, url):
        """Record where the running engine's dashboard lives so a second
        launch can hand the user the EXISTING dashboard (menu-launch safety
        net when there is no tray). Default: no-op."""

    def set_autostart(self, enabled):
        """Install/remove a start-at-login entry (tray only, no window).
        Returns (ok, msg). Default: unsupported no-op."""
        return False, "autostart not supported on this platform"

    def activate_existing(self):
        """Called when acquire_single_instance() failed: raise/show the
        already-running instance. Returns True when something was opened."""
        return False

    def open_external(self, path):
        raise NotImplementedError

    def suspicious_path_re(self):
        """Regex matching executable paths that are unusual origins for
        network activity on this platform."""
        return re.compile(r"$^")

    def reap_expired(self, rules):
        """Remove timed auto-block rules whose expiry passed. Default engine
        behaviour works off the rule name; backends may override."""
        import time
        removed = 0
        now = int(time.time())
        for r in list(rules):
            m = re.search(r" until (\d+)\b", r.get("name", ""))
            if m and int(m.group(1)) <= now:
                ok, _ = self.remove_rule(r.get("name", ""), r.get("number"))
                removed += 1 if ok else 0
        return removed

    def shutdown(self):
        pass


def get_backend():
    """Instantiate the backend for the running OS."""
    forced = os.environ.get("PFW_BACKEND", "")
    name = forced or ("windows" if os.name == "nt" else
                      "linux" if sys.platform.startswith("linux") else "")
    if name == "windows":
        import backend_windows
        return backend_windows.WindowsBackend()
    if name == "linux":
        import backend_linux
        return backend_linux.LinuxBackend()
    raise RuntimeError(
        f"PrivateFirewall supports Windows and Linux; not {sys.platform!r}")
