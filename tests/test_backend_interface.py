"""Engine <-> backend interface tests using a fake backend.

These run on any OS (they are part of the Windows CI too): they prove the
platform-neutral engine — State, poller, alert plumbing, HTTP API dispatch —
drives ONLY the FirewallBackend interface, and that capability flags and admin
gating behave.
"""

import json
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.request

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "pfw"))

os.environ.setdefault("PFW_LOG_DIR",
                      os.path.join(tempfile.mkdtemp(prefix="pfw-test-"), "logs"))
os.environ["PFW_NO_SINGLETON"] = "1"
os.environ["PFW_NO_ELEVATE"] = "1"
os.environ["PFW_TOKEN"] = "test-token"

from backend import FirewallBackend, Unsupported  # noqa: E402
import server  # noqa: E402


class FakeBackend(FirewallBackend):
    platform = "fake"

    def __init__(self, admin=True):
        self.admin = admin
        self.calls = []
        self.rules = [
            {"name": "PFW Block 192.0.2.9", "enabled": "True", "dir": "Inbound",
             "action": "Block", "remote": "192.0.2.9", "program": "",
             "ours": True, "number": 1},
            {"name": "22/tcp ALLOW IN", "enabled": "True", "dir": "Inbound",
             "action": "Allow", "remote": "Anywhere", "program": "",
             "ours": False, "number": 2},
        ]

    def capabilities(self):
        return {"platform": "fake", "firewall": "fakefw", "kill_conn": True,
                "app_rules": False, "port_rules": True, "net_profiles": False,
                "ipv6_toggle": True, "dns_names": False, "rules_shared": True,
                "elevate_live": True, "elevate_hint": "authorize"}

    def is_admin(self):
        return self.admin

    def elevate(self):
        self.admin = True
        return True, "elevated"

    def snapshot_connections(self):
        return [{"proto": "TCP", "pid": 42, "proc": "fake", "path": "/bin/fake",
                 "laddr": "10.0.0.5", "lport": 5555, "raddr": "93.184.216.34",
                 "rport": 443, "state": "ESTABLISHED",
                 "kill": ["10.0.0.5", 5555, "93.184.216.34", 443]}]

    def snapshot_throughput(self):
        return 1000.0, 2000.0, ["fake0"]

    def refresh_status(self):
        return {"rules": list(self.rules), "lockdown": False,
                "ipv6_blocked": False, "log_blocked": True, "fw_active": True,
                "dns_names": {}, "gateway": "10.0.0.1", "neighbors": {},
                "profiles": [], "connection": [], "defaults": {}, "error": ""}

    def read_new_drops(self):
        return []

    def kill_conn(self, kill):
        self.calls.append(("kill", kill))
        return True, "killed"

    def block_ip(self, ip, ttl_minutes=None):
        self.calls.append(("block_ip", ip, ttl_minutes))
        return True, "blocked"

    def add_port_rule(self, action, port, proto=None, direction="in"):
        self.calls.append(("add_port_rule", action, port, proto, direction))
        return True, "added"

    def remove_rule(self, name, number=None):
        self.calls.append(("remove_rule", name))
        return True, "removed"

    def set_lockdown(self, enable):
        self.calls.append(("lockdown", enable))
        return True, "ok"

    def set_block_ipv6(self, enable):
        self.calls.append(("ipv6", enable))
        return True, "ok"

    def open_external(self, path):
        self.calls.append(("open", path))

    def suspicious_path_re(self):
        return re.compile(r"/tmp/")


def make_state(admin=True):
    fake = FakeBackend(admin=admin)
    return server.State(backend=fake), fake


class StateTests(unittest.TestCase):
    def test_poll_once_uses_backend(self):
        st, fake = make_state()
        st.refresh_fw()
        st.poll_once()
        self.assertEqual(len(st.conns), 1)
        c = st.conns[0]
        self.assertEqual(c["class"], "public")
        self.assertEqual(st.if_names, ["fake0"])
        self.assertEqual(len(st.history), 1)
        self.assertEqual(st.history[0]["down"], 1000)

    def test_to_json_has_caps_and_rules(self):
        st, fake = make_state()
        st.refresh_fw()
        st.poll_once()
        d = json.loads(st.to_json())
        self.assertEqual(d["caps"]["platform"], "fake")
        self.assertTrue(d["caps"]["port_rules"])
        self.assertEqual(len(d["rules"]), 2)
        self.assertTrue(d["admin"])
        self.assertTrue(d["fw_active"])

    def test_auto_block_needs_admin(self):
        st, fake = make_state(admin=False)
        st.config["auto_block"]["on_portscan"] = True
        st.request_auto_block("198.51.100.9", "test", "on_portscan")
        self.assertNotIn(("block_ip", "198.51.100.9", 60), fake.calls)

    def test_reap_expired_default_impl(self):
        st, fake = make_state()
        fake.rules.append({"name": "PFW AutoBlock 198.51.100.7 until 1000",
                           "ours": True, "number": 3})
        removed = fake.reap_expired(fake.rules)
        self.assertEqual(removed, 1)
        self.assertIn(("remove_rule", "PFW AutoBlock 198.51.100.7 until 1000"),
                      fake.calls)

    def test_alert_engine_uses_backend_suspicious_re(self):
        st, fake = make_state()
        st.refresh_fw()
        st.alert_engine.feed_new_connection(
            {"proc": "evil", "path": "/tmp/evil", "raddr": "203.0.113.9",
             "rport": 4444})
        self.assertTrue(any(a["rule"] == "suspicious-path" for a in st.alerts))


class ApiTests(unittest.TestCase):
    """Drive the real HTTP handler against the fake backend."""

    @classmethod
    def setUpClass(cls):
        server.STATE, cls.fake = make_state()
        server.STATE.refresh_fw()
        from http.server import ThreadingHTTPServer
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        server.STATE = None

    def _req(self, path, body=None, token=None):
        token = server.TOKEN if token is None else token
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data,
                                     headers={"X-PFW-Token": token,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_state_requires_token(self):
        code, _ = self._req("/api/state", token="wrong")
        self.assertEqual(code, 401)

    def test_state_ok(self):
        code, d = self._req("/api/state")
        self.assertEqual(code, 200)
        self.assertEqual(d["caps"]["platform"], "fake")

    def test_add_rule_dispatch(self):
        code, d = self._req("/api/add-rule",
                            {"action": "deny", "port": "8080", "proto": "tcp",
                             "direction": "in"})
        self.assertEqual(code, 200)
        self.assertTrue(d["ok"])
        self.assertIn(("add_port_rule", "deny", "8080", "tcp", "in"),
                      self.fake.calls)

    def test_block_ip_dispatch(self):
        code, d = self._req("/api/block-ip", {"ip": "203.0.113.5"})
        self.assertTrue(d["ok"])
        self.assertIn(("block_ip", "203.0.113.5", None), self.fake.calls)

    def test_kill_dispatch(self):
        code, d = self._req("/api/kill",
                            {"kill": ["10.0.0.5", 5555, "93.184.216.34", 443]})
        self.assertTrue(d["ok"])

    def test_unsupported_maps_to_400(self):
        code, d = self._req("/api/block-app", {"path": "/bin/true"})
        self.assertEqual(code, 400)   # fake has no app_rules -> Unsupported

    def test_unelevated_is_read_only_but_can_elevate(self):
        self.fake.admin = False
        try:
            code, d = self._req("/api/block-ip", {"ip": "203.0.113.6"})
            self.assertEqual(code, 403)
            code, d = self._req("/api/elevate", {})
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
            self.assertTrue(self.fake.admin)
        finally:
            self.fake.admin = True


if __name__ == "__main__":
    unittest.main()
