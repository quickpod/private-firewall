"""Pure-parser and validation tests for the Linux backend + root helper.

No root, no real ufw: these exercise the text parsers with fixture output and
the helper's command whitelist. They run on every OS (Windows CI included).
"""

import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "pfw"))

import backend_linux  # noqa: E402
import root_helper  # noqa: E402

UFW_VERBOSE = """\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
"""

UFW_NUMBERED = """\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 192.0.2.99                 DENY OUT    Anywhere                   (out) # PFW Block 192.0.2.99
[ 2] Anywhere                   DENY IN     192.0.2.99                 # PFW Block 192.0.2.99
[ 3] 22/tcp                     ALLOW IN    Anywhere
[ 4] 80/tcp                     ALLOW IN    127.0.0.1                  # cf-allowlist-auto
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

UFW_LOG = (
    "Aug 16 07:33:21 host kernel: [12.3] [UFW BLOCK] IN=ens33 OUT= "
    "MAC=00:0c:29 SRC=203.0.113.9 DST=198.51.100.2 LEN=60 PROTO=TCP "
    "SPT=54321 DPT=23 WINDOW=1024\n"
    "Aug 16 07:33:22 host kernel: [12.4] [UFW BLOCK] IN= OUT=ens33 "
    "SRC=198.51.100.2 DST=203.0.113.10 PROTO=UDP SPT=5353 DPT=53\n"
    "Aug 16 07:33:23 host kernel: unrelated line\n")

PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:E5F3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1
   1: 050010AC:15B3 070910AC:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1
"""

PROC_ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ens33\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\t0\t0\t0
ens33\t000010AC\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


class UfwStatusParserTests(unittest.TestCase):
    def test_verbose_headers(self):
        st = backend_linux.parse_ufw_status(UFW_VERBOSE, "")
        self.assertTrue(st["active"])
        self.assertEqual(st["logging"], "on (low)")
        self.assertEqual(st["default_incoming"], "deny")
        self.assertEqual(st["default_outgoing"], "allow")

    def test_numbered_rules_and_comments(self):
        st = backend_linux.parse_ufw_status(UFW_VERBOSE, UFW_NUMBERED)
        self.assertEqual(len(st["rules"]), 5)
        r1, r2, r3, r4, r5 = st["rules"]
        self.assertEqual(r1["number"], 1)
        self.assertEqual(r1["name"], "PFW Block 192.0.2.99")
        self.assertTrue(r1["ours"])
        self.assertEqual(r1["dir"], "Outbound")
        self.assertEqual(r1["action"], "Block")
        self.assertEqual(r2["dir"], "Inbound")
        self.assertEqual(r2["remote"], "192.0.2.99")
        self.assertFalse(r3["ours"])          # system rule, no PFW comment
        self.assertEqual(r3["action"], "Allow")
        self.assertFalse(r4["ours"])          # commented but not PFW
        self.assertTrue(r5["v6"])

    def test_inactive(self):
        st = backend_linux.parse_ufw_status("Status: inactive\n", "")
        self.assertFalse(st["active"])


class UfwLogParserTests(unittest.TestCase):
    def test_block_lines(self):
        drops = backend_linux.parse_ufw_log_chunk(UFW_LOG)
        self.assertEqual(len(drops), 2)
        d0, d1 = drops
        self.assertEqual(d0["src"], "203.0.113.9")
        self.assertEqual(d0["dport"], "23")
        self.assertEqual(d0["dir"], "RECEIVE")
        self.assertEqual(d0["proto"], "TCP")
        self.assertEqual(d1["dir"], "SEND")


class ProcNetParserTests(unittest.TestCase):
    def test_tcp_rows(self):
        rows = backend_linux.parse_proc_net(PROC_TCP, "TCP", v6=False)
        self.assertEqual(len(rows), 2)
        laddr, lport, raddr, rport, state, inode = rows[0]
        self.assertEqual(laddr, "127.0.0.1")
        self.assertEqual(lport, 0xE5F3)
        self.assertEqual(state, "LISTEN")
        self.assertEqual(inode, "12345")
        laddr, lport, raddr, rport, state, inode = rows[1]
        self.assertEqual(laddr, "172.16.0.5")
        self.assertEqual(raddr, "172.16.9.7")
        self.assertEqual(rport, 443)
        self.assertEqual(state, "ESTABLISHED")

    def test_gateway(self):
        gw = backend_linux.parse_route_gateway(PROC_ROUTE)
        self.assertEqual(gw, "172.16.0.1")


class BackendActionValidationTests(unittest.TestCase):
    """Actions build validated specs; helper calls are captured, not executed."""

    def setUp(self):
        self.b = backend_linux.LinuxBackend()
        self.sent = []
        b = self

        class FakeHelper:
            def is_alive(self_inner):
                return True

            def request(self_inner, op, args=None, timeout=30):
                b.sent.append((op, args))
                if op == "ufw":
                    return {"ok": True, "data": {"rc": 0, "out": "Rule added",
                                                 "err": ""}}
                if op == "status":
                    return {"ok": True, "data": {
                        "verbose": {"rc": 0, "out": UFW_VERBOSE, "err": ""},
                        "numbered": {"rc": 0, "out": UFW_NUMBERED, "err": ""}}}
                return {"ok": True, "data": {"rc": 0, "out": "", "err": ""}}
        self.b.helper = FakeHelper()

    def test_block_ip_prepends_tagged_pair(self):
        ok, _ = self.b.block_ip("203.0.113.7")
        self.assertTrue(ok)
        argvs = [a["argv"] for op, a in self.sent if op == "ufw"]
        self.assertEqual(argvs[0][:2], ["prepend", "deny"])
        self.assertIn("comment", argvs[0])
        self.assertIn("PFW Block 203.0.113.7", argvs[0])
        self.assertIn("out", argvs[1])

    def test_block_ip_rejects_garbage(self):
        with self.assertRaises(ValueError):
            self.b.block_ip("not-an-ip; rm -rf /")

    def test_add_port_rule(self):
        ok, _ = self.b.add_port_rule("deny", "8080", "tcp", "in")
        self.assertTrue(ok)
        argv = self.sent[-1][1]["argv"]
        self.assertEqual(argv[0], "deny")
        self.assertIn("8080/tcp", argv)

    def test_add_port_rule_out_direction(self):
        self.b.add_port_rule("allow", "443", None, "out")
        argv = self.sent[-1][1]["argv"]
        self.assertEqual(argv[:3], ["allow", "out", "443"])

    def test_add_port_rule_rejects_bad_spec(self):
        ok, msg = self.b.add_port_rule("allow", "80; rm -rf", "tcp", "in")
        self.assertFalse(ok)

    def test_remove_rule_only_ours(self):
        ok, msg = self.b.remove_rule("22/tcp ALLOW IN Anywhere")
        self.assertFalse(ok)
        self.assertIn("PFW", msg)

    def test_remove_rule_deletes_by_number(self):
        ok, msg = self.b.remove_rule("PFW Block 192.0.2.99")
        self.assertTrue(ok)
        deletes = [a["argv"] for op, a in self.sent if op == "ufw"]
        # numbers resolved from status; both halves of the pair deleted
        self.assertTrue(all(a[:2] == ["--force", "delete"] for a in deletes))

    def test_lockdown_keeps_dns_dhcp(self):
        self.b.set_lockdown(True)
        argvs = [a["argv"] for op, a in self.sent if op == "ufw"]
        self.assertIn(["allow", "out", "53", "comment", "PFW Core DNS"], argvs)
        self.assertIn(["default", "deny", "outgoing"], argvs)

    def test_capabilities_are_honest(self):
        caps = self.b.capabilities()
        self.assertFalse(caps["app_rules"])       # no per-binary match in ufw
        self.assertTrue(caps["port_rules"])
        self.assertFalse(caps["net_profiles"])
        self.assertTrue(caps["rules_shared"])


class RootHelperValidationTests(unittest.TestCase):
    def test_status_allowed(self):
        root_helper.validate_ufw_argv(["status", "verbose"])
        root_helper.validate_ufw_argv(["--force", "delete", "3"])
        root_helper.validate_ufw_argv(
            ["prepend", "deny", "from", "203.0.113.9", "comment",
             "PFW Block 203.0.113.9"])

    def test_firewall_off_verbs_forbidden(self):
        for argv in (["disable"], ["enable"], ["reset"], ["--force", "reset"],
                     ["reload"]):
            with self.assertRaises(ValueError, msg=str(argv)):
                root_helper.validate_ufw_argv(argv)

    def test_shell_metacharacters_rejected(self):
        for argv in (["allow", "80; rm -rf /"], ["allow", "$(id)"],
                     ["allow", "80|22"], ["allow", "-rf"]):
            with self.assertRaises(ValueError, msg=str(argv)):
                root_helper.validate_ufw_argv(argv)

    def test_force_only_with_delete(self):
        with self.assertRaises(ValueError):
            root_helper.validate_ufw_argv(["--force", "default", "deny"])

    def test_tail_path_whitelist(self):
        with self.assertRaises(ValueError):
            root_helper.op_tail({"path": "/etc/shadow", "offset": 0})

    def test_bad_comment_rejected(self):
        with self.assertRaises(ValueError):
            root_helper.validate_ufw_argv(["allow", "80", "comment",
                                           "x` touch /pwn `"])

    def test_unknown_op_reported(self):
        resp = root_helper.handle_line('{"id": 7, "op": "shell"}')
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["id"], 7)

    def test_bad_json_reported(self):
        resp = root_helper.handle_line("not json")
        self.assertFalse(resp["ok"])


if __name__ == "__main__":
    unittest.main()
