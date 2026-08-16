"""Live ufw tests — OPT-IN, safe-by-construction.

Skipped unless PFW_LIVE_UFW=1 (and Linux + root access via PFW_HELPER_CMD or
euid 0).  Designed for the dev box / validation VM:

  * NEVER touches ufw enable/disable/reset or the default policies (the
    default-policy "lockdown" path is exercised only on the validation VM by
    hand, with an immediate revert — not here).
  * Only adds PFW-tagged rules, and removes every one of them again.
  * Snapshots `ufw status numbered` before and asserts the non-PFW rule set is
    byte-identical after, and that an SSH allow (22/tcp) present before is
    still present after — the lockout guard.

Run:  PFW_LIVE_UFW=1 PFW_HELPER_CMD="sudo -n" python3 -m unittest tests.test_ufw_live -v
"""

import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "pfw"))

LIVE = (os.environ.get("PFW_LIVE_UFW") == "1"
        and sys.platform.startswith("linux"))


@unittest.skipUnless(LIVE, "live ufw test (PFW_LIVE_UFW=1, Linux only)")
class LiveUfwTests(unittest.TestCase):
    TEST_IP = "192.0.2.123"          # RFC 5737 TEST-NET — never routable
    TEST_PORT = "58798"

    @classmethod
    def setUpClass(cls):
        import backend_linux
        cls.b = backend_linux.LinuxBackend()
        ok, msg = cls.b.elevate()
        if not ok:
            raise unittest.SkipTest(f"no root helper: {msg}")
        cls.before = cls._snapshot(cls.b)
        if not cls.before["active"]:
            raise unittest.SkipTest("ufw inactive on this host — not testing")

    @staticmethod
    def _snapshot(b):
        import backend_linux
        resp = b.helper.request("status", {}, timeout=45)
        assert resp.get("ok"), resp
        return backend_linux.parse_ufw_status(
            resp["data"]["verbose"]["out"], resp["data"]["numbered"]["out"])

    @classmethod
    def tearDownClass(cls):
        # belt & braces: remove any leftover test rules, then verify state
        for name in (f"PFW Block {cls.TEST_IP}",
                     f"PFW Allow {cls.TEST_PORT}/tcp in"):
            cls.b.remove_rule(name)
        after = cls._snapshot(cls.b)
        base = [(r["to"], r["from"], r["action"], r["dir"])
                for r in cls.before["rules"] if not r["ours"]]
        now = [(r["to"], r["from"], r["action"], r["dir"])
               for r in after["rules"] if not r["ours"]]
        assert base == now, "non-PFW ufw rules changed during tests!"
        assert after["active"], "ufw no longer active!"
        assert after["default_incoming"] == cls.before["default_incoming"], \
            "default incoming policy changed!"
        # SSH lockout guard
        ssh_before = any(r["to"].startswith("22/tcp") and r["action"] == "Allow"
                         for r in cls.before["rules"])
        ssh_after = any(r["to"].startswith("22/tcp") and r["action"] == "Allow"
                        for r in after["rules"])
        assert ssh_after or not ssh_before, "SSH allow rule disappeared!"
        cls.b.shutdown()

    def test_1_block_ip_roundtrip(self):
        ok, msg = self.b.block_ip(self.TEST_IP)
        self.assertTrue(ok, msg)
        st = self._snapshot(self.b)
        mine = [r for r in st["rules"]
                if r["name"] == f"PFW Block {self.TEST_IP}"]
        self.assertEqual(len(mine), 2)          # in + out
        # prepended: our block outranks the allows
        self.assertEqual(min(r["number"] for r in mine), 1)
        ok, msg = self.b.remove_rule(f"PFW Block {self.TEST_IP}")
        self.assertTrue(ok, msg)
        st = self._snapshot(self.b)
        self.assertFalse([r for r in st["rules"]
                          if r["name"] == f"PFW Block {self.TEST_IP}"])

    def test_2_port_rule_roundtrip(self):
        name = f"PFW Allow {self.TEST_PORT}/tcp in"
        ok, msg = self.b.add_port_rule("allow", self.TEST_PORT, "tcp", "in")
        self.assertTrue(ok, msg)
        st = self._snapshot(self.b)
        self.assertTrue([r for r in st["rules"] if r["name"] == name])
        ok, msg = self.b.remove_rule(name)
        self.assertTrue(ok, msg)
        st = self._snapshot(self.b)
        self.assertFalse([r for r in st["rules"] if r["name"] == name])

    def test_3_system_rules_are_protected(self):
        sysrule = next((r for r in self.before["rules"] if not r["ours"]), None)
        if sysrule is None:
            self.skipTest("no system rules on this host")
        ok, msg = self.b.remove_rule(sysrule["name"])
        self.assertFalse(ok)

    def test_4_helper_refuses_disable(self):
        resp = self.b.helper.request("ufw", {"argv": ["disable"]})
        self.assertFalse(resp.get("ok"))

    def test_5_status_reports_active(self):
        st = self.b.refresh_status()
        self.assertTrue(st["fw_active"])
        self.assertEqual(st["error"], "")


if __name__ == "__main__":
    unittest.main()
