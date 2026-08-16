"""Windows-path tests at mock level (run on ANY OS, including Windows CI).

backend_windows must import cleanly everywhere (its WinDLL handles are lazy);
the PowerShell bridge is the seam we monkeypatch to assert on the exact
scripts the rules manager produces — the same commands the pre-port engine
issued, proving the move behind the interface changed nothing.
"""

import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "pfw"))

import backend_windows  # noqa: E402  — the import itself is test #1


class ImportTests(unittest.TestCase):
    def test_module_imports_without_windll(self):
        # Would have raised at import time before the port (module-level
        # ctypes.WinDLL). Lazy handles must not be loaded yet off-Windows.
        if os.name != "nt":
            self.assertIsNone(backend_windows._dlls)

    def test_structures_defined_everywhere(self):
        self.assertTrue(hasattr(backend_windows, "MIB_TCPROW_OWNER_PID"))
        self.assertTrue(hasattr(backend_windows, "MIB_IFROW"))


class PsScriptTests(unittest.TestCase):
    def setUp(self):
        self.scripts = []
        self._orig = backend_windows.run_ps

        def fake_run_ps(script, timeout=45):
            self.scripts.append(script)
            return 0, "", ""
        backend_windows.run_ps = fake_run_ps
        self.rm = backend_windows.RulesManager()

    def tearDown(self):
        backend_windows.run_ps = self._orig

    def test_block_ip(self):
        ok, _ = self.rm.block_ip("203.0.113.5")
        self.assertTrue(ok)
        s = self.scripts[-1]
        self.assertIn("New-NetFirewallRule", s)
        self.assertIn("'PFW Block 203.0.113.5'", s)
        self.assertIn("-Group 'PrivateFirewall'", s)
        self.assertIn("-Direction Outbound", s)
        self.assertIn("-Direction Inbound", s)

    def test_block_ip_ttl_names_expiry(self):
        self.rm.block_ip("203.0.113.5", ttl_minutes=60)
        self.assertIn("PFW AutoBlock 203.0.113.5 until ", self.scripts[-1])

    def test_block_ip_rejects_garbage(self):
        with self.assertRaises(ValueError):
            self.rm.block_ip("nope'; Remove-Item /")

    def test_rule_for_app_quotes_path(self):
        # use a file guaranteed to exist on the running OS
        path = sys.executable
        ok, _ = self.rm.rule_for_app(path, "Block")
        self.assertTrue(ok)
        self.assertIn("-Action Block", self.scripts[-1])
        self.assertIn("-Program '", self.scripts[-1])

    def test_rule_for_app_missing_file(self):
        ok, msg = self.rm.rule_for_app("/no/such/file", "Block")
        self.assertFalse(ok)
        self.assertEqual(self.scripts, [])

    def test_remove_rule_validates_name(self):
        ok, msg = self.rm.remove_rule("bad'; Remove-Item /")
        self.assertFalse(ok)
        self.assertEqual(self.scripts, [])
        ok, _ = self.rm.remove_rule("PFW Block 203.0.113.5")
        self.assertTrue(ok)
        self.assertIn("Remove-NetFirewallRule", self.scripts[-1])

    def test_lockdown_scripts(self):
        self.rm.set_lockdown(True)
        s = self.scripts[-1]
        self.assertIn("Dnscache", s)
        self.assertIn("Dhcp", s)
        self.assertIn("-DefaultOutboundAction Block", s)
        self.rm.set_lockdown(False)
        self.assertIn("-DefaultOutboundAction Allow", self.scripts[-1])

    def test_ipv6_toggle_scripts(self):
        self.rm.set_block_ipv6(True)
        self.assertIn("Disable-NetAdapterBinding", self.scripts[-1])
        self.rm.set_block_ipv6(False)
        self.assertIn("Enable-NetAdapterBinding", self.scripts[-1])


class StatusParseTests(unittest.TestCase):
    def test_query_status_mapping(self):
        orig = backend_windows.ps_json
        backend_windows.ps_json = lambda s, timeout=45: {
            "profiles": [{"Name": "Public", "Enabled": True,
                          "DefaultOutboundAction": "4",
                          "LogFileName": "C:/fw.log", "LogBlocked": True}],
            "connection": [{"InterfaceAlias": "Wi-Fi", "Name": "CafeNet",
                            "NetworkCategory": 0}],
            "rules": [{"name": "PFW Block 1.2.3.4", "enabled": "True",
                       "dir": "Inbound", "action": "Block",
                       "remote": "1.2.3.4", "program": None}],
            "ipv6": [{"Name": "Ethernet", "Enabled": False}],
            "dns": [{"Entry": "example.com", "Data": "93.184.216.34"}],
            "gateway": ["172.16.0.1"],
            "neighbors": [{"IPAddress": "172.16.0.1",
                           "LinkLayerAddress": "aa-bb-cc-dd-ee-ff"}],
        }
        try:
            rm = backend_windows.RulesManager()
            st = rm.query_status()
        finally:
            backend_windows.ps_json = orig
        self.assertTrue(st["lockdown"])
        self.assertTrue(st["ipv6_blocked"])
        self.assertTrue(st["log_blocked"])
        self.assertEqual(st["connection"][0]["category"], "Public")
        self.assertEqual(st["gateway"], "172.16.0.1")
        self.assertEqual(st["dns_names"]["93.184.216.34"], "example.com")
        self.assertTrue(st["rules"][0]["ours"])
        self.assertEqual(st["error"], "")

    def test_query_status_failure(self):
        orig = backend_windows.ps_json
        backend_windows.ps_json = lambda s, timeout=45: None
        try:
            st = backend_windows.RulesManager().query_status()
        finally:
            backend_windows.ps_json = orig
        self.assertEqual(st["error"], "status query failed")


class DropLogTests(unittest.TestCase):
    def test_tailer_parses_drops(self):
        import tempfile
        line = ("2026-08-16 10:00:00 DROP TCP 203.0.113.9 198.51.100.2 "
                "54321 445 60 S 123 0 8192 - - - RECEIVE\n")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(line * 3)
            path = f.name
        try:
            t = backend_windows.FwLogTailer()
            t.primed = True                     # read from byte 0
            drops = t.read_new(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(drops), 3)
        self.assertEqual(drops[0]["src"], "203.0.113.9")
        self.assertEqual(drops[0]["dport"], "445")
        self.assertEqual(drops[0]["dir"], "RECEIVE")


if __name__ == "__main__":
    unittest.main()
