"""Alert classification + copy tests (the fe80/port-0 field defect).

Benign local-network chatter (link-local NDP/RA, multicast, ICMPv6/IGMP) must
never be presented as attack attempts; "port 0" must never appear in
user-facing text; alert copy must describe the origin in plain language.
Platform-neutral: runs everywhere, including Windows CI.
"""

import os
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "pfw"))

os.environ.setdefault("PFW_LOG_DIR",
                      os.path.join(tempfile.mkdtemp(prefix="pfw-test-"), "logs"))
os.environ["PFW_NO_SINGLETON"] = "1"
os.environ["PFW_NO_ELEVATE"] = "1"

import server  # noqa: E402
from test_backend_interface import FakeBackend  # noqa: E402


def drop(src, dport="445", proto="TCP", dst="198.51.100.2", dir_="RECEIVE"):
    return {"ts": "x", "proto": proto, "src": src, "dst": dst,
            "sport": "1234", "dport": dport, "dir": dir_}


class BackgroundClassificationTests(unittest.TestCase):
    def test_link_local_v6_is_background(self):
        self.assertTrue(server.is_background_drop(
            drop("fe80::b481:43ff:fe10:603d", dport="0", proto="58")))

    def test_link_local_v4_is_background(self):
        self.assertTrue(server.is_background_drop(drop("169.254.7.9")))

    def test_multicast_dst_is_background(self):
        self.assertTrue(server.is_background_drop(
            drop("192.168.1.20", dst="ff02::1")))
        self.assertTrue(server.is_background_drop(
            drop("192.168.1.20", dst="239.255.255.250")))

    def test_icmpv6_igmp_are_background(self):
        self.assertTrue(server.is_background_drop(
            drop("203.0.113.9", proto="ICMPv6")))
        self.assertTrue(server.is_background_drop(
            drop("203.0.113.9", proto="2")))

    def test_routable_tcp_is_not_background(self):
        self.assertFalse(server.is_background_drop(drop("93.184.216.34")))

    def test_proto_names_never_port_zero(self):
        self.assertEqual(server.proto_name("58"), "ICMPv6")
        self.assertEqual(server.proto_name("2"), "IGMP")
        self.assertEqual(server.proto_name("44"), "fragment")
        self.assertEqual(server.proto_name("tcp"), "TCP")
        self.assertEqual(server.proto_name("ICMPv6"), "ICMPv6")

    def test_mac_from_eui64(self):
        # fe80::b481:43ff:fe10:603d -> EUI-64 with ff:fe -> b6:81:43:10:60:3d
        self.assertEqual(server.mac_from_eui64("fe80::b481:43ff:fe10:603d"),
                         "b6:81:43:10:60:3d")
        self.assertEqual(server.mac_from_eui64("fe80::1"), "")
        self.assertEqual(server.mac_from_eui64("192.168.1.1"), "")


class AlertGatingTests(unittest.TestCase):
    def setUp(self):
        self.st = server.State(backend=FakeBackend())
        self.st.refresh_fw()
        self.eng = self.st.alert_engine

    def test_ndp_chatter_never_alerts(self):
        # the exact field case: link-local ICMPv6 logged with port 0
        chatter = [drop("fe80::b481:43ff:fe10:603d", dport="0", proto="58")
                   for _ in range(50)]
        self.eng.feed_drops(chatter)
        self.assertEqual(list(self.st.alerts), [])

    def test_port_zero_never_alerts_even_routable(self):
        self.eng.feed_drops([drop("93.184.216.34", dport="0", proto="TCP")
                             for _ in range(50)])
        self.assertEqual(list(self.st.alerts), [])

    def test_short_burst_does_not_trip_bruteforce(self):
        # 20 hits within the same instant: volume alone must not alarm
        self.eng.feed_drops([drop("93.184.216.34") for _ in range(20)])
        self.assertFalse([a for a in self.st.alerts
                          if a["rule"] == "brute-force"])

    def test_sustained_routable_attempts_do_alert(self):
        import time as _t
        base = _t.time()
        seq = [drop("93.184.216.34") for _ in range(20)]
        # simulate a spread of >60s by rewriting the recorded hit times
        self.eng.feed_drops(seq[:10])
        key = ("93.184.216.34", "445")
        self.eng.brute[key] = type(self.eng.brute[key])(
            (base - 120 + i for i in range(10)), maxlen=200)
        self.eng.feed_drops(seq[10:])
        alerts = [a for a in self.st.alerts if a["rule"] == "brute-force"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("an internet address (93.184.216.34)", alerts[0]["title"])
        self.assertNotIn("port 0", alerts[0]["detail"])

    def test_describe_source_router(self):
        self.assertIn("your router",
                      self.eng.describe_source("10.0.0.1"))   # fake gateway

    def test_describe_source_lan_device_with_mac(self):
        txt = self.eng.describe_source("fe80::b481:43ff:fe10:603d")
        self.assertIn("local network", txt)
        self.assertIn("b6:81:43:10:60:3d", txt)

    def test_poll_event_text_uses_protocol_names(self):
        d = drop("fe80::1%eth0", dport="0", proto="58")
        d["proto"] = server.proto_name(d["proto"])
        d["bg"] = server.is_background_drop(d)
        self.assertTrue(d["bg"])
        self.assertEqual(d["proto"], "ICMPv6")


class MutedByDefaultTests(unittest.TestCase):
    """Owner policy: notifications are opt-in; enforcement/logging always on."""

    def setUp(self):
        self.st = server.State(backend=FakeBackend())

    def alert(self, severity="critical", origin="internet"):
        return {"id": 1, "severity": severity, "origin": origin,
                "rule": "x", "title": "t", "detail": "d"}

    def test_fresh_config_is_muted(self):
        self.assertFalse(self.st.config["notifications"]["enabled"])
        self.assertFalse(self.st.should_notify(self.alert("critical")))

    def test_upgraded_config_without_flag_stays_muted(self):
        import config as cfgmod
        merged = cfgmod._deep_merge(cfgmod.DEFAULT_CONFIG,
                                    {"notifications": {"balloons": True,
                                                       "min_severity": "warning"}})
        self.assertFalse(merged["notifications"]["enabled"])

    def test_alerts_still_recorded_while_muted(self):
        self.st._emit_alert("critical", "port-scan", "t", "d", "internet")
        self.assertEqual(len(self.st.alerts), 1)

    def test_enabled_conservative_defaults(self):
        self.st.config["notifications"]["enabled"] = True
        self.assertTrue(self.st.should_notify(self.alert("serious")))
        self.assertTrue(self.st.should_notify(self.alert("critical")))
        # essential-only: warnings stay quiet by default
        self.assertFalse(self.st.should_notify(self.alert("warning")))
        # local-network origins stay quiet by default
        self.assertFalse(self.st.should_notify(
            self.alert("critical", origin="local")))

    def test_local_category_opt_in(self):
        self.st.config["notifications"]["enabled"] = True
        self.st.config["notifications"]["categories"]["local"] = True
        self.assertTrue(self.st.should_notify(
            self.alert("critical", origin="local")))

    def test_state_json_reports_notify_state(self):
        import json
        d = json.loads(self.st.to_json())
        self.assertFalse(d["notify"]["enabled"])


if __name__ == "__main__":
    unittest.main()
