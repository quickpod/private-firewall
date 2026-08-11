"""Editable configuration profile for PrivateFirewall.

Lives at %ProgramData%\\PrivateFirewall\\config.json. On first run the default
below is written out; the user (or the dashboard Settings panel) can edit it and
the engine hot-reloads it. Unknown/missing keys are filled from the default via a
deep merge, so an old or partial file keeps working after upgrades.

The defaults are tuned for a laptop that travels: it watches for scans and
intrusions, auto-blocks scanners for an hour, and tightens up automatically on
untrusted (Public) Wi-Fi.
"""

import copy
import json
import os

SEVERITIES = ("info", "warning", "serious", "critical")

DEFAULT_CONFIG = {
    "poll_secs": 2,

    # --- detection thresholds + which alerts are active ---------------------
    "alerts": {
        "portscan":       {"enabled": True, "ports": 8,  "window_secs": 60},
        "bruteforce":     {"enabled": True, "hits": 15,  "window_secs": 300},
        "fanout":         {"enabled": True, "ips": 30,   "window_secs": 300},
        "upload_surge":   {"enabled": True, "mbps": 4.0, "window_secs": 60},
        "new_listener":   {"enabled": True},
        "plaintext_dns":  {"enabled": True},
        "suspicious_path":{"enabled": True},
        "arp_spoof":      {"enabled": True},
    },

    # --- active defense: auto-block attackers, with an expiry ---------------
    "auto_block": {
        "on_portscan":   True,
        "on_bruteforce": False,
        "ttl_minutes":   60,
    },

    # --- desktop notifications (tray balloons) -----------------------------
    "notifications": {
        "balloons": True,
        "min_severity": "warning",     # info | warning | serious | critical
    },

    # --- per network-location behaviour; applied automatically on change ----
    # A travelling laptop is stricter on untrusted networks. These override the
    # base auto-block / notification level while connected to that category.
    "auto_apply_network_profile": True,
    "network_profiles": {
        "Public":  {"auto_block": True,  "min_severity": "warning",
                    "note": "Untrusted (hotel/cafe/airport). Be strict."},
        "Private": {"auto_block": True,  "min_severity": "warning",
                    "note": "Home / trusted LAN."},
        "Domain":  {"auto_block": False, "min_severity": "serious",
                    "note": "Managed corporate network."},
    },

    # --- allow/deny lists ---------------------------------------------------
    # Trusted IPs are never alerted on or auto-blocked (loopback + your gateway
    # style hosts). Add your home subnet if you like, e.g. "192.168.1.0/24".
    "trusted_ips": ["127.0.0.1", "::1"],

    # --- extra features -----------------------------------------------------
    "features": {
        "dns_names": True,     # annotate connections with resolved hostnames
        "arp_spoof": True,     # watch the gateway MAC for MITM on public Wi-Fi
    },
}


def _deep_merge(base, override):
    """Return base deep-merged with override (override wins for scalars)."""
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path):
    """Load config.json merged over the defaults. Writes the default file if it
    doesn't exist yet. Never raises on a bad file — falls back to defaults."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            user = json.load(f)
        return _deep_merge(DEFAULT_CONFIG, user)
    except FileNotFoundError:
        save_config(path, DEFAULT_CONFIG)
        return copy.deepcopy(DEFAULT_CONFIG)
    except (ValueError, OSError):
        return copy.deepcopy(DEFAULT_CONFIG)


def save_config(path, cfg):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def validate(cfg):
    """Validate + coerce a candidate config (from the dashboard editor). Returns
    (ok, cleaned_or_none, error_message). Merged over defaults so partial edits
    are fine; only type/range errors are rejected."""
    if not isinstance(cfg, dict):
        return False, None, "config must be a JSON object"
    merged = _deep_merge(DEFAULT_CONFIG, cfg)
    try:
        ps = float(merged["poll_secs"])
        if not 0.5 <= ps <= 60:
            return False, None, "poll_secs must be between 0.5 and 60"
        merged["poll_secs"] = ps
        for name, a in merged["alerts"].items():
            if "enabled" in a:
                a["enabled"] = bool(a["enabled"])
            for numeric in ("ports", "hits", "ips", "window_secs"):
                if numeric in a:
                    a[numeric] = int(a[numeric])
            if "mbps" in a:
                a["mbps"] = float(a["mbps"])
        ab = merged["auto_block"]
        ab["on_portscan"] = bool(ab["on_portscan"])
        ab["on_bruteforce"] = bool(ab["on_bruteforce"])
        ab["ttl_minutes"] = max(1, int(ab["ttl_minutes"]))
        if merged["notifications"]["min_severity"] not in SEVERITIES:
            return False, None, "notifications.min_severity must be one of " \
                                + "/".join(SEVERITIES)
        merged["notifications"]["balloons"] = bool(merged["notifications"]["balloons"])
        for pname, prof in merged["network_profiles"].items():
            if prof.get("min_severity", "warning") not in SEVERITIES:
                return False, None, f"network_profiles.{pname}.min_severity invalid"
            prof["auto_block"] = bool(prof.get("auto_block", True))
        if not isinstance(merged["trusted_ips"], list):
            return False, None, "trusted_ips must be a list"
    except (KeyError, ValueError, TypeError) as e:
        return False, None, f"invalid config: {e}"
    return True, merged, ""


def sev_rank(sev):
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0
