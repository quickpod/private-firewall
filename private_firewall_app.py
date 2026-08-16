#!/usr/bin/env python3
r"""PrivateFirewall entry point (this is what gets built into PrivateFirewall.exe).

Launches the monitoring engine with the system-tray icon and opens the local
dashboard. The engine binds only to 127.0.0.1 and is token-authed; nothing is
exposed off the machine. Firewall mutations require elevation (the built exe
requests admin via its manifest).
"""
import os
import sys

# Single-instance marker: the installer's AppMutex checks this to warn the
# user to close the app before install/uninstall. Harmless off Windows.
if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.CreateMutexW(None, False, "QuickOpen.PrivateFirewall")
    except Exception:
        pass


# The pfw modules use flat imports (import config, import tray); put pfw on path.
if getattr(sys, "frozen", False):
    sys.path.insert(0, sys._MEIPASS)  # PyInstaller-bundled modules + dashboard.html
else:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "pfw"))

import server  # noqa: E402  (resolved via the path insert / bundled modules)


def main():
    # Default to tray + open-dashboard when launched with no explicit flags.
    # --no-open (the start-at-login entry) keeps it tray-only: no window at
    # login — the OS firewall enforces from boot either way, the app is the
    # monitoring surface.
    if "--tray" not in sys.argv:
        sys.argv.append("--tray")
    if "--open" not in sys.argv and "--no-open" not in sys.argv:
        sys.argv.append("--open")
    return server.main()


if __name__ == "__main__":
    sys.exit(main() or 0)
