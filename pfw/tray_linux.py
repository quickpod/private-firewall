"""System-tray icon for PrivateFirewall on Linux.

Uses pystray + Pillow when available (quickopen-runtime vendors pystray;
python3-pil comes from the deb dependency).  If either is missing, or the
desktop offers no usable tray protocol, server.main() catches the exception
and serves headless — the dashboard is the product, the tray is a convenience.

Menu mirrors the Windows tray: Open Dashboard · Lockdown toggle ·
Mute alert popups · Open logs folder · Exit.  Alert popups use
``notify-send`` (libnotify) when present, matching the Windows balloons.
"""

import shutil
import subprocess
import threading
import time

import pystray                     # noqa: F401 — ImportError -> headless
from PIL import Image, ImageDraw

ACCENT = (194, 65, 12, 255)        # PrivateFirewall accent #c2410c
WARN = (207, 45, 58, 255)


def _icon_image(warning=False):
    """Draw the shield line-art at 64px (theme-neutral, like the app icon)."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = WARN if warning else ACCENT
    d.polygon([(32, 6), (12, 15), (12, 32), (32, 58), (52, 32), (52, 15)],
              outline=color, width=4)
    d.line([(22, 32), (30, 40), (44, 24)], fill=color, width=4)
    return img


class LinuxTray:
    def __init__(self, state, url, log_dir, open_external, config_path):
        self.state = state
        self.url = url
        self.log_dir = log_dir
        self.open_external = open_external
        self.config_path = config_path
        self.muted = False
        self.last_alert_id = 0
        self.icon = None
        self._warn = False

    # -- notifications ------------------------------------------------------
    def _notify(self, title, body):
        ns = shutil.which("notify-send")
        if ns:
            subprocess.Popen([ns, "-a", "PrivateFirewall", "-i", "security-high",
                              title, body],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)

    def _watch(self):
        while True:
            time.sleep(3)
            s = self.state
            with s.lock:
                alerts = list(s.alerts)
            crit = any(a["severity"] in ("critical", "serious") for a in alerts)
            if crit != self._warn and self.icon is not None:
                self._warn = crit
                self.icon.icon = _icon_image(crit)
            newest = [a for a in alerts if a["id"] > self.last_alert_id]
            if alerts:
                self.last_alert_id = max(a["id"] for a in alerts)
            if self.muted:
                continue
            # muted-by-default policy: State.should_notify is the one gate
            new_notify = [a for a in newest if s.should_notify(a)]
            if new_notify:
                a = new_notify[-1]
                self._notify(a["title"], a["detail"])

    # -- menu actions --------------------------------------------------------
    def _lockdown_label(self, _item=None):
        with self.state.lock:
            on = self.state.fw.get("lockdown", False)
        return "Disable lockdown" if on else "Enable lockdown (zero-trust)"

    def _toggle_lockdown(self):
        with self.state.lock:
            enable = not self.state.fw.get("lockdown", False)
        def _do():
            ok, msg = self.state.backend.set_lockdown(enable)
            self.state.refresh_fw()
            self.state._emit_event(
                "action", f"tray lockdown {'ON' if enable else 'OFF'} ok={ok}")
            self._notify("PrivateFirewall lockdown",
                         ("Outbound default-deny is ON. Allow apps from the "
                          "dashboard." if enable else
                          "Lockdown disabled; outbound set to Allow.")
                         if ok else f"Lockdown change failed: {msg}")
        threading.Thread(target=_do, daemon=True).start()

    def _menu(self):
        return pystray.Menu(
            pystray.MenuItem("Open Dashboard",
                             lambda: self.open_external(self.url), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self._lockdown_label, self._toggle_lockdown,
                             enabled=lambda _i: self.state.backend.is_admin()),
            pystray.MenuItem("Mute alert popups",
                             self._toggle_mute,
                             checked=lambda _i: self.muted),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open logs folder",
                             lambda: self.open_external(self.log_dir)),
            pystray.MenuItem("Edit settings file",
                             lambda: self.open_external(self.config_path)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit PrivateFirewall", self._exit),
        )

    def _toggle_mute(self):
        self.muted = not self.muted

    def _exit(self):
        if self.icon is not None:
            self.icon.stop()

    def run(self):
        self.icon = pystray.Icon("private-firewall", _icon_image(False),
                                 "PrivateFirewall", self._menu())
        threading.Thread(target=self._watch, daemon=True).start()
        self.icon.run()          # blocks; raises if no tray protocol available


def run_tray(state, url, log_dir, open_external, config_path=""):
    LinuxTray(state, url, log_dir, open_external, config_path).run()
