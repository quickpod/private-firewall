"""System-tray icon for PrivateFirewall on Linux (Plasma StatusNotifier).

pystray's appindicator backend needs the AyatanaAppIndicator3 GIR typelib —
the deb Depends carries it (gir1.2-ayatanaappindicator3-0.1 + gir1.2-gtk-3.0,
mapped from the `pystray` requirements line), so a bare Quick OS 0.1.11 plus
this package is enough.  If the stack still is not there (headless session,
stripped install), server.main() catches the failure and serves headless — the
dashboard is the product, the tray is the handle to reach it.

Icon style matches the suite's tray rule (securevault/infra-monitor): the app
mark, painted over whatever the shell renders behind it (NOT theme-swapped),
with a state dot bottom-right:

    green  — protection active  (the system firewall is enforcing)
    red    — protection DISABLED (ufw inactive — nothing is enforced)

Menu (callbacks arrive on pystray's own thread; everything they touch is
thread-safe State methods): Open Dashboard · notifications on/off · Quit.
"""

import os
import sys
import threading
import time

import pystray                     # ImportError/ValueError -> headless caller
from PIL import Image, ImageDraw

ACCENT = "#c2410c"                 # PrivateFirewall accent
DOT_ACTIVE = "#31b558"             # protection active (suite green)
DOT_OFF = "#cf2d3a"                # firewall inactive — attention


def _asset(name):
    here = os.path.dirname(os.path.abspath(__file__))
    for r in (here, os.path.dirname(here)):
        p = os.path.join(r, name)
        if os.path.exists(p):
            return p
    return None


def _icon_image(active=True):
    """App mark + state dot. Falls back to drawn shield line-art if the png
    is missing — the tray must never fail over a cosmetic asset."""
    size = 64
    img = None
    png = _asset("private-firewall.png")
    if png:
        try:
            img = Image.open(png).convert("RGBA").resize((size, size))
        except Exception:
            img = None
    if img is None:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.polygon([(32, 4), (10, 13), (10, 32), (32, 60), (54, 32), (54, 13)],
                  outline=ACCENT, width=5)
        d.line([(21, 31), (29, 39), (45, 22)], fill=ACCENT, width=5)
    d = ImageDraw.Draw(img)
    colour = DOT_ACTIVE if active else DOT_OFF
    d.ellipse((size - 26, size - 26, size - 4, size - 4), fill=colour,
              outline="#ffffff", width=2)
    return img


class LinuxTray:
    def __init__(self, state, url, log_dir, open_external, config_path):
        self.state = state
        self.url = url
        self.open_external = open_external
        self.icon = None
        self._active = True

    # -- live state ----------------------------------------------------------
    def _fw_active(self):
        with self.state.lock:
            return self.state.fw.get("fw_active", True)

    def _notif_on(self):
        return bool(self.state.config.get("notifications", {})
                    .get("enabled", False))

    def _status_caption(self, _item=None):
        return ("Protection active" if self._active
                else "Protection DISABLED (firewall off)")

    def _tooltip(self):
        return ("Private Firewall — protection active" if self._active
                else "Private Firewall — firewall INACTIVE")

    def _watch(self):
        """Keep the icon/tooltip reflecting the firewall state."""
        while self.icon is not None:
            time.sleep(4)
            active = self._fw_active()
            if active != self._active and self.icon is not None:
                self._active = active
                try:
                    self.icon.icon = _icon_image(active)
                    self.icon.title = self._tooltip()
                    self.icon.update_menu()
                except Exception:
                    pass

    # -- menu actions --------------------------------------------------------
    def _open(self, *_a):
        self.open_external(self.url)

    def _notif_label(self, _item=None):
        return ("Disable notifications" if self._notif_on()
                else "Enable notifications")

    def _toggle_notifications(self, *_a):
        def _do():
            cfg = dict(self.state.config)
            notif = dict(cfg.get("notifications", {}))
            notif["enabled"] = not notif.get("enabled", False)
            cfg["notifications"] = notif
            self.state.save_config(cfg)          # validates + persists
            self.state._emit_event(
                "action",
                f"notifications {'ON' if notif['enabled'] else 'OFF'} (tray)")
            try:
                self.icon.update_menu()
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _quit(self, *_a):
        icon = self.icon
        self.icon = None
        try:
            icon.stop()
        except Exception:
            os._exit(0)

    def run(self):
        self._active = self._fw_active()
        self.icon = pystray.Icon(
            "private-firewall", _icon_image(self._active), self._tooltip(),
            menu=pystray.Menu(
                pystray.MenuItem("Open Dashboard", self._open, default=True),
                pystray.MenuItem(self._status_caption, None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(self._notif_label, self._toggle_notifications),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit Private Firewall", self._quit),
            ))
        threading.Thread(target=self._watch, daemon=True).start()
        self.icon.run()        # blocks until Quit; raises if no tray protocol


def run_tray(state, url, log_dir, open_external, config_path=""):
    LinuxTray(state, url, log_dir, open_external, config_path).run()
