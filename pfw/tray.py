"""System-tray icon for PrivateFirewall — pure ctypes, no dependencies.

Runs in-process with the engine on the main thread (owns the Win32 message
loop) while the HTTP server runs on a background thread. Because it shares the
process it reads live State directly for the tooltip / icon / balloon alerts and
can toggle lockdown without a second token exchange.

Right-click menu: Open Dashboard · Lockdown toggle · Mute alert popups ·
Open logs folder · Copy dashboard link · Exit. Double-click opens the dashboard.
The icon turns to a warning glyph and raises a balloon when a critical/serious
alert fires (unless muted). Re-adds itself if Explorer restarts.
"""

import ctypes
import threading
import time
from ctypes import (POINTER, Structure, byref, c_int, c_long, c_size_t,
                    c_ssize_t, c_uint, c_ushort, c_void_p, c_wchar, c_wchar_p,
                    sizeof, WINFUNCTYPE)

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# --- message / flag constants ---------------------------------------------
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_DESTROY = 0x0002
WM_TIMER = 0x0113
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B
SW_HIDE = 0

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NIIF_INFO, NIIF_WARNING, NIIF_ERROR = 0x01, 0x02, 0x03

IDI_APPLICATION = 32512
IDI_WARNING = 32515
IDI_SHIELD = 32518

MF_STRING, MF_SEPARATOR, MF_CHECKED, MF_GRAYED = 0x0000, 0x0800, 0x0008, 0x0001
TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY = 0x0002, 0x0100, 0x0080

(ID_OPEN, ID_LOCKDOWN, ID_IPV6, ID_MUTE, ID_LOGS, ID_COPY,
 ID_EDITCFG, ID_RELOAD, ID_EXIT) = 1, 2, 3, 4, 5, 6, 7, 8, 9

WNDPROC = WINFUNCTYPE(c_ssize_t, c_void_p, c_uint, c_size_t, c_ssize_t)


class GUID(Structure):
    _fields_ = [("b", ctypes.c_ubyte * 16)]


class POINT(Structure):
    _fields_ = [("x", c_long), ("y", c_long)]


class MSG(Structure):
    _fields_ = [("hwnd", c_void_p), ("message", c_uint), ("wParam", c_size_t),
                ("lParam", c_ssize_t), ("time", c_uint), ("pt", POINT)]


class WNDCLASS(Structure):
    _fields_ = [("style", c_uint), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", c_int), ("cbWndExtra", c_int),
                ("hInstance", c_void_p), ("hIcon", c_void_p),
                ("hCursor", c_void_p), ("hbrBackground", c_void_p),
                ("lpszMenuName", c_wchar_p), ("lpszClassName", c_wchar_p)]


class NOTIFYICONDATAW(Structure):
    _fields_ = [
        ("cbSize", c_uint), ("hWnd", c_void_p), ("uID", c_uint),
        ("uFlags", c_uint), ("uCallbackMessage", c_uint), ("hIcon", c_void_p),
        ("szTip", c_wchar * 128), ("dwState", c_uint), ("dwStateMask", c_uint),
        ("szInfo", c_wchar * 256), ("uVersion", c_uint),
        ("szInfoTitle", c_wchar * 64), ("dwInfoFlags", c_uint),
        ("guidItem", GUID), ("hBalloonIcon", c_void_p)]


def _sig():
    user32.DefWindowProcW.restype = c_ssize_t
    user32.DefWindowProcW.argtypes = [c_void_p, c_uint, c_size_t, c_ssize_t]
    user32.CreateWindowExW.restype = c_void_p
    user32.CreateWindowExW.argtypes = [c_uint, c_wchar_p, c_wchar_p, c_uint,
        c_int, c_int, c_int, c_int, c_void_p, c_void_p, c_void_p, c_void_p]
    user32.RegisterClassW.restype = c_ushort
    user32.RegisterClassW.argtypes = [POINTER(WNDCLASS)]
    user32.LoadIconW.restype = c_void_p
    user32.LoadIconW.argtypes = [c_void_p, c_void_p]
    user32.CreatePopupMenu.restype = c_void_p
    user32.AppendMenuW.argtypes = [c_void_p, c_uint, c_size_t, c_wchar_p]
    user32.TrackPopupMenu.restype = c_int
    user32.TrackPopupMenu.argtypes = [c_void_p, c_uint, c_int, c_int, c_int,
                                      c_void_p, c_void_p]
    user32.SetMenuDefaultItem.argtypes = [c_void_p, c_uint, c_uint]
    user32.DestroyMenu.argtypes = [c_void_p]
    user32.SetForegroundWindow.argtypes = [c_void_p]
    user32.GetCursorPos.argtypes = [POINTER(POINT)]
    user32.SetTimer.argtypes = [c_void_p, c_size_t, c_uint, c_void_p]
    user32.GetMessageW.argtypes = [POINTER(MSG), c_void_p, c_uint, c_uint]
    user32.GetMessageW.restype = c_int
    user32.DispatchMessageW.argtypes = [POINTER(MSG)]
    user32.TranslateMessage.argtypes = [POINTER(MSG)]
    user32.RegisterWindowMessageW.restype = c_uint
    user32.RegisterWindowMessageW.argtypes = [c_wchar_p]
    user32.DestroyWindow.argtypes = [c_void_p]
    kernel32.GetModuleHandleW.restype = c_void_p
    kernel32.GetModuleHandleW.argtypes = [c_wchar_p]
    shell32.Shell_NotifyIconW.restype = c_int
    shell32.Shell_NotifyIconW.argtypes = [c_uint, POINTER(NOTIFYICONDATAW)]


class Tray:
    def __init__(self, state, url, log_dir, open_external, admin, config_path=""):
        self.state = state
        self.url = url
        self.log_dir = log_dir
        self.config_path = config_path
        self.open_external = open_external
        self.admin = admin
        self.muted = False
        self.hwnd = None
        self.nid = None
        self.last_alert_id = 0
        self.icon_warn = False
        self._wndproc = WNDPROC(self._on_message)   # keep ref alive (no GC)
        self._wm_taskbar = 0

    # -- icon helpers -------------------------------------------------------
    def _icon(self, warning):
        return user32.LoadIconW(None, c_void_p(IDI_WARNING if warning else IDI_SHIELD))

    def _add_icon(self):
        nid = NOTIFYICONDATAW()
        nid.cbSize = sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self._icon(False)
        nid.szTip = "PrivateFirewall"
        self.nid = nid
        return shell32.Shell_NotifyIconW(NIM_ADD, byref(nid))

    def _update(self, tip=None, icon_warn=None, info=None, info_title=None,
                info_flag=NIIF_WARNING):
        if self.nid is None:
            return
        nid = self.nid
        nid.uFlags = NIF_TIP
        if tip is not None:
            nid.szTip = tip[:127]
        if icon_warn is not None and icon_warn != self.icon_warn:
            nid.uFlags |= NIF_ICON
            nid.hIcon = self._icon(icon_warn)
            self.icon_warn = icon_warn
        if info is not None:
            nid.uFlags |= NIF_INFO
            nid.szInfo = info[:255]
            nid.szInfoTitle = (info_title or "PrivateFirewall")[:63]
            nid.dwInfoFlags = info_flag
        shell32.Shell_NotifyIconW(NIM_MODIFY, byref(nid))

    def _remove_icon(self):
        if self.nid is not None:
            shell32.Shell_NotifyIconW(NIM_DELETE, byref(self.nid))

    # -- periodic refresh (tooltip, icon, balloon on new alerts) ------------
    def _refresh(self):
        s = self.state
        with s.lock:
            conns = sum(1 for c in s.conns if c.get("state") == "ESTABLISHED")
            alerts = list(s.alerts)
            lockdown = s.rules.lockdown
        crit = [a for a in alerts if a["severity"] in ("critical", "serious")]
        tip = (f"PrivateFirewall\n{conns} active · {len(alerts)} alerts"
               f"{' · LOCKDOWN' if lockdown else ''}")
        newest = [a for a in alerts if a["id"] > self.last_alert_id]
        if alerts:
            self.last_alert_id = max(a["id"] for a in alerts)
        # balloon gating from the editable profile: on/off + minimum severity
        order = ("info", "warning", "serious", "critical")
        notif = self.state.config.get("notifications", {})
        balloons_on = notif.get("balloons", True)
        try:
            min_rank = order.index(self.state.effective_min_severity())
        except (ValueError, AttributeError):
            min_rank = 1
        def _rank(s):
            return order.index(s) if s in order else 0
        new_notify = [a for a in newest if _rank(a["severity"]) >= min_rank]
        if new_notify and balloons_on and not self.muted:
            a = new_notify[-1]
            self._update(tip=tip, icon_warn=True, info=a["detail"],
                         info_title=f"⚠ {a['title']}",
                         info_flag=NIIF_ERROR if a["severity"] == "critical"
                         else NIIF_WARNING)
        else:
            self._update(tip=tip, icon_warn=bool(crit))

    # -- menu ---------------------------------------------------------------
    def _show_menu(self):
        s = self.state
        with s.lock:
            lockdown = s.rules.lockdown
            ipv6_blocked = s.rules.ipv6_blocked
        hmenu = user32.CreatePopupMenu()
        user32.AppendMenuW(hmenu, MF_STRING, ID_OPEN, "Open Dashboard")
        user32.SetMenuDefaultItem(hmenu, ID_OPEN, 0)
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        lock_flags = MF_STRING | (0 if self.admin else MF_GRAYED)
        user32.AppendMenuW(hmenu, lock_flags, ID_LOCKDOWN,
                           "Disable lockdown" if lockdown else "Enable lockdown (zero-trust)")
        ipv6_flags = MF_STRING | (0 if self.admin else MF_GRAYED) | \
            (MF_CHECKED if ipv6_blocked else 0)
        user32.AppendMenuW(hmenu, ipv6_flags, ID_IPV6, "Block all IPv6")
        user32.AppendMenuW(hmenu, MF_STRING | (MF_CHECKED if self.muted else 0),
                           ID_MUTE, "Mute alert popups")
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(hmenu, MF_STRING, ID_EDITCFG, "Edit settings file")
        user32.AppendMenuW(hmenu, MF_STRING, ID_RELOAD, "Reload settings")
        user32.AppendMenuW(hmenu, MF_STRING, ID_LOGS, "Open logs folder")
        user32.AppendMenuW(hmenu, MF_STRING, ID_COPY, "Copy dashboard link")
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(hmenu, MF_STRING, ID_EXIT, "Exit PrivateFirewall")

        pt = POINT()
        user32.GetCursorPos(byref(pt))
        user32.SetForegroundWindow(self.hwnd)   # so the menu dismisses on click-away
        cmd = user32.TrackPopupMenu(
            hmenu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
            pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(hmenu)
        if cmd:
            self._on_command(cmd)

    def _on_command(self, cmd):
        if cmd == ID_OPEN:
            self.open_external(self.url)
        elif cmd == ID_LOGS:
            self.open_external(self.log_dir)
        elif cmd == ID_EDITCFG:
            self.open_external(self.config_path)
        elif cmd == ID_RELOAD:
            threading.Thread(target=self.state.reload_config, daemon=True).start()
        elif cmd == ID_COPY:
            self._copy(self.url)
        elif cmd == ID_MUTE:
            self.muted = not self.muted
        elif cmd == ID_LOCKDOWN and self.admin:
            with self.state.lock:
                enable = not self.state.rules.lockdown
            # blocking PowerShell call — off the UI thread
            threading.Thread(target=self._toggle_lockdown, args=(enable,),
                             daemon=True).start()
        elif cmd == ID_IPV6 and self.admin:
            with self.state.lock:
                enable = not self.state.rules.ipv6_blocked
            threading.Thread(target=self._toggle_ipv6, args=(enable,),
                             daemon=True).start()
        elif cmd == ID_EXIT:
            user32.DestroyWindow(self.hwnd)

    def _toggle_lockdown(self, enable):
        ok, msg = self.state.rules.set_lockdown(enable)
        self.state.rules.refresh()
        self.state._emit_event("action",
                               f"tray lockdown {'ON' if enable else 'OFF'} ok={ok}")
        self._update(
            info=("Outbound default-deny is ON. Allow apps from the dashboard."
                  if enable else "Lockdown disabled; outbound set to Allow.")
            if ok else f"Lockdown change failed: {msg}",
            info_title="PrivateFirewall lockdown",
            info_flag=NIIF_INFO if ok else NIIF_ERROR)

    def _toggle_ipv6(self, enable):
        ok, msg = self.state.rules.set_block_ipv6(enable)
        self.state.rules.refresh()
        self.state._emit_event("action",
                               f"tray block-ipv6 {'ON' if enable else 'OFF'} ok={ok}")
        self._update(
            info=("All IPv6 is now blocked (adapters unbound from IPv6)."
                  if enable else "IPv6 re-enabled on all adapters.")
            if ok else f"IPv6 change failed: {msg}",
            info_title="PrivateFirewall IPv6",
            info_flag=NIIF_INFO if ok else NIIF_ERROR)

    def _copy(self, text):
        # 64-bit safety: without restype/argtypes ctypes assumes 32-bit int and
        # TRUNCATES the HGLOBAL handles, so the clipboard write silently no-ops.
        CF_UNICODETEXT, GMEM_MOVEABLE = 13, 0x0002
        kernel32.GlobalAlloc.restype = c_void_p
        kernel32.GlobalAlloc.argtypes = [c_uint, c_size_t]
        kernel32.GlobalLock.restype = c_void_p
        kernel32.GlobalLock.argtypes = [c_void_p]
        kernel32.GlobalUnlock.argtypes = [c_void_p]
        user32.OpenClipboard.argtypes = [c_void_p]
        user32.SetClipboardData.restype = c_void_p
        user32.SetClipboardData.argtypes = [c_uint, c_void_p]
        data = (text + "\0").encode("utf-16-le")
        if not user32.OpenClipboard(None):
            return
        try:
            user32.EmptyClipboard()
            h = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
            ptr = kernel32.GlobalLock(h)
            ctypes.memmove(ptr, data, len(data))
            kernel32.GlobalUnlock(h)
            if not user32.SetClipboardData(CF_UNICODETEXT, h):
                kernel32.GlobalFree.argtypes = [c_void_p]
                kernel32.GlobalFree(h)          # ownership stays ours on failure
        finally:
            user32.CloseClipboard()

    # -- window proc --------------------------------------------------------
    def _on_message(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            if lparam == WM_LBUTTONDBLCLK:
                self.open_external(self.url)
            elif lparam in (WM_RBUTTONUP, WM_CONTEXTMENU):
                self._show_menu()
            return 0
        if msg == WM_TIMER:
            try:
                self._refresh()
            except Exception:
                pass
            return 0
        if msg == self._wm_taskbar and self._wm_taskbar:
            self._add_icon()          # Explorer restarted — re-add the icon
            return 0
        if msg == WM_DESTROY:
            self._remove_icon()
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    # -- run ----------------------------------------------------------------
    def run(self):
        _sig()
        hinst = kernel32.GetModuleHandleW(None)
        wc = WNDCLASS()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = "PrivateFirewallTray"
        if not user32.RegisterClassW(byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.hwnd = user32.CreateWindowExW(
            0, "PrivateFirewallTray", "PrivateFirewall", 0, 0, 0, 0, 0,
            None, None, hinst, None)
        if not self.hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self._wm_taskbar = user32.RegisterWindowMessageW("TaskbarCreated")
        if not self._add_icon():
            raise ctypes.WinError(ctypes.get_last_error())
        self._refresh()
        user32.SetTimer(self.hwnd, 1, 3000, None)

        msg = MSG()
        while True:
            r = user32.GetMessageW(byref(msg), None, 0, 0)
            if r <= 0:
                break
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))
        self._remove_icon()


def run_tray(state, url, log_dir, open_external, admin, config_path=""):
    Tray(state, url, log_dir, open_external, admin, config_path).run()
