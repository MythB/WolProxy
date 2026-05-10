"""
WOL Proxy — System Tray Application
"""

import sys
import os
import threading
import logging
import time
import socket
import queue
import winreg
import ctypes
import collections
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, Raw, IP
import pystray
from PIL import Image, ImageTk

# ─────────────────────────────────────────
#  GET ICON
# ─────────────────────────────────────────
_ico_cache = None
_ico_lock  = threading.Lock()

def _get_icon_path():
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, "wol_proxy.ico")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "wol_proxy.ico")

def _load_ico_image(size: int = 64):
    global _ico_cache
    with _ico_lock:
        if _ico_cache is None:
            try:
                _ico_cache = Image.open(_get_icon_path()).convert("RGBA")
            except Exception:
                _ico_cache = Image.new("RGBA", (64, 64), (15, 98, 254, 255))
        try:
            return _ico_cache.resize((size, size), Image.LANCZOS)
        except Exception:
            return Image.new("RGBA", (size, size), (15, 98, 254, 255))

def _set_window_icon(win: tk.Toplevel):
    try:
        img = _load_ico_image(32)
        if img is None:
            return
        tk_img = ImageTk.PhotoImage(img)
        win.iconphoto(True, tk_img)
        win._icon_ref = tk_img
    except Exception:
        pass

# ─────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────
WOL_PORT        = 9
APP_NAME        = "WolProxy"
APP_VERSION     = "1.0.0"
APP_PUBLISHER   = "MythB"
APP_DESCRIPTION = "WoLProxy — captures Wake-on-LAN packets on any interface and forwards them to a target host"
STARTUP_KEY     = r"Software\Microsoft\Windows\CurrentVersion\Run"
CONFIG_KEY      = r"Software\WolProxy"
LOG_BUFFER      = 500

# ─────────────────────────────────────────
#  DEFAULTS
# ─────────────────────────────────────────
DEFAULTS = {
    "trigger_mac": "AA:BB:CC:DD:EE:FF",
    "target_mac":  "FF:EE:DD:CC:BB:AA",
    "broadcast":   "255.255.255.255",
    "window":      0.5,
}

# ─────────────────────────────────────────
#  SINGLE INSTANCE (mutex)
# ─────────────────────────────────────────
_MUTEX_NAME   = "Global\\WOLProxy_SingleInstance"
_mutex_handle = None

def _acquire_mutex() -> bool:
    global _mutex_handle
    try:
        _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
        err = ctypes.windll.kernel32.GetLastError()
        if err == 183:
            return False
        if err != 0:
            return False
        return True
    except Exception:
        return False

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────
log_queue  = queue.Queue()
log_buffer = collections.deque(maxlen=LOG_BUFFER)
_buf_lock  = threading.Lock()

class _QueueHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        with _buf_lock:
            log_buffer.append(msg)
        log_queue.put(msg)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[_QueueHandler()],
)

# ─────────────────────────────────────────
#  CONFIG (registry)
# ─────────────────────────────────────────
def load_config() -> dict:
    result = dict(DEFAULTS)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONFIG_KEY, 0, winreg.KEY_READ) as k:
            for key in DEFAULTS:
                try:
                    val, _ = winreg.QueryValueEx(k, key)
                    result[key] = float(val) if key == "window" else val
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"[ERR] Config load failed: {e}")
    return result

def save_config(data: dict):
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CONFIG_KEY) as k:
            for key, val in data.items():
                winreg.SetValueEx(k, key, 0, winreg.REG_SZ, str(val))
    except Exception as e:
        logging.error(f"[ERR] Config save failed: {e}")

cfg       = load_config()
_cfg_lock = threading.Lock()

# ─────────────────────────────────────────
#  SNIFF STATUS  (FIX #3 — dynamic log label)
# ─────────────────────────────────────────
_sniff_status_text = "● listening"
_sniff_status_ok   = True
_sniff_status_lock = threading.Lock()

def _set_sniff_status(text: str, ok: bool = True):
    """Update the sniff status that the log window label polls."""
    global _sniff_status_text, _sniff_status_ok
    with _sniff_status_lock:
        _sniff_status_text = text
        _sniff_status_ok   = ok

# ─────────────────────────────────────────
#  WOL CORE (Scapy + Npcap)
# ─────────────────────────────────────────
_last_evt      = 0.0
_last_evt_lock = threading.Lock()
_sniff_stop    = threading.Event()
_sniff_exited  = threading.Event()
_restart_lock  = threading.Lock()

def _get_cfg(key):
    with _cfg_lock:
        return cfg[key]

def _send_wol():
    try:
        with _cfg_lock:
            target_mac = cfg["target_mac"]
            broadcast  = cfg["broadcast"]
        mac   = target_mac.replace(":", "").replace("-", "").lower()
        magic = bytes.fromhex("FF" * 6 + mac * 16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (broadcast, WOL_PORT))
        ts = time.strftime("%H:%M:%S")
        logging.info(f"[OK]  Magic packet sent → {target_mac}")
        _update_tray_tooltip(f"WOL Proxy — Last sent: {ts}")
    except Exception as e:
        logging.error(f"[ERR] Send failed: {e}")
        _update_tray_tooltip("WOL Proxy — Send error!")

def _check_wol(pkt):
    global _last_evt
    if _sniff_stop.is_set():
        return
    try:
        if IP not in pkt or Raw not in pkt:
            return
        data = bytes(pkt[Raw])
        if len(data) >= 102 and data[:6] == b"\xff" * 6:
            mac_bytes = data[6:12]
            if data[6:102] != mac_bytes * 16:
                return
            target = ":".join(f"{b:02x}" for b in mac_bytes)
            now    = time.time()
            window = _get_cfg("window")
            with _last_evt_lock:
                if now - _last_evt < window:
                    return
                _last_evt = now
            trigger_mac = _get_cfg("trigger_mac").lower().replace("-", ":")
            target_mac  = _get_cfg("target_mac").lower().replace("-", ":")
            if target in (trigger_mac, target_mac):
                logging.info(f"[WOL] Captured: {pkt[IP].src} → {target}")
                threading.Thread(target=_send_wol, daemon=True).start()
            else:
                logging.info(f"[BLK] Rejected: {target} (not allowed)")
    except Exception as e:
        logging.error(f"[ERR] Packet error: {e}")

def _check_npcap() -> bool:
    try:
        ctypes.windll.LoadLibrary("wpcap.dll")
        return True
    except OSError:
        return False

def _sniff_worker():
    _sniff_exited.clear()
    if not _check_npcap():
        logging.error("[ERR] Npcap not found — install from https://npcap.com")
        _update_tray_tooltip("WOL Proxy — Npcap missing!")
        _set_sniff_status("● Npcap missing", ok=False)
        ctypes.windll.user32.MessageBoxW(
            0,
            "WOL Proxy requires Npcap to capture packets.\n\n"
            "Download and install it from:\nhttps://npcap.com\n\n"
            "Then restart the application.",
            "WOL Proxy — Npcap Required",
            0x10,
        )
        return
    logging.info("[INF] Listening on all interfaces...")
    _update_tray_tooltip("WOL Proxy — Listening")
    # FIX #3 — reflect OK status in log window label
    _set_sniff_status("● listening", ok=True)
    consecutive_errors = 0
    while not _sniff_stop.is_set():
        try:
            sniff(filter="udp and (port 9 or port 7)",
                  prn=_check_wol, store=0,
                  timeout=5, stop_filter=lambda _: _sniff_stop.is_set())
            consecutive_errors = 0
            # Restore OK status after recovery
            _set_sniff_status("● listening", ok=True)
        except Exception as e:
            consecutive_errors += 1
            wait = min(3 * (2 ** min(consecutive_errors - 1, 5)), 120)
            logging.error(f"[ERR] Sniff loop error: {e} — retrying in {wait}s")
            _update_tray_tooltip("WOL Proxy — Sniff error, retrying...")
            _set_sniff_status("● error, retrying…", ok=False)
            if consecutive_errors >= 10:
                logging.warning("[WRN] Too many sniff errors")
            time.sleep(wait)
    _sniff_exited.set()

_tray_icon_ref      = None
_tray_icon_ref_lock = threading.Lock()

def _update_tray_tooltip(text: str):
    with _tray_icon_ref_lock:
        ref = _tray_icon_ref
    try:
        if ref is not None:
            ref.title = text
    except Exception:
        pass

def start_sniff():
    _sniff_stop.clear()
    _sniff_exited.clear()
    threading.Thread(target=_sniff_worker, daemon=True, name="SniffThread").start()

def restart_sniff():
    if not _restart_lock.acquire(blocking=False):
        return
    try:
        _sniff_stop.set()
        _sniff_exited.wait(timeout=6.0)
        start_sniff()
        logging.info("[INF] Listener restarted")
    finally:
        _restart_lock.release()

# ─────────────────────────────────────────
#  REGISTRY — STARTUP
# ─────────────────────────────────────────
def _exe_cmd():
    if getattr(sys, "frozen", False):
        return '"' + sys.executable + '"'
    exe = sys.executable.replace("python.exe", "pythonw.exe")
    return '"' + exe + '" "' + os.path.abspath(__file__) + '"'

def startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, APP_NAME)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False

def set_startup(enable: bool):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if enable:
                winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, _exe_cmd())
                logging.info("[INF] Added to startup")
            else:
                try:
                    winreg.DeleteValue(k, APP_NAME)
                    logging.info("[INF] Removed from startup")
                except FileNotFoundError:
                    pass
    except Exception as e:
        logging.error(f"[ERR] Registry startup: {e}")

# ─────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def _valid_mac(v):
    normalized = v.strip().replace("-", ":")
    return bool(_MAC_RE.match(normalized))

def _valid_ip(v):
    parts = v.strip().split(".")
    try:
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def _valid_win(v):
    try:
        return 0.0 <= float(v) <= 10.0
    except ValueError:
        return False

# ─────────────────────────────────────────
#  APPLICATION (UI)
# ─────────────────────────────────────────
class App:
    def __init__(self):
        _hide_console()
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_NAME)
        _set_window_icon(self.root)

        self.log_win      = None
        self.log_text     = None
        self.settings_win = None
        self.icon         = None
        self._status_var   = None
        self._status_label = None
        self._svars        = {}
        self._orig_cfg     = {}
        self._tooltip_timer = None

        threading.Thread(target=self._run_tray, daemon=True).start()
        self._poll()
        self.root.mainloop()

    def _run_tray(self):
        global _tray_icon_ref
        icon_image = _load_ico_image(64)
        if icon_image is None:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Show Logs", self._tray_show_logs, default=True),
            pystray.MenuItem("Settings", self._tray_show_settings),
            pystray.MenuItem("Run at Startup", self._tray_toggle_startup,
                             checked=lambda _: startup_enabled()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._tray_quit),
        )
        self.icon = pystray.Icon(APP_NAME, icon_image, "WOL Proxy — Listening", menu)
        with _tray_icon_ref_lock:
            _tray_icon_ref = self.icon
        self.icon.run()

    def _tray_show_logs(self, *_): self.root.after(0, self._open_log_window)
    def _tray_show_settings(self, *_): self.root.after(0, self._open_settings_window)

    def _tray_toggle_startup(self, *_):
        is_enabled = startup_enabled()
        set_startup(not is_enabled)
        state = "enabled" if not is_enabled else "disabled"
        logging.info(f"[INF] Startup {state}")
        self._set_tray_tooltip_timed(f"WOL Proxy — Startup {state}", "WOL Proxy — Listening", 3.0)

    def _set_tray_tooltip_timed(self, text, revert_to, delay):
        if self._tooltip_timer:
            self._tooltip_timer.cancel()
        _update_tray_tooltip(text)
        self._tooltip_timer = threading.Timer(delay, _update_tray_tooltip, args=(revert_to,))
        self._tooltip_timer.daemon = True
        self._tooltip_timer.start()

    def _tray_quit(self, *_):
        if self._tooltip_timer:
            self._tooltip_timer.cancel()
        _sniff_stop.set()
        _sniff_exited.wait(timeout=6.0)
        if self.icon:
            self.icon.stop()
        self.root.after(0, self.root.quit)

    # ── Settings window ──
    def _open_settings_window(self):
        if self.settings_win and self.settings_win.winfo_exists():
            with _cfg_lock:
                current = dict(cfg)
                self._orig_cfg = current
            for key, var in self._svars.items():
                var.set(str(current[key]))
            self.settings_win.deiconify()
            self.settings_win.lift()
            self.settings_win.focus_force()
            return

        win = tk.Toplevel(self.root)
        self.settings_win = win
        win.title("WOL Proxy — Settings")
        win.resizable(False, False)
        win.configure(bg="#0d1117")
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        _set_window_icon(win)

        with _cfg_lock:
            self._orig_cfg = dict(cfg)

        bar = tk.Frame(win, bg="#161b22", height=64)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Label(bar, text="Settings", bg="#161b22", fg="#58a6ff",
                 font=("Segoe UI Semibold", 11)).pack(side=tk.LEFT, padx=14, pady=12)
        tk.Frame(win, bg="#30363d", height=1).pack(fill=tk.X)

        form = tk.Frame(win, bg="#0d1117")
        form.pack(fill=tk.BOTH, expand=True, padx=24, pady=18)

        fields = [
            ("WOL Trigger MAC", "trigger_mac"),
            ("Relay Target MAC", "target_mac"),
            ("Broadcast Address", "broadcast"),
            ("Debounce (sec)",    "window"),
        ]
        with _cfg_lock:
            current = dict(cfg)

        for row, (label, key) in enumerate(fields):
            tk.Label(form, text=label, bg="#0d1117", fg="#c9d1d9",
                     font=("Segoe UI", 9), anchor="w").grid(
                row=row * 2, column=0, sticky="w", padx=(0, 16), pady=(10, 0))
            var = tk.StringVar(value=str(current[key]))
            self._svars[key] = var
            tk.Entry(form, textvariable=var, bg="#161b22", fg="#e6edf3",
                     insertbackground="#58a6ff", relief=tk.FLAT,
                     font=("Consolas", 10), width=22,
                     highlightthickness=1, highlightbackground="#30363d",
                     highlightcolor="#58a6ff").grid(
                row=row * 2, column=1, rowspan=2, sticky="new", pady=(10, 10), ipady=5)

        form.columnconfigure(1, weight=1)
        tk.Frame(win, bg="#30363d", height=1).pack(fill=tk.X, padx=24)

        btn_row = tk.Frame(win, bg="#0d1117")
        btn_row.pack(fill=tk.X, padx=24, pady=12)

        def _save():
            errors = []
            new_cfg = {}
            for key, var in self._svars.items():
                val = var.get().strip()
                if key in ("trigger_mac", "target_mac"):
                    if not _valid_mac(val):
                        errors.append(f"Invalid MAC: {val}")
                    else:
                        new_cfg[key] = val.replace("-", ":").upper()
                elif key == "broadcast":
                    if not _valid_ip(val):
                        errors.append(f"Invalid IP: {val}")
                    else:
                        new_cfg[key] = val
                elif key == "window":
                    if not _valid_win(val):
                        errors.append("Debounce must be 0–10 seconds")
                    else:
                        new_cfg[key] = float(val)
            if errors:
                messagebox.showerror("Error", "\n".join(errors), parent=win)
                return
            with _cfg_lock:
                cfg.update(new_cfg)
                full = dict(cfg)
            save_config(full)
            logging.info(f"[INF] Saved — Trigger={full['trigger_mac']} "
                         f"Target={full['target_mac']} Broadcast={full['broadcast']} "
                         f"Window={full['window']}s")
            threading.Thread(target=restart_sniff, daemon=True).start()
            win.withdraw()

        def _reset():
            for key, var in self._svars.items():
                var.set(str(DEFAULTS[key]))
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, CONFIG_KEY)
            except Exception:
                pass
            with _cfg_lock:
                cfg.update(dict(DEFAULTS))
            self._orig_cfg = dict(DEFAULTS)
            logging.info("[INF] Reset to defaults")
            threading.Thread(target=restart_sniff, daemon=True).start()
            win.withdraw()

        def _cancel():
            for key, var in self._svars.items():
                var.set(str(self._orig_cfg.get(key, DEFAULTS[key])))
            logging.info("[INF] Cancelled")
            win.withdraw()

        tk.Button(btn_row, text="Save & Apply", bg="#1f6feb", fg="#ffffff",
                  activebackground="#388bfd", activeforeground="#ffffff",
                  relief=tk.FLAT, font=("Segoe UI Semibold", 9),
                  command=_save, cursor="hand2", padx=14, pady=6, borderwidth=0).pack(side=tk.RIGHT)
        tk.Button(btn_row, text="Reset", bg="#21262d", fg="#c9d1d9",
                  activebackground="#30363d", activeforeground="#ffffff",
                  relief=tk.FLAT, font=("Segoe UI", 9),
                  command=_reset, cursor="hand2", padx=10, pady=6, borderwidth=0).pack(side=tk.RIGHT, padx=(0, 8))
        tk.Button(btn_row, text="Cancel", bg="#21262d", fg="#c9d1d9",
                  activebackground="#30363d", activeforeground="#ffffff",
                  relief=tk.FLAT, font=("Segoe UI", 9),
                  command=_cancel, cursor="hand2", padx=10, pady=6, borderwidth=0).pack(side=tk.RIGHT, padx=(0, 8))
        _center_window(win)

    # ── Log window ──
    def _open_log_window(self):
        if self.log_win and self.log_win.winfo_exists():
            self.log_win.deiconify()
            self.log_win.lift()
            self.log_win.focus_force()
            self._load_buffer()
            return
        self.log_win = win = tk.Toplevel(self.root)
        win.title("WOL Proxy — Logs")
        win.configure(bg="#0d1117")
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        win.resizable(True, True)
        _set_window_icon(win)
        bar = tk.Frame(win, bg="#161b22", height=64)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Label(bar, text="Logs", bg="#161b22", fg="#58a6ff",
                 font=("Segoe UI Semibold", 11)).pack(side=tk.LEFT, padx=14, pady=12)
        self._status_var = tk.StringVar(value=_sniff_status_text)
        self._status_label = tk.Label(
            bar, textvariable=self._status_var,
            bg="#161b22", fg="#3fb950", font=("Segoe UI", 9))
        self._status_label.pack(side=tk.LEFT, pady=12)
        for txt, cmd in [("Clear", self._clear_log),
                         ("Settings", lambda: self.root.after(0, self._open_settings_window))]:
            tk.Button(bar, text=txt, bg="#21262d", fg="#c9d1d9",
                      activebackground="#30363d", activeforeground="#ffffff",
                      relief=tk.FLAT, font=("Segoe UI", 9),
                      command=cmd, cursor="hand2", padx=10, pady=4, borderwidth=0).pack(side=tk.RIGHT, padx=5, pady=10)
        tk.Frame(win, bg="#30363d", height=1).pack(fill=tk.X)
        self.log_text = scrolledtext.ScrolledText(
            win, bg="#0d1117", fg="#8b949e",
            font=("Cascadia Code", 9) if _font_exists("Cascadia Code") else ("Consolas", 10),
            state="disabled", borderwidth=0, highlightthickness=0,
            insertbackground="#58a6ff", selectbackground="#264f78")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for tag, color in [("ok", "#3fb950"), ("wol", "#58a6ff"), ("blk", "#f0883e"),
                           ("err", "#f85149"), ("wrn", "#d29922"), ("inf", "#8b949e"),
                           ("time", "#484f58"), ("sep", "#484f58")]:
            self.log_text.tag_configure(tag, foreground=color)
        _center_window(win, 854, 480)
        self._load_buffer()

    def _load_buffer(self):
        if not self._text_ok(): return
        with _buf_lock:
            lines = list(log_buffer)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        for line in lines:
            self._insert_line(line)
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    def _insert_line(self, msg):
        if msg.startswith("---"):
            self.log_text.insert(tk.END, msg + "\n", "sep")
            return
        parts = msg.split("  ", 1)
        ts, body = (parts[0], parts[1]) if len(parts) == 2 else ("", msg)
        tag = "inf"
        for key, val in {"[OK]": "ok", "[WOL]": "wol", "[BLK]": "blk",
                         "[ERR]": "err", "[WRN]": "wrn"}.items():
            if key in body:
                tag = val
                break
        if ts:
            self.log_text.insert(tk.END, ts + "  ", "time")
        self.log_text.insert(tk.END, body + "\n", tag)

    def _append_log(self, msg):
        if not self._text_ok(): return
        self.log_text.configure(state="normal")
        self._insert_line(msg)
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > LOG_BUFFER:
            self.log_text.delete("1.0", f"{line_count - LOG_BUFFER}.0")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    def _poll(self):
        try:
            if not self._text_ok():
                while not log_queue.empty():
                    try:
                        log_queue.get_nowait()
                    except queue.Empty:
                        break
                self.root.after(500, self._poll)
                return
            
            for _ in range(50):
                self._append_log(log_queue.get_nowait())
        except queue.Empty:
            pass
        
        if self._status_var and self._status_label:
            with _sniff_status_lock:
                txt = _sniff_status_text
                ok  = _sniff_status_ok
            self._status_var.set(txt)
            try:
                self._status_label.configure(fg="#3fb950" if ok else "#f85149")
            except Exception:
                pass
        
        self.root.after(200, self._poll)

    def _clear_log(self):
        if not self._text_ok(): return
        sep = f"--- Cleared at {time.strftime('%H:%M:%S')} ---"
        with _buf_lock:
            log_buffer.clear()
            log_buffer.append(sep)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, sep + "\n", "sep")
        self.log_text.configure(state="disabled")

    def _text_ok(self):
        return (self.log_win and self.log_win.winfo_exists()
                and self.log_win.winfo_viewable()
                and self.log_text)

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def _center_window(win, width=None, height=None):
    win.update_idletasks()
    w = width or win.winfo_reqwidth()
    h = height or win.winfo_reqheight()
    x = (win.winfo_screenwidth() - w) // 2
    y = (win.winfo_screenheight() - h) // 2
    if width and height:
        win.geometry(f"{w}x{h}+{x}+{y}")
    else:
        win.geometry(f"+{x}+{y}")

def _hide_console():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass

_font_cache = {}
def _font_exists(name):
    if name in _font_cache:
        return _font_cache[name]
    try:
        import tkinter.font as tkf
        result = name in tkf.families()
    except Exception:
        result = False
    _font_cache[name] = result
    return result

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    if not _acquire_mutex():
        ctypes.windll.user32.MessageBoxW(
            0, "WOL Proxy is already running.\nCheck the system tray.",
            "WOL Proxy", 0x40)
        sys.exit(0)

    start_sniff()
    logging.info("[INF] WOL Proxy started")
    logging.info(f"[INF] Broadcast={cfg['broadcast']}:{WOL_PORT}")
    logging.info(f"[INF] Trigger={cfg['trigger_mac']}  Target={cfg['target_mac']}")
    logging.info(f"[INF] Window={cfg['window']}s")
    App()
