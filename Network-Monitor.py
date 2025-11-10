#!/usr/bin/env python3
# Network Monitor v3.6 — Stable Monitoring Edition (with slider, pause, and configurable settings)
# -----------------------------------------------------------------------------------------------
# - Detects ALL private hops (Windows PowerShell Test-NetConnection or traceroute)
# - Pings every internal hop + first public hop (“Internet”)
# - 24h history (auto-prune), zoom/pan, and a Matplotlib time slider to scroll
# - Configurable: interval (sec), attempts, timeout (sec), fast-retry interval (sec)
# - Non-autoscrolling text log (only follows when at bottom)
# - Pause/Resume button
# - Export graph to PNG (“Save As…”)
#
# Requirements:
#   pip install matplotlib
#
# Notes:
#   - On Windows, needs PowerShell (default).
#   - On Linux/macOS, needs `traceroute` installed.

import os, subprocess, time, datetime, platform, threading, re, csv, shutil
import math
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from collections import deque

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.widgets import Slider
import json
import signal, sys

SETTINGS_FILE = "network_monitor_settings.json"

# ---------------- Configuration defaults (user-changeable in GUI) ---------------
DEFAULT_INTERVAL_SEC = 10     # normal sampling interval
DEFAULT_ATTEMPTS = 3          # ping attempts per cycle
DEFAULT_TIMEOUT_SEC = 2       # per attempt timeout
DEFAULT_FAST_RETRY_SEC = 2    # temporary faster retry when any hop is down
DEFAULT_WINDOW_MIN = 60       # time window shown when using the slider (minutes)
MAX_HISTORY_DAYS = 7          # keep at most 7 days of data in memory
HISTORY_HOURS = 24 * MAX_HISTORY_DAYS

DEFAULT_EXTRA_TARGET = "1.1.1.1"  # Optional extra host/IP to monitor (Cloudflare DNS)

LOG_BASENAME = "network_log"
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
TRACEROUTE_TIMEOUT = 25
DEFAULT_INTERNET_FALLBACK = "1.1.1.1"

IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

# ---------------- Utility ----------------
def run_cmd(cmd, timeout=None, shell=False):
    return subprocess.run(cmd if not shell else " ".join(cmd),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout, shell=shell)

def is_private_ip(ip: str) -> bool:
    try:
        a, b, c, d = [int(x) for x in ip.split(".")]
        if a == 10: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168: return True
    except Exception:
        pass
    return False

def detect_connection_type() -> str:
    sysn = platform.system().lower()
    try:
        if sysn == "windows":
            r = run_cmd(["netsh","wlan","show","interfaces"], timeout=3)
            if "State" in r.stdout and re.search(r"State\s*:\s*connected", r.stdout, re.I):
                m = re.search(r"SSID\s*:\s*(.+)", r.stdout, re.I)
                return "Wi-Fi" + (f" ({m.group(1).strip()})" if m else "")
            return "LAN"
        if sysn == "linux":
            if shutil.which("iwgetid"):
                r = run_cmd(["iwgetid","-r"], timeout=2)
                if r.returncode == 0 and r.stdout.strip():
                    return f"Wi-Fi ({r.stdout.strip()})"
                return "LAN"
            if shutil.which("nmcli"):
                r = run_cmd(["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device"], timeout=3)
                for line in r.stdout.splitlines():
                    p = line.split(":")
                    if len(p)>=4 and p[1]=="wifi" and p[2]=="connected":
                        return f"Wi-Fi ({p[3]})"
                return "LAN"
            return "Unknown"
        if sysn == "darwin":
            if shutil.which("networksetup"):
                r = run_cmd(["networksetup","-getairportnetwork","en0"], timeout=3)
                if "Current Wi-Fi Network" in r.stdout:
                    ssid = r.stdout.strip().split(":")[-1].strip()
                    return f"Wi-Fi ({ssid})"
                return "LAN"
            return "Unknown"
    except Exception:
        return "Unknown"
    return "Unknown"

# ----- Traceroute parsing -----
def parse_ps_traceroute(text: str):
    # Include IPs on the same "TraceRoute :" line and below; exclude SourceAddress & 0.0.0.0.
    src = None
    m_src = re.search(r"SourceAddress\s*:\s*(\d+\.\d+\.\d+\.\d+)", text, re.I)
    if m_src: src = m_src.group(1)

    hops = []
    m_tr = re.search(r"TraceRoute\s*:\s*(.*)$", text, re.I | re.M)
    if m_tr:
        same_line = m_tr.group(1)
        hops.extend(IP_RE.findall(same_line))
        tail = text[m_tr.end():]
        hops.extend(IP_RE.findall(tail))
    else:
        m_any = re.search(r"TraceRoute", text, re.I)
        if m_any:
            tail = text[m_any.end():]
            hops.extend(IP_RE.findall(tail))

    cleaned = []
    for ip in hops:
        if ip == "0.0.0.0" or ip == src: continue
        if not cleaned or cleaned[-1] != ip:
            cleaned.append(ip)
    return cleaned

def parse_tracert(text: str):
    hops = []
    for line in text.splitlines():
        if re.match(r"^\s*\d+\s", line):
            ips = IP_RE.findall(line)
            if ips:
                ip = ips[-1]
                if ip != "0.0.0.0" and (not hops or hops[-1] != ip):
                    hops.append(ip)
    if not hops:
        rough = IP_RE.findall(text)
        for ip in rough:
            if ip != "0.0.0.0" and (not hops or hops[-1] != ip):
                hops.append(ip)
    return hops

def get_gateway_fallback_list():
    sysn = platform.system().lower()
    try:
        if sysn == "windows":
            r = run_cmd(["ipconfig"], timeout=5, shell=True)
            m = re.search(r"Default Gateway[ .:]+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return [m.group(1)]
        else:
            r = run_cmd(["ip","route"], timeout=5)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return [m.group(1)]
    except Exception:
        pass
    return []

def traceroute_windows():
    try:
        r = run_cmd(["powershell","-NoProfile","-Command",
                     f"Test-NetConnection {DEFAULT_INTERNET_FALLBACK} -TraceRoute | Out-String"],
                    timeout=TRACEROUTE_TIMEOUT)
        if r.returncode == 0 and r.stdout:
            print("📡 PowerShell Test-NetConnection output:\n" + r.stdout)
            hops = parse_ps_traceroute(r.stdout)
            if hops: return hops
    except subprocess.TimeoutExpired:
        print("⚠️ PowerShell TraceRoute timed out.")
    except Exception as e:
        print(f"⚠️ PowerShell TraceRoute error: {e}")

    for cmd in ([["tracert","-4","-d",DEFAULT_INTERNET_FALLBACK]],
                [["tracert","-4",DEFAULT_INTERNET_FALLBACK]]):
        try:
            res = run_cmd(cmd, timeout=TRACEROUTE_TIMEOUT, shell=True)
            out = res.stdout or res.stderr
            if out:
                print(f"📡 tracert output ({' '.join(cmd[0])}):\n{out}")
                hops = parse_tracert(out)
                if hops: return hops
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout from: {' '.join(cmd[0])}")
        except Exception as e:
            print(f"⚠️ tracert error: {e}")

    gw = get_gateway_fallback_list()
    if gw:
        print(f"✅ Fallback gateway: {gw[0]}")
        return gw
    return []

def traceroute_unix():
    for cmd in (["traceroute","-n","-w","2","-q","1",DEFAULT_INTERNET_FALLBACK],
                ["traceroute","-n",DEFAULT_INTERNET_FALLBACK],
                ["traceroute",DEFAULT_INTERNET_FALLBACK]):
        try:
            res = run_cmd(cmd, timeout=TRACEROUTE_TIMEOUT)
            out = res.stdout or res.stderr
            if out:
                print(f"📡 traceroute output ({' '.join(cmd)}):\n{out}")
                hops = parse_tracert(out)
                if hops: return hops
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout from: {' '.join(cmd)}")
        except Exception as e:
            print(f"⚠️ traceroute error: {e}")
    gw = get_gateway_fallback_list()
    if gw:
        print(f"✅ Fallback gateway: {gw[0]}")
        return gw
    return []

def detect_route():
    print("\n🔍 Starting route detection...\n")
    sysn = platform.system().lower()
    hops = traceroute_windows() if sysn == "windows" else traceroute_unix()

    if not hops:
        print("❌ No hops detected. Using fallback targets.")
        return ["192.168.0.1"], DEFAULT_INTERNET_FALLBACK

    internal = [ip for ip in hops if is_private_ip(ip)]
    first_public = None
    for ip in hops:
        if not is_private_ip(ip):
            first_public = ip
            break

    print(f"🏠 Internal hops: {internal}")
    print(f"☁️ First public hop (Internet): {first_public or DEFAULT_INTERNET_FALLBACK}")
    return internal if internal else ["192.168.0.1"], (first_public or DEFAULT_INTERNET_FALLBACK)

# ------------- Ping engine -------------
def parse_latency_ms(output: str) -> float:
    match = re.search(r"time[=<]?\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    if not match:
        return math.nan
    value = float(match.group(1))
    return value


def ping_once(ip, timeout_sec):
    is_win = (os.name == "nt")
    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_sec)), ip]
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        output = (res.stdout or "") + (res.stderr or "")
        latency = parse_latency_ms(output)
        if res.returncode != 0:
            return False, math.nan
        return True, latency
    except Exception:
        return False, math.nan


def ping_check(ip, attempts=3, timeout_sec=2):
    """Return (reachable: bool, fail_count: int, latency_ms: float) after multiple attempts."""
    fails = 0
    for _ in range(int(attempts)):
        ok, latency = ping_once(ip, timeout_sec)
        if ok:
            return True, fails, latency
        fails += 1
    return False, fails, math.nan

def now_ts():
    return datetime.datetime.now()

def fmt_time(ts: datetime.datetime):
    return ts.strftime("%H:%M:%S")

# ------------- App -------------
class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor — v3.6 Stable (24h, Slider, Pause)")
        self.root.geometry("1300x850")

        # State
        self.paused = False
        self.running = True
        self._after_jobs = []

        # Settings (tk variables)
        self.var_interval = tk.IntVar(value=DEFAULT_INTERVAL_SEC)
        self.var_attempts = tk.IntVar(value=DEFAULT_ATTEMPTS)
        self.var_timeout = tk.IntVar(value=DEFAULT_TIMEOUT_SEC)
        self.var_fast_retry = tk.IntVar(value=DEFAULT_FAST_RETRY_SEC)
        self.var_window_min = tk.IntVar(value=DEFAULT_WINDOW_MIN)
        self.var_extra_target = tk.StringVar(value=DEFAULT_EXTRA_TARGET)
        self.var_maintenance_frequency = tk.StringVar(value="Off")
        self.var_maintenance_time = tk.StringVar(value="03:00")
        self.var_maintenance_duration = tk.IntVar(value=10)
        self.var_maintenance_weekday = tk.StringVar(value="Monday")
        self.load_settings()

        # Header: status + connection type + buttons
        top_frame = ttk.Frame(root)
        top_frame.pack(fill="x", padx=10, pady=(10,5))

        status_container = ttk.Frame(top_frame)
        status_container.pack(side="left")

        self.status_label = ttk.Label(status_container, text="Initializing...", font=("Segoe UI", 14, "bold"))
        self.status_label.pack(anchor="w")

        self.summary_label = ttk.Label(status_container, text="", font=("Segoe UI", 9))
        self.summary_label.pack(anchor="w", pady=(2, 0))

        self.stats_frame = ttk.Frame(status_container)
        self.stats_frame.pack(anchor="w", fill="x", pady=(6, 0))
        self.stats_frame.columnconfigure(1, weight=1)
        self.stat_rows = {}

        self.conn_type_label = ttk.Label(top_frame, text="", font=("Segoe UI", 10))
        self.conn_type_label.pack(side="left", padx=(12,0))

        btn_frame = ttk.Frame(root)
        btn_frame.pack(fill="x", padx=10, pady=(0,5))

        self.pause_btn = ttk.Button(btn_frame, text="⏸ Pause", command=self.toggle_pause)
        self.pause_btn.pack(side="left", padx=(0,8))

        self.reset_btn = ttk.Button(btn_frame, text="🔄 Reset", command=self.reset_monitor)
        self.reset_btn.pack(side="left", padx=(0,8))

        self.export_btn = ttk.Button(btn_frame, text="📸 Export Graph to PNG", command=self.export_graph)
        self.export_btn.pack(side="left")

        # Settings panel
        settings = ttk.LabelFrame(root, text="Settings")
        settings.pack(fill="x", padx=10, pady=5)

        ttk.Label(settings, text="Interval (sec):").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Spinbox(settings, from_=2, to=3600, textvariable=self.var_interval, width=6).grid(row=0, column=1, sticky="w")

        ttk.Label(settings, text="Attempts:").grid(row=0, column=2, sticky="w", padx=12, pady=4)
        ttk.Spinbox(settings, from_=1, to=10, textvariable=self.var_attempts, width=6).grid(row=0, column=3, sticky="w")

        ttk.Label(settings, text="Timeout (sec):").grid(row=0, column=4, sticky="w", padx=12, pady=4)
        ttk.Spinbox(settings, from_=1, to=10, textvariable=self.var_timeout, width=6).grid(row=0, column=5, sticky="w")

        ttk.Label(settings, text="Fast retry (sec):").grid(row=0, column=6, sticky="w", padx=12, pady=4)
        ttk.Spinbox(settings, from_=1, to=60, textvariable=self.var_fast_retry, width=6).grid(row=0, column=7, sticky="w")

        ttk.Label(settings, text="Window (min):").grid(row=0, column=8, sticky="w", padx=12, pady=4)
        ttk.Spinbox(settings, from_=1, to=1440, textvariable=self.var_window_min, width=6, command=self.update_slider_range).grid(row=0, column=9, sticky="w")

        ttk.Label(settings, text="Extra host/IP (optional):").grid(row=1, column=8, sticky="w", padx=12, pady=4)
        self.extra_target_entry = ttk.Entry(settings, textvariable=self.var_extra_target, width=18)
        self.extra_target_entry.grid(row=1, column=9, sticky="w")

        ttk.Label(settings, text="Maintenance:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.maintenance_mode_combo = ttk.Combobox(
            settings,
            values=["Off", "Daily", "Weekly"],
            state="readonly",
            width=8,
            textvariable=self.var_maintenance_frequency,
        )
        self.maintenance_mode_combo.grid(row=1, column=1, sticky="w")
        self.maintenance_mode_combo.bind("<<ComboboxSelected>>", lambda *_: self.update_maintenance_widgets())
        self.maintenance_mode_combo.set(self.var_maintenance_frequency.get())

        ttk.Label(settings, text="Start (HH:MM):").grid(row=1, column=2, sticky="w", padx=12, pady=4)
        self.maintenance_time_entry = ttk.Entry(settings, textvariable=self.var_maintenance_time, width=8)
        self.maintenance_time_entry.grid(row=1, column=3, sticky="w")

        ttk.Label(settings, text="Duration (min):").grid(row=1, column=4, sticky="w", padx=12, pady=4)
        self.maintenance_duration_spin = ttk.Spinbox(settings, from_=1, to=180, textvariable=self.var_maintenance_duration, width=6)
        self.maintenance_duration_spin.grid(row=1, column=5, sticky="w")

        ttk.Label(settings, text="Weekday:").grid(row=1, column=6, sticky="w", padx=12, pady=4)
        self.weekday_options = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]
        self.maintenance_weekday_combo = ttk.Combobox(
            settings,
            values=self.weekday_options,
            state="readonly",
            width=10,
            textvariable=self.var_maintenance_weekday,
        )
        self.maintenance_weekday_combo.grid(row=1, column=7, sticky="w")
        self.maintenance_weekday_combo.set(self.var_maintenance_weekday.get())

        # Log window
        self.textbox = scrolledtext.ScrolledText(root, height=12, width=160, state="disabled")
        self.textbox.pack(padx=10, pady=(6,10), fill="x")

        # Matplotlib figure + toolbar
        plot_frame = ttk.Frame(root)
        plot_frame.pack(fill="both", expand=True, padx=10, pady=(0,6))

        self.fig, (self.ax_status, self.ax_latency) = plt.subplots(
            2,
            1,
            figsize=(10, 5.8),
            sharex=True,
            gridspec_kw={"height_ratios": [1.2, 1]},
        )
        # Reserve extra room underneath the latency chart so the time labels and
        # the slider can both be shown without overlapping.  The additional
        # padding also keeps the Matplotlib toolbar readable on high-DPI
        # displays.
        default_bottom = getattr(self.fig.subplotpars, "bottom", 0.11)
        self.slider_height = 0.06
        self.slider_gap = 0.03
        self.slider_min_bottom = 0.025
        min_bottom_needed = self.slider_min_bottom + self.slider_height + self.slider_gap + 0.05
        self.figure_bottom_margin = max(default_bottom, min_bottom_needed)
        self.fig.subplots_adjust(bottom=self.figure_bottom_margin, right=0.8, hspace=0.25)
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.get_tk_widget().pack(side="top", fill="both", expand=True)

        self.toolbar = NavigationToolbar2Tk(self.canvas, plot_frame)
        self.toolbar.update()

        # Pagination controls (24h per page)
        pagination_frame = ttk.Frame(plot_frame)
        pagination_frame.pack(fill="x", pady=(6, 0))
        self.prev_page_btn = ttk.Button(pagination_frame, text="◀ Previous day", command=self.prev_page)
        self.prev_page_btn.pack(side="left")
        self.page_label_var = tk.StringVar(value="No history")
        ttk.Label(pagination_frame, textvariable=self.page_label_var).pack(side="left", padx=8)
        self.next_page_btn = ttk.Button(pagination_frame, text="Next day ▶", command=self.next_page)
        self.next_page_btn.pack(side="left")

        # Slider (matplotlib) — add an axis below the plot
        # Position the slider comfortably below the axes, leaving enough
        # headroom for the "Time" label and tick text.
        axes_box = self.ax_latency.get_position()
        max_bottom = axes_box.y0 - self.slider_height - self.slider_gap
        slider_bottom = self.slider_min_bottom
        if max_bottom < slider_bottom:
            slider_bottom = max(0.0, max_bottom)
        self.slider_ax = self.fig.add_axes([axes_box.x0, slider_bottom, axes_box.width, self.slider_height])  # [left, bottom, width, height] in figure coords
        self.time_slider = Slider(
            self.slider_ax,
            "Offset (min)",
            -float(DEFAULT_WINDOW_MIN),
            0.0,
            valinit=0.0,
            valfmt="%0.1f min",
        )
        self.time_slider.on_changed(self.on_slider_changed)
        self.position_time_slider()

        # Data containers
        self.timestamps = deque()  # store datetime objects
        self.history = {}          # ip -> deque of 0/1
        self.latency_history = {}  # ip -> deque of latency (ms)
        self.internet_series = deque()  # 0/1 for internet
        self.internet_latency_series = deque()
        self.extra_series = deque()
        self.extra_latency_series = deque()
        self.problem_flags = deque()
        self.internal_hops = []
        self.internet_ip = DEFAULT_INTERNET_FALLBACK
        self.extra_target = None
        self.hop_colors = ["tab:blue", "tab:orange", "tab:purple", "tab:brown",
                           "tab:pink", "tab:gray", "tab:olive", "tab:cyan"]
        self.internet_color = "skyblue"  # dashed
        self.extra_color = "mediumseagreen"
        self.start_time = now_ts()
        self.total_measurements = 0
        self.page_dates = []
        self.current_page_index = 0

        # Initialize log file paths (TXT + CSV will be timestamped)
        self.start_new_log_files()

        # Connection type
        self.conn_type = detect_connection_type()
        print(f"📶 Link type: {self.conn_type}")
        self.conn_type_label.config(text=f"Link type: {self.conn_type}")

        # Detect route once
        self.internal_hops, self.internet_ip = detect_route()
        self.extra_target = self.resolve_extra_target()
        extra_display = f" → Extra={self.extra_target}" if self.extra_target else ""
        print(f"🌐 Targets: {self.internal_hops} → Internet={self.internet_ip}{extra_display}")
        self.append_gui(
            f"Targets → {', '.join(self.internal_hops)} → Internet={self.internet_ip}{extra_display}"
        )

        for ip in self.internal_hops:
            self.history[ip] = deque()
            self.latency_history[ip] = deque()

        if self.extra_target:
            self.extra_series.clear()
            self.extra_latency_series.clear()

        self.build_stat_rows()

        # Initialize CSV header
        self.init_csv_header()
        self.append_gui(
            f"Log files → {os.path.basename(self.log_txt_path)}, {os.path.basename(self.log_csv_path)}"
        )

        # Initialize statistics label
        self.update_stats_label()

        self.problem_marker_artists = []
        self.maintenance_active = False
        self.update_maintenance_widgets()
        self.refresh_page_controls()

        # Start monitor thread
        threading.Thread(target=self.monitor_loop, daemon=True).start()

    # ---------- Settings persistence ----------
    def load_settings(self):
        """Load saved user settings from JSON file."""
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.var_interval.set(data.get("interval", self.var_interval.get()))
                self.var_attempts.set(data.get("attempts", self.var_attempts.get()))
                self.var_timeout.set(data.get("timeout", self.var_timeout.get()))
                self.var_fast_retry.set(data.get("fast_retry", self.var_fast_retry.get()))
                self.var_window_min.set(data.get("window_min", self.var_window_min.get()))
                freq_val = data.get("maintenance_frequency", self.var_maintenance_frequency.get())
                if isinstance(freq_val, str):
                    freq_val = freq_val.capitalize()
                if freq_val not in ("Off", "Daily", "Weekly"):
                    freq_val = "Off"
                self.var_maintenance_frequency.set(freq_val)
                self.var_maintenance_time.set(data.get("maintenance_time", self.var_maintenance_time.get()))
                self.var_maintenance_duration.set(data.get("maintenance_duration", self.var_maintenance_duration.get()))
                weekday_val = data.get("maintenance_weekday", self.var_maintenance_weekday.get())
                if weekday_val not in getattr(self, "weekday_options", []):
                    weekday_val = "Monday"
                self.var_maintenance_weekday.set(weekday_val)
                extra_val = data.get("extra_target", self.var_extra_target.get())
                if isinstance(extra_val, str):
                    self.var_extra_target.set(extra_val)
                print("⚙️ Settings loaded from file.")
            except Exception as e:
                print(f"⚠️ Could not load settings: {e}")
    
    def save_settings(self):
        """Save current settings to JSON file."""
        data = {
            "interval": self.var_interval.get(),
            "attempts": self.var_attempts.get(),
            "timeout": self.var_timeout.get(),
            "fast_retry": self.var_fast_retry.get(),
            "window_min": self.var_window_min.get(),
            "extra_target": self.var_extra_target.get(),
            "maintenance_frequency": self.var_maintenance_frequency.get(),
            "maintenance_time": self.var_maintenance_time.get(),
            "maintenance_duration": self.var_maintenance_duration.get(),
            "maintenance_weekday": self.var_maintenance_weekday.get(),
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print("💾 Settings saved.")
        except Exception as e:
            print(f"⚠️ Could not save settings: {e}")

    def update_maintenance_widgets(self):
        mode = self.var_maintenance_frequency.get()
        weekly = (mode.lower() == "weekly")
        try:
            self.maintenance_weekday_combo.configure(state="readonly" if weekly else "disabled")
        except Exception:
            pass

    def _create_stat_row(self, row_index, title):
        label = ttk.Label(self.stats_frame, text=title, font=("Segoe UI", 9, "bold"))
        label.grid(row=row_index, column=0, sticky="w", pady=1)

        progress = ttk.Progressbar(self.stats_frame, maximum=100)
        progress.grid(row=row_index, column=1, sticky="ew", padx=(8, 6), pady=1)

        value = ttk.Label(self.stats_frame, text="—", font=("Segoe UI", 9))
        value.grid(row=row_index, column=2, sticky="e", pady=1)

        return {"label": label, "progress": progress, "value": value}

    def build_stat_rows(self):
        for child in self.stats_frame.winfo_children():
            child.destroy()
        self.stat_rows = {}

        row = 0
        for idx, ip in enumerate(self.internal_hops, start=1):
            title = f"Hop {idx} ({ip})"
            self.stat_rows[ip] = self._create_stat_row(row, title)
            row += 1

        title = f"Internet ({self.internet_ip})"
        self.stat_rows["Internet"] = self._create_stat_row(row, title)
        row += 1

        if self.extra_target:
            extra_title = f"Extra ({self.extra_target})"
            self.stat_rows["Extra"] = self._create_stat_row(row, extra_title)

    def resolve_extra_target(self):
        value = self.var_extra_target.get()
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value or None

    def parse_maintenance_time(self):
        try:
            hour, minute = [int(x) for x in self.var_maintenance_time.get().strip().split(":", 1)]
            if not (0 <= hour < 24 and 0 <= minute < 60):
                raise ValueError
            return hour, minute
        except Exception:
            return None

    def is_in_maintenance(self, ref_ts=None):
        mode = (self.var_maintenance_frequency.get() or "Off").lower()
        if mode not in {"daily", "weekly"}:
            return False

        parsed = self.parse_maintenance_time()
        if not parsed:
            return False

        if ref_ts is None:
            ref_ts = now_ts()

        hour, minute = parsed
        duration_min = max(1, int(self.var_maintenance_duration.get() or 0))

        start_candidate = ref_ts.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if mode == "daily":
            if ref_ts < start_candidate:
                start_candidate -= datetime.timedelta(days=1)
        else:  # weekly
            weekday_str = self.var_maintenance_weekday.get()
            try:
                target_weekday = self.weekday_options.index(weekday_str)
            except ValueError:
                target_weekday = 0
            delta_days = (ref_ts.weekday() - target_weekday) % 7
            start_candidate -= datetime.timedelta(days=delta_days)
            if ref_ts < start_candidate:
                start_candidate -= datetime.timedelta(days=7)

        end_time = start_candidate + datetime.timedelta(minutes=duration_min)
        return start_candidate <= ref_ts <= end_time

    def handle_maintenance_state(self, ts):
        active = self.is_in_maintenance(ts)
        if active and not self.maintenance_active:
            self.maintenance_active = True
            self.append_gui("🛠 Maintenance window active — checks paused", "gray")
        elif not active and self.maintenance_active:
            self.maintenance_active = False
            self.append_gui("✅ Maintenance window ended — monitoring resumed", "green")
            self.status_label.config(text="Monitoring...", foreground="black")
        return active

    def clear_slider_markers(self):
        for artist in getattr(self, "problem_marker_artists", []):
            try:
                artist.remove()
            except Exception:
                pass
        self.problem_marker_artists = []

    def update_slider_markers(self, all_timestamps, latest_ts, flags):
        self.clear_slider_markers()
        if not all_timestamps or not flags:
            self.slider_ax.figure.canvas.draw_idle()
            return

        offsets = []
        for ts, flag in zip(all_timestamps, flags):
            if flag:
                offsets.append((ts - latest_ts).total_seconds() / 60.0)

        if not offsets:
            self.slider_ax.figure.canvas.draw_idle()
            return

        scatter = self.slider_ax.scatter(offsets, [0.5] * len(offsets), color="red", s=40, zorder=5, clip_on=False)
        self.problem_marker_artists.append(scatter)
        for offset in offsets:
            line = self.slider_ax.axvline(offset, color="red", ymin=0.15, ymax=0.85, alpha=0.5, linewidth=1)
            self.problem_marker_artists.append(line)
        self.slider_ax.figure.canvas.draw_idle()


    # ---------- CSV ----------
    def start_new_log_files(self):
        """Create fresh TXT/CSV log file paths using a timestamp."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.current_log_timestamp = timestamp
        self.log_txt_path = os.path.join(LOG_DIR, f"{LOG_BASENAME}_{timestamp}.txt")
        self.log_csv_path = os.path.join(LOG_DIR, f"{LOG_BASENAME}_{timestamp}.csv")
        self.csv_initialized = False
        try:
            with open(self.log_txt_path, "w", encoding="utf-8") as f:
                f.write("")
        except Exception as e:
            print(f"⚠️ Could not initialize log file {self.log_txt_path}: {e}")
        else:
            print(f"📝 Logging to {os.path.basename(self.log_txt_path)} and {os.path.basename(self.log_csv_path)}")

    def init_csv_header(self):
        with open(self.log_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            header = ["timestamp"]
            for idx, ip in enumerate(self.internal_hops, start=1):
                header.extend([f"hop{idx}_status_{ip}", f"hop{idx}_latency_ms"])
            header.extend(["internet_status", "internet_latency_ms"])
            if self.extra_target:
                header.extend(["extra_status", "extra_latency_ms"])
            header.extend(["fail_count", "status"])
            writer.writerow(header)
        self.csv_initialized = True

    # ---------- Pause/Resume ----------
    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.config(text="▶ Resume" if self.paused else "⏸ Pause")
        self.append_gui("⏸ Monitoring paused" if self.paused else "▶ Monitoring resumed")

    def reset_monitor(self):
        if not messagebox.askyesno(
            "Reset Monitor",
            "This will clear the history, logs, and restart monitoring. Continue?",
        ):
            return

        # Pause monitoring loop while we reset state
        self.paused = True
        self.pause_btn.config(text="▶ Resume")
        self.status_label.config(text="Resetting monitor...", foreground="blue")
        self.root.update_idletasks()

        # Give the monitor loop a moment to acknowledge pause
        time.sleep(0.1)

        # Clear in-memory history
        self.timestamps = deque()
        for series in self.history.values():
            series.clear()
        for series in self.latency_history.values():
            series.clear()
        self.extra_series = deque()
        self.extra_latency_series = deque()
        self.internet_latency_series = deque()
        self.problem_flags = deque()
        self.clear_slider_markers()

        # Clear GUI log
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", tk.END)
        self.textbox.configure(state="disabled")

        # Remove current log files
        for path in (getattr(self, "log_txt_path", None), getattr(self, "log_csv_path", None)):
            if not path:
                continue
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                print(f"⚠️ Could not remove {path}: {e}")

        # Start fresh log files
        self.start_new_log_files()

        # Re-detect route targets
        self.internal_hops, self.internet_ip = detect_route()
        self.extra_target = self.resolve_extra_target()
        self.history = {ip: deque() for ip in self.internal_hops}
        self.latency_history = {ip: deque() for ip in self.internal_hops}
        if self.extra_target:
            self.extra_series = deque()
            self.extra_latency_series = deque()
        self.build_stat_rows()

        # Recreate CSV header for the new log files
        self.init_csv_header()
        self.append_gui(
            f"Log files → {os.path.basename(self.log_txt_path)}, {os.path.basename(self.log_csv_path)}"
        )

        # Reset slider and plot
        try:
            self.time_slider.reset()
        except Exception:
            self.time_slider.set_val(1.0)
        self.update_plot()

        # Update status and resume monitoring
        extra_display = f" → Extra={self.extra_target}" if self.extra_target else ""
        targets_msg = f"Targets → {', '.join(self.internal_hops)} → Internet={self.internet_ip}{extra_display}"
        self.append_gui(targets_msg)
        self.status_label.config(text="Monitoring...", foreground="black")
        self.start_time = now_ts()
        self.total_measurements = 0
        self.internet_series = deque()
        self.internet_latency_series = deque()
        if self.extra_target:
            self.extra_series = deque()
            self.extra_latency_series = deque()
        self.problem_flags = deque()
        self.maintenance_active = False
        self.update_stats_label()
        self.paused = False
        self.pause_btn.config(text="⏸ Pause")
        self.append_gui("🔄 Monitor reset — monitoring restarted", "blue")

    # ---------- Export PNG ----------
    def export_graph(self):
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default_name = f"network_graph_{ts}.png"
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
            initialfile=default_name,
            title="Save Graph As..."
        )
        if not path: return
        try:
            self.fig.savefig(path, dpi=150, bbox_inches="tight")
            messagebox.showinfo("Export", f"Graph saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save PNG:\n{e}")

    # ---------- Log UI helper with “smart follow” ----------
    def append_gui(self, msg, color=None):
        # Detect if we are currently at the bottom
        at_bottom = (self.textbox.yview()[1] >= 0.999)
        self.textbox.configure(state="normal")
        self.textbox.insert(tk.END, msg + "\n")
        self.textbox.configure(state="disabled")
        if at_bottom:
            self.textbox.yview_moveto(1.0)  # only follow if we were already at bottom
        if color:
            self.status_label.config(foreground=color, text=msg)
        self.root.update_idletasks()

    # ---------- Monitor loop ----------
    def monitor_loop(self):
        while self.running:
            if self.paused:
                time.sleep(0.2)
                continue

            interval = int(self.var_interval.get())
            attempts = int(self.var_attempts.get())
            timeout = int(self.var_timeout.get())
            fast_retry = int(self.var_fast_retry.get())

            ts = now_ts()

            if self.handle_maintenance_state(ts):
                time.sleep(1.0)
                continue

            # Ping internal hops
            hop_results = []
            any_down = False
            total_fail = 0
            for ip in self.internal_hops:
                ok, fails, latency = ping_check(ip, attempts=attempts, timeout_sec=timeout)
                total_fail += fails
                hop_results.append((ip, ok, latency))
                if not ok:
                    any_down = True

            # Ping internet hop
            internet_ok, inet_fails, internet_latency = ping_check(
                self.internet_ip, attempts=attempts, timeout_sec=timeout
            )
            total_fail += inet_fails
            if not internet_ok:
                any_down = True

            extra_result = None
            if self.extra_target:
                extra_ok, extra_fails, extra_latency = ping_check(
                    self.extra_target, attempts=attempts, timeout_sec=timeout
                )
                total_fail += extra_fails
                if not extra_ok:
                    any_down = True
                extra_result = (self.extra_target, extra_ok, extra_latency)

            # Update series (prune >24h)
            self.timestamps.append(ts)
            for ip, ok, latency in hop_results:
                self.history[ip].append(1 if ok else 0)
                self.latency_history[ip].append(latency)
            self.internet_series.append(1 if internet_ok else 0)
            self.internet_latency_series.append(internet_latency)
            if extra_result:
                self.extra_series.append(1 if extra_result[1] else 0)
                self.extra_latency_series.append(extra_result[2])
            self.problem_flags.append(1 if any_down else 0)
            self.prune_history()
            self.total_measurements += 1
            self.update_stats_label()

            # Classify
            status, color = self.classify(hop_results, internet_ok, extra_result)

            # Log to files + console
            line = self.log_line(
                ts,
                hop_results,
                internet_ok,
                internet_latency,
                total_fail,
                status,
                extra_result=extra_result,
            )
            print(line)
            self.append_gui(line, color)

            # Redraw plot
            self.update_plot()

            # Sleep (fast retry if anything was down)
            sleep_sec = fast_retry if any_down else interval
            for _ in range(int(sleep_sec * 5)):  # small chunks to allow quick pause
                if not self.running or self.paused:
                    break
                time.sleep(0.2)

    def prune_history(self):
        # Keep at most HISTORY_HOURS hours
        cutoff = now_ts() - datetime.timedelta(hours=HISTORY_HOURS)
        # prune timestamps and align all series
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
            for ip in self.internal_hops:
                if self.history[ip]:
                    self.history[ip].popleft()
                if self.latency_history.get(ip):
                    self.latency_history[ip].popleft()
            if self.internet_series:
                self.internet_series.popleft()
            if self.internet_latency_series:
                self.internet_latency_series.popleft()
            if self.extra_series:
                self.extra_series.popleft()
            if self.extra_latency_series:
                self.extra_latency_series.popleft()
            if self.problem_flags:
                self.problem_flags.popleft()

    def classify(self, hop_results, internet_ok, extra_result=None):
        all_internal_ok = all(ok for _, ok, _ in hop_results)
        first_hop_ok = hop_results[0][1] if hop_results else True
        if not first_hop_ok:
            return "❌ First hop down — local LAN issue", "red"
        for idx, (ip, ok, _) in enumerate(hop_results, start=1):
            if not ok:
                return f"🟠 Hop {idx} ({ip}) down — intermediate router issue", "orange"
        if not internet_ok:
            return "🔴 Internet down — ISP/DNS issue", "red"
        if extra_result and not extra_result[1]:
            return f"🟣 Extra target ({extra_result[0]}) down — custom check failed", "purple"
        if all_internal_ok and internet_ok and (not extra_result or extra_result[1]):
            return "✅ All good — connection stable", "green"
        return "⚠️ Indeterminate state", "gray"

    def log_line(self, ts, hop_results, internet_ok, internet_latency, fail_count, status, extra_result=None):
        human = fmt_time(ts)
        def pretty_latency(value):
            if value is None:
                return "—"
            if isinstance(value, float) and math.isnan(value):
                return "—"
            return f"{value:.1f} ms"

        parts = [
            f"{ip}:{'True' if ok else 'False'} ({pretty_latency(latency)})"
            for ip, ok, latency in hop_results
        ]
        if extra_result:
            extra_ip, extra_ok, extra_latency = extra_result
            parts.append(
                f"Extra {extra_ip}:{'True' if extra_ok else 'False'} ({pretty_latency(extra_latency)})"
            )
        line = (
            f"[{human}] "
            + " | ".join(parts)
            + f" | Internet:{internet_ok} ({pretty_latency(internet_latency)}) | fails:{fail_count} → {status}"
        )
        # TXT
        with open(self.log_txt_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        # CSV
        if not self.csv_initialized:
            self.init_csv_header()
        with open(self.log_csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            row = [human]

            for _, ok, latency in hop_results:
                latency_value = ""
                if latency is not None and not (isinstance(latency, float) and math.isnan(latency)):
                    latency_value = f"{latency:.3f}"
                row.extend([ok, latency_value])

            inet_latency_value = ""
            if internet_latency is not None and not (
                isinstance(internet_latency, float) and math.isnan(internet_latency)
            ):
                inet_latency_value = f"{internet_latency:.3f}"

            row.extend([internet_ok, inet_latency_value])

            if self.extra_target:
                if extra_result:
                    _, extra_ok, extra_latency = extra_result
                    extra_latency_value = ""
                    if extra_latency is not None and not (
                        isinstance(extra_latency, float) and math.isnan(extra_latency)
                    ):
                        extra_latency_value = f"{extra_latency:.3f}"
                    row.extend([extra_ok, extra_latency_value])
                else:
                    row.extend(["", ""])

            row.extend([fail_count, status])
            writer.writerow(row)
        return line

    # ---------- Plot & Slider ----------
    def update_slider_range(self):
        # Called when window minutes changes
        self.update_plot()

    def on_slider_changed(self, val):
        # Slider value represents minute offset relative to latest measurement (<= 0)
        self.update_plot()

    def get_page_indices(self, timestamps):
        if not timestamps:
            return []
        if not self.page_dates:
            return list(range(len(timestamps)))
        if not (0 <= self.current_page_index < len(self.page_dates)):
            return list(range(len(timestamps)))
        current_date = self.page_dates[self.current_page_index]
        start_of_day = datetime.datetime.combine(current_date, datetime.time.min)
        end_of_day = start_of_day + datetime.timedelta(days=1)
        indices = [idx for idx, ts in enumerate(timestamps) if start_of_day <= ts < end_of_day]
        return indices or list(range(len(timestamps)))

    def update_pagination(self):
        timestamps = list(self.timestamps)
        unique_dates = sorted({ts.date() for ts in timestamps})
        was_on_latest = self.page_dates and self.current_page_index == len(self.page_dates) - 1
        self.page_dates = unique_dates
        if not self.page_dates:
            self.current_page_index = 0
        else:
            if was_on_latest or self.current_page_index >= len(self.page_dates):
                self.current_page_index = len(self.page_dates) - 1
            else:
                self.current_page_index = max(0, min(self.current_page_index, len(self.page_dates) - 1))
        self.refresh_page_controls()

    def refresh_page_controls(self):
        if not getattr(self, "prev_page_btn", None):
            return
        if not self.page_dates:
            self.page_label_var.set("No history")
            self.prev_page_btn.state(["disabled"])
            self.next_page_btn.state(["disabled"])
            return
        total = len(self.page_dates)
        current = self.page_dates[self.current_page_index]
        self.page_label_var.set(f"History: {current.strftime('%Y-%m-%d')} ({self.current_page_index + 1}/{total})")
        if self.current_page_index == 0:
            self.prev_page_btn.state(["disabled"])
        else:
            self.prev_page_btn.state(["!disabled"])
        if self.current_page_index >= total - 1:
            self.next_page_btn.state(["disabled"])
        else:
            self.next_page_btn.state(["!disabled"])

    def prev_page(self):
        if not self.page_dates:
            return
        if self.current_page_index <= 0:
            return
        self.current_page_index -= 1
        self.refresh_page_controls()
        if hasattr(self, "time_slider"):
            self.time_slider.set_val(0.0)

    def next_page(self):
        if not self.page_dates:
            return
        if self.current_page_index >= len(self.page_dates) - 1:
            return
        self.current_page_index += 1
        self.refresh_page_controls()
        if hasattr(self, "time_slider"):
            self.time_slider.set_val(0.0)

    def update_plot(self):
        self.ax_status.clear()
        self.ax_latency.clear()

        if not self.timestamps:
            self.canvas.draw()
            return

        self.update_pagination()

        # Determine visible window from slider + window size
        window_min = max(1, int(self.var_window_min.get()))
        window_min = min(window_min, 24 * 60)
        if window_min != self.var_window_min.get():
            self.var_window_min.set(window_min)
        window_delta = datetime.timedelta(minutes=window_min)

        t_all = list(self.timestamps)
        t_min = t_all[0]
        t_max = t_all[-1]

        index_list = self.get_page_indices(t_all)
        flags_list = list(self.problem_flags)

        t_page = [t_all[idx] for idx in index_list]
        if not t_page:
            self.canvas.draw()
            return

        flags_page = []
        for idx in index_list:
            if idx < len(flags_list):
                flags_page.append(flags_list[idx])
            else:
                flags_page.append(False)

        t_min = t_page[0]
        t_max = t_page[-1]
        # Update slider range to match available history (expressed in minutes)
        computed_slider_min = ((t_min + window_delta) - t_max).total_seconds() / 60.0
        slider_min_minutes = min(0.0, computed_slider_min)
        if slider_min_minutes == 0.0:
            slider_min_minutes = -1.0 / 60.0

        if (
            getattr(self.time_slider, "valmin", None) is None
            or self.time_slider.valmin != slider_min_minutes
            or self.time_slider.valmax != 0.0
        ):
            self.time_slider.valmin = slider_min_minutes
            self.time_slider.valmax = 0.0
            self.time_slider.ax.set_xlim(slider_min_minutes, 0.0)

        current_val = self.time_slider.val
        clamped_val = min(max(current_val, slider_min_minutes), 0.0)
        if clamped_val != current_val:
            self.time_slider.set_val(clamped_val)
            return

        offset_minutes = self.time_slider.val
        end_time = t_max + datetime.timedelta(minutes=offset_minutes)

        if end_time > t_max:
            end_time = t_max
        if end_time < t_min:
            end_time = t_min

        start_time = max(t_min, end_time - window_delta)
        end_time = start_time + window_delta
        if end_time > t_max:
            end_time = t_max
            start_time = max(t_min, end_time - window_delta)

        if hasattr(self.time_slider, "valtext"):
            self.time_slider.valtext.set_text(f"{self.time_slider.val:.1f} min")

        indices = [idx for idx, ts in enumerate(t_all) if start_time <= ts <= end_time]
        if not indices:
            indices = list(range(max(0, len(t_all) - 10), len(t_all)))
            start_time = t_all[indices[0]]
            end_time = t_all[indices[-1]]

        t_vis = [t_all[idx] for idx in indices]
        if not t_vis:
            # if no points in window, widen slightly around end
            t_vis = t_page[-min(len(t_page), 10):]
            start_time = t_vis[0]
            end_time = t_vis[-1]

        for i, ip in enumerate(self.internal_hops):
            color = self.hop_colors[i % len(self.hop_colors)]
            status_values = list(self.history.get(ip, []))
            latency_values = list(self.latency_history.get(ip, []))

            status_series = [status_values[idx] for idx in indices if idx < len(status_values)]

            latency_series = []
            for idx in indices:
                if idx >= len(latency_values):
                    latency_series.append(math.nan)
                else:
                    value = latency_values[idx]
                    if value is None or (isinstance(value, float) and math.isnan(value)):
                        latency_series.append(math.nan)
                    else:
                        latency_series.append(float(value))

            label = f"Hop {i + 1} ({ip})"
            self.ax_status.plot(t_vis, status_series, label=label, color=color, marker="o", linewidth=1.5)
            self.ax_latency.plot(t_vis, latency_series, color=color, marker="o", linewidth=1.2, label="_nolegend_")

        inet_status_values = list(self.internet_series)
        inet_latency_values = list(self.internet_latency_series)
        status_series = [inet_status_values[idx] for idx in indices if idx < len(inet_status_values)]

        latency_series = []
        for idx in indices:
            if idx >= len(inet_latency_values):
                latency_series.append(math.nan)
            else:
                value = inet_latency_values[idx]
                if value is None or (isinstance(value, float) and math.isnan(value)):
                    latency_series.append(math.nan)
                else:
                    latency_series.append(float(value))

        self.ax_status.plot(
            t_vis,
            status_series,
            label="Internet",
            color=self.internet_color,
            linestyle="--",
            marker="o",
            linewidth=1.8,
        )
        self.ax_latency.plot(t_vis, latency_series, color=self.internet_color, linestyle="--", marker="o", linewidth=1.4, label="_nolegend_")

        if self.extra_target:
            extra_status_values = list(self.extra_series)
            extra_latency_values = list(self.extra_latency_series)
            status_series = [extra_status_values[idx] for idx in indices if idx < len(extra_status_values)]

            latency_series = []
            for idx in indices:
                if idx >= len(extra_latency_values):
                    latency_series.append(math.nan)
                else:
                    value = extra_latency_values[idx]
                    if value is None or (isinstance(value, float) and math.isnan(value)):
                        latency_series.append(math.nan)
                    else:
                        latency_series.append(float(value))

            self.ax_status.plot(
                t_vis,
                status_series,
                label=f"Extra ({self.extra_target})",
                color=self.extra_color,
                linestyle=":",
                marker="o",
                linewidth=1.6,
            )
            self.ax_latency.plot(
                t_vis,
                latency_series,
                color=self.extra_color,
                linestyle=":",
                marker="o",
                linewidth=1.2,
                label="_nolegend_",
            )

        self.ax_status.set_ylim(-0.1, 1.1)
        self.ax_status.set_yticks([0, 1])
        self.ax_status.set_yticklabels(["Down", "Up"])
        self.ax_status.grid(axis="y", linestyle="--", alpha=0.3)
        legend = self.ax_status.legend(
            loc="center left",
            bbox_to_anchor=(1.02, 0.5),
            borderaxespad=0,
            framealpha=0.7,
            ncol=1,
            title="Connecties",
        )

        # Make space on the right for legend while keeping the enlarged bottom
        # margin that separates the x-axis labels from the slider.
        bottom_margin = getattr(self, "figure_bottom_margin", 0.11)
        self.fig.subplots_adjust(right=0.8, bottom=bottom_margin, hspace=0.25)
        self.position_time_slider()

        self.fig.subplots_adjust(right=0.8, hspace=0.25)

        extra_suffix = " + extra host" if self.extra_target else ""
        self.ax_status.set_title(f"Connectiviteit ({len(self.internal_hops)} interne hop(s){extra_suffix})")
        self.ax_status.set_ylabel("Status (Up/Down)")

        self.ax_latency.set_title("Latency-overzicht")
        self.ax_latency.set_ylabel("Latency (ms)")
        self.ax_latency.grid(True, linestyle="--", alpha=0.3)
        self.ax_latency.set_xlabel("Tijd")

        import matplotlib.dates as mdates

        self.ax_latency.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        self.ax_latency.xaxis.set_minor_formatter(mdates.DateFormatter('%d/%m\n%H:%M'))
        self.fig.autofmt_xdate(rotation=45)

        x_left, x_right = start_time, end_time
        if x_left == x_right:
            pad = datetime.timedelta(seconds=30)
            x_left -= pad
            x_right += pad
        self.ax_status.set_xlim(x_left, x_right)

        self.update_slider_markers(t_page, t_max, flags_page)
        self.canvas.draw_idle()

    def position_time_slider(self):
        if not hasattr(self, "slider_ax"):
            return
        axes_box = self.ax_latency.get_position()
        max_bottom = axes_box.y0 - self.slider_height - self.slider_gap
        slider_bottom = self.slider_min_bottom
        if max_bottom < slider_bottom:
            slider_bottom = max(0.0, max_bottom)
        self.slider_ax.set_position([axes_box.x0, slider_bottom, axes_box.width, self.slider_height])

    def format_elapsed(self, delta):
        seconds = max(0, int(delta.total_seconds()))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        if hours:
            parts.append(f"{hours}h")
        if minutes or hours:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        return " ".join(parts)

    def update_stats_label(self):
        elapsed = (
            now_ts() - self.start_time if hasattr(self, "start_time") and self.start_time else datetime.timedelta(0)
        )
        elapsed_str = self.format_elapsed(elapsed)
        lines = [f"Measurements: {self.total_measurements} | Runtime: {elapsed_str}"]

        def pct_text(up_count, total_count):
            down_count = max(0, total_count - up_count)
            if total_count <= 0:
                return "0.0% up (0) / 0.0% down (0)"
            up_pct = (up_count / total_count) * 100
            down_pct = 100 - up_pct
            return f"{up_pct:.1f}% up ({up_count}) / {down_pct:.1f}% down ({down_count})"
        summary_parts = [f"Metingen: {self.total_measurements}", f"Tijd: {elapsed_str}"]

        if self.timestamps:
            summary_parts.append(f"Laatste meting: {fmt_time(self.timestamps[-1])}")

        outages = sum(self.problem_flags) if self.problem_flags else 0
        summary_parts.append(f"Storingen gedetecteerd: {outages}")

        self.summary_label.config(text=" | ".join(summary_parts))

        def sanitize_latency_values(values):
            clean = []
            for value in values:
                if value is None:
                    continue
                if isinstance(value, float) and math.isnan(value):
                    continue
                clean.append(float(value))
            return clean

        def latest_latency(values):
            for value in reversed(values):
                if value is None:
                    continue
                if isinstance(value, float) and math.isnan(value):
                    continue
                return float(value)
            return None

        for idx, ip in enumerate(self.internal_hops, start=1):
            widgets = self.stat_rows.get(ip)
            if not widgets:
                continue

            widgets["label"].config(text=f"Hop {idx} ({ip})")

            series = list(self.history.get(ip, []))
            total = len(series)
            up = sum(series) if total else 0
            up_pct = (up / total * 100) if total else 0
            widgets["progress"]["value"] = up_pct

            latency_series = list(self.latency_history.get(ip, []))
            clean_latency = sanitize_latency_values(latency_series)
            avg_latency = sum(clean_latency) / len(clean_latency) if clean_latency else None
            latest = latest_latency(latency_series)

            latency_bits = []
            if avg_latency is not None:
                latency_bits.append(f"avg {avg_latency:.1f} ms")
            if latest is not None:
                latency_bits.append(f"laatste {latest:.1f} ms")
            latency_text = " | ".join(latency_bits) if latency_bits else "geen data"

            widgets["value"].config(text=f"{up_pct:.1f}% up | {latency_text}")

        inet_widgets = self.stat_rows.get("Internet")
        if inet_widgets:
            inet_widgets["label"].config(text=f"Internet ({self.internet_ip})")
            inet_series = list(self.internet_series)
            total = len(inet_series)
            up = sum(inet_series) if total else 0
            up_pct = (up / total * 100) if total else 0
            inet_widgets["progress"]["value"] = up_pct

            inet_latency_series = list(self.internet_latency_series)
            clean_latency = sanitize_latency_values(inet_latency_series)
            avg_latency = sum(clean_latency) / len(clean_latency) if clean_latency else None
            latest = latest_latency(inet_latency_series)

            latency_bits = []
            if avg_latency is not None:
                latency_bits.append(f"avg {avg_latency:.1f} ms")
            if latest is not None:
                latency_bits.append(f"laatste {latest:.1f} ms")
            latency_text = " | ".join(latency_bits) if latency_bits else "geen data"

            inet_widgets["value"].config(text=f"{up_pct:.1f}% up | {latency_text}")

        extra_widgets = self.stat_rows.get("Extra")
        if extra_widgets and self.extra_target:
            extra_widgets["label"].config(text=f"Extra ({self.extra_target})")
            extra_series = list(self.extra_series)
            total = len(extra_series)
            up = sum(extra_series) if total else 0
            up_pct = (up / total * 100) if total else 0
            extra_widgets["progress"]["value"] = up_pct

            extra_latency_series = list(self.extra_latency_series)
            clean_latency = sanitize_latency_values(extra_latency_series)
            avg_latency = sum(clean_latency) / len(clean_latency) if clean_latency else None
            latest = latest_latency(extra_latency_series)

            latency_bits = []
            if avg_latency is not None:
                latency_bits.append(f"avg {avg_latency:.1f} ms")
            if latest is not None:
                latency_bits.append(f"laatste {latest:.1f} ms")
            latency_text = " | ".join(latency_bits) if latency_bits else "geen data"

            extra_widgets["value"].config(text=f"{up_pct:.1f}% up | {latency_text}")

        try:
            self.root.update_idletasks()
        except Exception:
            pass

def safe_exit(app, root):
    """Gracefully stop background thread and close the GUI."""
    if not getattr(app, "running", False):
        return  # already shutting down

    app.running = False
    print("👋 Exiting Network Monitor cleanly.")

    try:
        # Cancel pending after() jobs if any
        for job in getattr(app, "_after_jobs", []):
            try:
                root.after_cancel(job)
            except Exception:
                pass

        # Stop the GUI event loop safely
        if root.winfo_exists():
            root.quit()
            root.update_idletasks()
            root.destroy()

    except Exception:
        pass

    # Ensure Python process ends even if Tkinter thread lingers
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)


def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)

    def on_close():
        try:
            app.save_settings()
        except Exception:
            pass
        # Call safe_exit asynchronously to avoid “invalid command name” after WM_DELETE
        root.after(50, lambda: safe_exit(app, root))

    root.protocol("WM_DELETE_WINDOW", on_close)

    signal.signal(signal.SIGINT, lambda *_: safe_exit(app, root))

    try:
        root.mainloop()
    except KeyboardInterrupt:
        safe_exit(app, root)

if __name__ == "__main__":
    main()

