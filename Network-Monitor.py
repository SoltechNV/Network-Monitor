#!/usr/bin/env python3
# Network Monitor v3.5 — English + Export Edition
# ------------------------------------------------
# - Detects ALL internal (private) hops via PowerShell Test-NetConnection (Windows) or traceroute.
# - Pings every internal hop + the first public hop (“Internet”), logs to TXT/CSV, and draws a live chart.
# - Clear status (green/orange/red) in console & GUI.
# - Internet line is light-blue dashed; each internal hop gets its own contrasting color.
# - “Save As…” button exports the current graph as a PNG.
#
# Requirements:
#   Python 3.9+ (tested), tkinter, matplotlib
#   On macOS/Linux: traceroute
#   On Windows: PowerShell available (default)
#
# Run:
#   pip install matplotlib
#   python network_monitor_v3_5.py

import subprocess, time, datetime, platform, threading, re, csv, shutil, os
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import deque

# ---------------- Configuration ----------------
LOG_TXT = "network_log.txt"
LOG_CSV = "network_log.csv"
PING_INTERVAL = 5                 # seconds between measurements
PING_TIMEOUT = 2                  # ping timeout per probe
DEFAULT_INTERNET_FALLBACK = "1.1.1.1"
MAX_POINTS = 60                   # points shown in the graph
TRACEROUTE_TIMEOUT = 25           # generous to avoid timeouts on corp networks
# ------------------------------------------------

def run_cmd(cmd, timeout=None, shell=False):
    """Run a command and capture stdout/stderr as text."""
    return subprocess.run(
        cmd if not shell else " ".join(cmd),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout, shell=shell
    )

def is_private_ip(ip: str) -> bool:
    """Classify RFC1918 private IPv4 ranges: 10/8, 172.16-31/12, 192.168/16."""
    try:
        a, b, c, d = [int(x) for x in ip.split(".")]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
    except Exception:
        pass
    return False

def ping(host: str) -> bool:
    """Single ping with OS-appropriate flags."""
    if not host:
        return True
    is_win = platform.system().lower() == "windows"
    count_flag = "-n" if is_win else "-c"
    timeout_flag = "-w" if is_win else "-W"
    try:
        res = run_cmd(["ping", count_flag, "1", timeout_flag, str(PING_TIMEOUT), host])
        return res.returncode == 0
    except Exception:
        return False

def detect_connection_type() -> str:
    """Return 'Wi-Fi (...)', 'LAN', or 'Unknown'."""
    sysn = platform.system().lower()
    try:
        if sysn == "windows":
            r = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=3)
            if "State" in r.stdout and re.search(r"State\s*:\s*connected", r.stdout, re.I):
                m = re.search(r"SSID\s*:\s*(.+)", r.stdout, re.I)
                return "Wi-Fi" + (f" ({m.group(1).strip()})" if m else "")
            return "LAN"
        if sysn == "linux":
            if shutil.which("iwgetid"):
                r = run_cmd(["iwgetid", "-r"], timeout=2)
                if r.returncode == 0 and r.stdout.strip():
                    return f"Wi-Fi ({r.stdout.strip()})"
                return "LAN"
            if shutil.which("nmcli"):
                r = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], timeout=3)
                for line in r.stdout.splitlines():
                    p = line.split(":")
                    if len(p) >= 4 and p[1] == "wifi" and p[2] == "connected":
                        return f"Wi-Fi ({p[3]})"
                return "LAN"
            return "Unknown"
        if sysn == "darwin":  # macOS
            if shutil.which("networksetup"):
                r = run_cmd(["networksetup", "-getairportnetwork", "en0"], timeout=3)
                if "Current Wi-Fi Network" in r.stdout:
                    ssid = r.stdout.strip().split(":")[-1].strip()
                    return f"Wi-Fi ({ssid})"
                return "LAN"
            return "Unknown"
    except Exception:
        return "Unknown"
    return "Unknown"

IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

def parse_ps_traceroute(text: str):
    """
    Parse IPs from PowerShell Test-NetConnection -TraceRoute output.
    Specifically includes IPs on the same line as 'TraceRoute : ...'
    and excludes SourceAddress, 0.0.0.0, duplicates.
    """
    # SourceAddress (exclude)
    src = None
    m_src = re.search(r"SourceAddress\s*:\s*(\d+\.\d+\.\d+\.\d+)", text, re.I)
    if m_src:
        src = m_src.group(1)

    # Grab everything from 'TraceRoute :' to the end
    m_tr = re.search(r"TraceRoute\s*:\s*(.*)$", text, re.I | re.M)
    hops = []
    if m_tr:
        # First, IPs on the same line after the colon:
        same_line = m_tr.group(1)
        hops.extend(IP_RE.findall(same_line))
        # Then, all remaining lines after that match:
        start = m_tr.end()
        tail = text[start:]
        hops.extend(IP_RE.findall(tail))
    else:
        # Fallback: any IPs after a line containing 'TraceRoute'
        m_any = re.search(r"TraceRoute", text, re.I)
        if m_any:
            tail = text[m_any.end():]
            hops.extend(IP_RE.findall(tail))

    # Clean: remove dest echo (we’ll treat first public separately), 0.0.0.0, src, duplicates in order
    cleaned = []
    for ip in hops:
        if ip == "0.0.0.0" or ip == src:
            continue
        if not cleaned or cleaned[-1] != ip:
            cleaned.append(ip)
    return cleaned

def parse_tracert(text: str):
    """
    Parse classic 'tracert' (Windows) or 'traceroute' (Unix) formatted lines.
    Takes the rightmost IP on hop lines, skips 0.0.0.0 and duplicates.
    """
    hops = []
    for line in text.splitlines():
        if re.match(r"^\s*\d+\s", line):  # starts with hop number
            ips = IP_RE.findall(line)
            if ips:
                ip = ips[-1]
                if ip != "0.0.0.0" and (not hops or hops[-1] != ip):
                    hops.append(ip)
    # If no numbered hop lines (some traceroute variants), fallback to any IP order:
    if not hops:
        rough = IP_RE.findall(text)
        for ip in rough:
            if ip != "0.0.0.0" and (not hops or hops[-1] != ip):
                hops.append(ip)
    return hops

def get_gateway_fallback_list():
    """Fallback: return [default_gateway] if traceroute fails."""
    sysn = platform.system().lower()
    try:
        if sysn == "windows":
            r = run_cmd(["ipconfig"], timeout=5, shell=True)
            m = re.search(r"Default Gateway[ .:]+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return [m.group(1)]
        else:
            r = run_cmd(["ip", "route"], timeout=5)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return [m.group(1)]
    except Exception:
        pass
    return []

def traceroute_windows():
    """Windows route discovery: PowerShell Test-NetConnection → tracert → gateway fallback."""
    # 1) PowerShell
    try:
        r = run_cmd(["powershell", "-NoProfile", "-Command",
                     f"Test-NetConnection {DEFAULT_INTERNET_FALLBACK} -TraceRoute | Out-String"],
                    timeout=TRACEROUTE_TIMEOUT)
        if r.returncode == 0 and r.stdout:
            print("📡 PowerShell Test-NetConnection output:\n" + r.stdout)
            hops = parse_ps_traceroute(r.stdout)
            if hops:
                return hops
    except subprocess.TimeoutExpired:
        print("⚠️ PowerShell TraceRoute timed out.")
    except Exception as e:
        print(f"⚠️ PowerShell TraceRoute error: {e}")

    # 2) tracert
    for cmd in ([["tracert", "-4", "-d", DEFAULT_INTERNET_FALLBACK]],
                [["tracert", "-4", DEFAULT_INTERNET_FALLBACK]]):
        try:
            res = run_cmd(cmd, timeout=TRACEROUTE_TIMEOUT, shell=True)
            out = res.stdout or res.stderr
            if out:
                print(f"📡 tracert output ({' '.join(cmd[0])}):\n{out}")
                hops = parse_tracert(out)
                if hops:
                    return hops
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout from: {' '.join(cmd[0])}")
        except Exception as e:
            print(f"⚠️ tracert error: {e}")

    # 3) Default gateway fallback
    gw_list = get_gateway_fallback_list()
    if gw_list:
        print(f"✅ Fallback gateway: {gw_list[0]}")
        return gw_list
    return []

def traceroute_unix():
    """Unix route discovery: traceroute → gateway fallback."""
    for cmd in (["traceroute", "-n", "-w", "2", "-q", "1", DEFAULT_INTERNET_FALLBACK],
                ["traceroute", "-n", DEFAULT_INTERNET_FALLBACK],
                ["traceroute", DEFAULT_INTERNET_FALLBACK]):
        try:
            res = run_cmd(cmd, timeout=TRACEROUTE_TIMEOUT)
            out = res.stdout or res.stderr
            if out:
                print(f"📡 traceroute output ({' '.join(cmd)}):\n{out}")
                hops = parse_tracert(out)
                if hops:
                    return hops
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout from: {' '.join(cmd)}")
        except Exception as e:
            print(f"⚠️ traceroute error: {e}")
    gw_list = get_gateway_fallback_list()
    if gw_list:
        print(f"✅ Fallback gateway: {gw_list[0]}")
        return gw_list
    return []

def detect_route():
    """
    Return (internal_hops_list, first_public_ip)
    - internal_hops_list: all private hops (in order)
    - first_public_ip: first non-private hop, or DEFAULT_INTERNET_FALLBACK if not found
    """
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

def now_ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def init_csv(header_ips):
    """Write CSV header dynamically: timestamp, <hop ips...>, Internet, status."""
    with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp"] + header_ips + ["Internet", "status"])

def log_line_to_files(ts, hop_results, internet_ok, status):
    """
    hop_results: Ordered list of tuples [(ip, ok), ...] to preserve hop order.
    """
    parts = [f"{ip}:{'True' if ok else 'False'}" for ip, ok in hop_results]
    line = f"[{ts}] " + " | ".join(parts) + f" | Internet:{internet_ok} → {status}"
    # TXT
    with open(LOG_TXT, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    # CSV
    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        row = [ts] + [ok for _, ok in hop_results] + [internet_ok, status]
        writer.writerow(row)
    return line

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor — Multi-Hop Edition")
        self.root.geometry("1200x760")

        # Top status bar
        self.status_label = ttk.Label(root, text="Initializing...", font=("Segoe UI", 14))
        self.status_label.pack(pady=(10, 0))

        # Connection type
        self.conn_type_label = ttk.Label(root, text="", font=("Segoe UI", 10))
        self.conn_type_label.pack(pady=(2, 8))

        # Buttons row (Export)
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=(0, 8))
        self.export_btn = ttk.Button(btn_frame, text="📸 Export Graph to PNG", command=self.export_graph)
        self.export_btn.pack()

        # Log window
        self.textbox = scrolledtext.ScrolledText(root, height=14, width=150, state="disabled")
        self.textbox.pack(padx=10, pady=10)

        # Plot
        self.fig, self.ax = plt.subplots(figsize=(10, 3.5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Time axis
        self.timestamps = deque(maxlen=MAX_POINTS)

        # Colors for internal hops; Internet in light-blue dashed
        self.hop_colors = ["tab:blue", "tab:orange", "tab:purple", "tab:brown", "tab:pink", "tab:gray", "tab:olive", "tab:cyan"]
        self.internet_color = "skyblue"

        # Connection type
        self.conn_type = detect_connection_type()
        print(f"📶 Link type: {self.conn_type}")
        self.conn_type_label.config(text=f"Link type: {self.conn_type}")

        # Detect route (once)
        self.internal_hops, self.internet_ip = detect_route()
        print(f"🌐 Targets: {self.internal_hops} → Internet={self.internet_ip}")
        self.append_gui(f"Targets → {', '.join(self.internal_hops)} → Internet={self.internet_ip}")

        # Dynamic histories: one deque per hop + one for internet
        self.history = {ip: deque(maxlen=MAX_POINTS) for ip in self.internal_hops}
        self.history["_internet"] = deque(maxlen=MAX_POINTS)

        # Prepare CSV header with dynamic hop IPs
        init_csv(self.internal_hops)

        self.running = True
        threading.Thread(target=self.monitor_loop, daemon=True).start()

    # ---------- UI helpers ----------
    def append_gui(self, msg, color=None):
        self.textbox.configure(state="normal")
        self.textbox.insert(tk.END, msg + "\n")
        self.textbox.configure(state="disabled")
        self.textbox.yview(tk.END)
        if color:
            self.status_label.config(foreground=color, text=msg)
        self.root.update_idletasks()

    def export_graph(self):
        """Save current graph as PNG (graph only)."""
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default_name = f"network_graph_{ts}.png"
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
            initialfile=default_name,
            title="Save Graph As..."
        )
        if not path:
            return
        try:
            self.fig.savefig(path, dpi=150, bbox_inches="tight")
            messagebox.showinfo("Export", f"Graph saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save PNG:\n{e}")

    def update_chart(self):
        self.ax.clear()
        # plot each internal hop
        for i, ip in enumerate(self.internal_hops):
            col = self.hop_colors[i % len(self.hop_colors)]
            self.ax.plot(self.timestamps, self.history[ip], label=f"Hop {i+1} ({ip})",
                         color=col, marker="o", linewidth=1.5)
        # plot internet as dashed skyblue
        self.ax.plot(self.timestamps, self.history["_internet"], label="Internet",
                     color=self.internet_color, linestyle="--", marker="o", linewidth=1.8)

        self.ax.set_ylim(-0.1, 1.1)
        self.ax.set_yticks([0, 1])
        self.ax.set_yticklabels(["Down", "Up"])
        self.ax.legend(loc="upper left", ncol=2)
        self.ax.set_title(f"Connection history ({len(self.internal_hops)} internal hop(s))")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Status (Up/Down)")
        self.fig.autofmt_xdate(rotation=45)
        self.canvas.draw()

    # ---------- Classification ----------
    def classify(self, hop_results, internet_ok):
        """
        hop_results: list of (ip, ok) in hop order (Hop 1, Hop 2, ...)
        """
        all_internal_ok = all(ok for _, ok in hop_results)
        first_hop_ok = hop_results[0][1] if hop_results else True

        if all_internal_ok and internet_ok:
            return "✅ All good — connection stable", "green"
        if not first_hop_ok:
            return "❌ First hop down — local LAN issue", "red"
        # If any intermediate hop is down:
        for idx, (ip, ok) in enumerate(hop_results, start=1):
            if not ok:
                return f"🟠 Hop {idx} ({ip}) down — intermediate router issue", "orange"
        if not internet_ok:
            return "🔴 Internet down — ISP/DNS issue", "red"
        return "⚠️ Indeterminate state", "gray"

    # ---------- Main monitor loop ----------
    def monitor_loop(self):
        while self.running:
            # Probe all internal hops in order
            hop_results = []
            for ip in self.internal_hops:
                ok = ping(ip)
                hop_results.append((ip, ok))
            # Probe internet (first public hop)
            internet_ok = ping(self.internet_ip)

            ts = now_ts()
            status, color = self.classify(hop_results, internet_ok)

            # Console + files
            line = log_line_to_files(ts, hop_results, internet_ok, status)
            print(line)

            # GUI text
            self.append_gui(line, color)

            # Update histories
            self.timestamps.append(ts)
            for ip, ok in hop_results:
                self.history[ip].append(1 if ok else 0)
            self.history["_internet"].append(1 if internet_ok else 0)

            # Redraw chart
            self.update_chart()

            time.sleep(PING_INTERVAL)

def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: setattr(app, "running", False) or root.destroy())
    root.mainloop()

if __name__ == "__main__":
    main()
