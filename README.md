# Network Monitor 🛰️  
Multi-hop Network Connectivity and Latency Visualizer

---

## Overview
**Network Monitor** is a lightweight Python utility that continuously checks the connectivity between your computer, all internal network hops (routers, firewalls, modems), and the public Internet.  
It displays real-time results in both a terminal and a graphical interface with dynamic charts and logging.

Originally built for troubleshooting double-NAT and mesh Wi-Fi setups, it works equally well on simple single-router networks.

---

## ✨ Features
- **Automatic hop detection** using PowerShell `Test-NetConnection` (Windows) or `traceroute` (Unix/macOS).
- **Monitors all private IP hops** (e.g., 192.168.x.x, 10.x.x.x, 172.16–31.x.x).
- **First public hop** (e.g., your ISP gateway) is treated as the *Internet*.
- **Real-time graph**:
  - Each internal hop in a unique color.
  - Internet link shown as a **light blue dashed line** (cloud color).
  - Live status updates (Up/Down) every few seconds.
- **Console + GUI logging** with colored status messages.
- **Automatic CSV/TXT logging** of all results.
- **Export graph to PNG** with a “Save As…” dialog.
- Works on **Windows, macOS, and Linux**.

---

## 🧰 Requirements

**Python:** 3.9 or higher  
**Modules:**

```bash
pip install matplotlib
```

**System tools:**
- On Windows: PowerShell must be available (default)
- On Linux/macOS: `traceroute` command must be installed

---

## 🚀 Usage

1. **Clone the repository:**

   ```bash
   git clone https://github.com/SoltechNV/Network-Monitor.git
   cd Network-Monitor
   ```

2. **Run the tool:**

   ```bash
   python network_monitor_v3_5.py
   ```

3. The GUI will:
   - Detect your connection type (Wi-Fi / LAN)
   - Discover all hops
   - Start live monitoring and graph updates every 5 seconds

4. Use the **📸 Export Graph to PNG** button to save a snapshot of the chart.

---

## 🖼️ Example Screenshot
*(Replace this placeholder once you have a screenshot.)*

![Network Monitor GUI Example](screenshot.png)

---

## 🗂️ Log Files
- `network_log_YYYY-MM-DD_HH-MM-SS.txt` — human-readable event log
- `network_log_YYYY-MM-DD_HH-MM-SS.csv` — machine-readable data log for spreadsheets

Fresh log files are created in the same directory as the script every time the
application starts, and again whenever you press the **🔄 Reset** button. This
keeps each monitoring session neatly separated.

---

## 🧠 Status Indicators
| Symbol | Meaning |
|---------|----------|
| ✅ | All good — connection stable |
| ❌ | First hop unreachable — local LAN issue |
| 🟠 | Intermediate hop down — router/modem issue |
| 🔴 | Internet down — ISP or DNS problem |
| ⚠️ | Indeterminate state |

---

## 🧩 Example Output (console)
```
[17:42:15] 192.168.1.1:True | 192.168.5.1:True | Internet:True → ✅ All good — connection stable
[17:42:20] 192.168.1.1:True | 192.168.5.1:False | Internet:False → 🟠 Hop 2 (192.168.5.1) down — intermediate router issue
```

---

## 📦 Exported Graph
When you press **📸 Export Graph to PNG**, a “Save As…” dialog lets you choose a filename and folder.  
The file will be saved as a clean graph snapshot with all hop histories.

---

## ⚖️ License
MIT License — feel free to modify, share, and improve this tool.

---

## 👨‍💻 Author
**Ronny Franken**  

---

*Troubleshooting your LAN has never been this visual.*
