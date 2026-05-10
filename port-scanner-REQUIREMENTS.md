# 🔍 Port Scanner — System Requirements

## Overview

**Tool Name:** Port Scanner  
**Repository:** `cyber-toolkit/port-scanner`  
**Language:** Python  
**Purpose:** A lightweight, multi-threaded port scanner for demonstrating how attackers enumerate open ports on a target machine. Built for ethical hacking education.

---

## Operating System Support

| OS | Supported |
|---|---|
| Windows 10 / 11 | ✅ |
| Ubuntu 20.04+ | ✅ |
| Kali Linux | ✅ Recommended |
| macOS 12+ | ✅ |

---

## Python Version

| Requirement | Version |
|---|---|
| Minimum | Python 3.8 |
| Recommended | Python 3.11+ |

Check your version:
```bash
python --version
```

Download Python: https://www.python.org/downloads/

---

## Dependencies

### ✅ No external libraries required
The port scanner uses **only Python built-in libraries:**

| Library | Purpose |
|---|---|
| `socket` | Connect to ports and resolve hostnames |
| `threading` | Scan multiple ports simultaneously |
| `argparse` | Accept command-line arguments (target, port range) |
| `datetime` | Timestamp scan start and end times |
| `queue` | Manage threaded port queue |
| `colorama` | ⚠️ Optional — colored terminal output |

> If you want colored output install colorama:
> ```bash
> pip install colorama
> ```

---

## Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| RAM | 512 MB | 2 GB+ |
| Storage | 5 MB | 10 MB |
| CPU | Single Core | Dual Core+ (benefits threading) |
| Network | Any NIC | Ethernet for accuracy |

---

## Network Requirements

> ⚠️ **Only scan machines you own or have written permission to scan.**
> Unauthorized port scanning is illegal in most countries.

| Target Type | Allowed |
|---|---|
| `localhost` / `127.0.0.1` | ✅ Always safe |
| Your own lab VM | ✅ Safe |
| Your own server | ✅ With caution |
| Any external/public IP | ❌ Illegal without permission |

### Recommended Lab Setup
- Run a **VirtualBox** or **VMware** virtual machine as the target
- Scan between two VMs on a **host-only network**
- Use **Kali Linux** as the attacker and **Ubuntu/Metasploitable** as the target

---

## Permissions

| Action | Requires Admin/Root |
|---|---|
| Scan ports above 1024 | ❌ No |
| Scan ports below 1024 (system ports) | ✅ Yes on Linux/macOS |
| Run on Windows | ❌ No (standard user is fine) |

**Linux/macOS — run with sudo for system ports:**
```bash
sudo python scanner.py --target 127.0.0.1 --start 1 --end 1024
```

**Windows — standard terminal is fine:**
```powershell
python scanner.py --target 127.0.0.1 --start 1 --end 1024
```

---

## Recommended Tools Alongside Port Scanner

| Tool | Purpose | Link |
|---|---|---|
| VS Code | Edit and run the script | https://code.visualstudio.com |
| Nmap | Compare scan results with yours | https://nmap.org |
| Wireshark | See the packets your scanner sends | https://www.wireshark.org |
| VirtualBox | Isolated target machine for demos | https://www.virtualbox.org |
| Metasploitable 2 | Intentionally vulnerable target VM | https://sourceforge.net/projects/metasploitable |

---

## File Structure

```
cyber-toolkit/
└── port-scanner/
    ├── scanner.py        # Main scanner script
    ├── requirements.txt  # Only colorama (optional)
    └── README.md         # Usage instructions
```

---

## Installation & Usage

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/cyber-toolkit.git

# 2. Navigate to port scanner
cd cyber-toolkit/port-scanner

# 3. (Optional) Install colorama for colored output
pip install colorama

# 4. Run the scanner
python scanner.py --target 127.0.0.1 --start 1 --end 1000
```

### CLI Arguments

| Argument | Description | Example |
|---|---|---|
| `--target` | IP address or hostname to scan | `127.0.0.1` |
| `--start` | Starting port number | `1` |
| `--end` | Ending port number | `1000` |
| `--threads` | Number of threads (default: 100) | `200` |
| `--timeout` | Socket timeout in seconds (default: 1) | `0.5` |

### Example Commands

```bash
# Scan localhost ports 1–1000
python scanner.py --target 127.0.0.1 --start 1 --end 1000

# Scan a lab VM with 200 threads for speed
python scanner.py --target 192.168.1.10 --start 1 --end 65535 --threads 200

# Scan with a shorter timeout for faster results
python scanner.py --target 192.168.1.10 --start 1 --end 1000 --timeout 0.5
```

---

## Expected Output

```
====================================
 🔍 Port Scanner — Cyber Toolkit
====================================
 Target  : 127.0.0.1
 Range   : 1 - 1000
 Threads : 100
 Started : 2025-01-01 10:00:00
====================================

[OPEN]  Port 22   — SSH
[OPEN]  Port 80   — HTTP
[OPEN]  Port 443  — HTTPS
[OPEN]  Port 3306 — MySQL

====================================
 Scan Complete — 4 open ports found
 Duration: 3.42 seconds
====================================
```

---

## ⚠️ Legal Disclaimer

This tool is built **strictly for educational purposes.**
Only use it on systems you own or have explicit written permission to test.
The author is not responsible for any misuse of this tool.

---

## Classroom Usage Notes

- Demo on `localhost` first so students see results immediately
- Use **Metasploitable 2** as a target VM — it has many open ports by design
- Compare results with **Nmap** to show students how professional tools work
- Discuss why open ports are a security risk and how firewalls mitigate them
