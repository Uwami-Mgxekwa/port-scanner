# Port Scanner

A lightweight network port scanner that checks which ports are open on a target machine, identifies the services running on them, and generates a clean HTML report with risk levels and remediation advice.

## Usage

```bash
python scanner.py --target 127.0.0.1 --start 1 --end 1024
```

| Argument | Default | Description |
|---|---|---|
| `--target` | required | IP address or hostname to scan |
| `--start` | 1 | First port in range |
| `--end` | 1024 | Last port in range |
| `--threads` | 100 | Concurrent threads |
| `--timeout` | 1.0 | Seconds per port |

## Quick Run

| File | Platform |
|---|---|
| `run_scanner.bat` | Windows |
| `run_scanner.ps1` | PowerShell |
| `run_scanner.sh` | Linux / macOS |

After each scan a `report.html` file is saved and opened automatically in your browser.

## Report Includes

- Open ports with service names and risk levels
- Risk breakdown chart
- Per-port remediation advice
- Full scan details

> Only scan systems you own or have explicit permission to test.

---

Powered by [brelinx.com](https://brelinx.com)
