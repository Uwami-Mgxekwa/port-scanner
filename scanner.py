#!/usr/bin/env python3
# =============================================================================
#  🔍 Port Scanner — Cyber Toolkit
#  Author  : Your Name
#  Repo    : github.com/yourusername/cyber-toolkit
#  Usage   : python scanner.py --target 127.0.0.1 --start 1 --end 1000
#  Warning : Only scan systems you own or have permission to test.
# =============================================================================

import socket
import threading
import argparse
from queue import Queue
from datetime import datetime

# ── Optional: colored output ──────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN  = Fore.GREEN
    RED    = Fore.RED
    CYAN   = Fore.CYAN
    YELLOW = Fore.YELLOW
    RESET  = Style.RESET_ALL
except ImportError:
    GREEN = RED = CYAN = YELLOW = RESET = ""

# ── Common ports & their service names ───────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ── Globals ───────────────────────────────────────────────────────────────────
open_ports = []
lock       = threading.Lock()
queue      = Queue()


# ── Banner ────────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{CYAN}====================================
  🔍  Port Scanner — Cyber Toolkit
===================================={RESET}""")


# ── Print scan info before starting ──────────────────────────────────────────
def print_scan_info(target, start, end, threads):
    print(f"{YELLOW} Target  :{RESET} {target}")
    print(f"{YELLOW} Range   :{RESET} {start} - {end}")
    print(f"{YELLOW} Threads :{RESET} {threads}")
    print(f"{YELLOW} Started :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{CYAN}===================================={RESET}\n")


# ── Scan a single port ────────────────────────────────────────────────────────
def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            with lock:
                open_ports.append((port, service))
                print(f"{GREEN}[OPEN]{RESET}  Port {port:<6} — {service}")

    except socket.error:
        pass


# ── Worker thread: pulls ports from the queue ─────────────────────────────────
def worker(target, timeout):
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, timeout)
        queue.task_done()


# ── Fill the queue with ports to scan ─────────────────────────────────────────
def fill_queue(start, end):
    for port in range(start, end + 1):
        queue.put(port)


# ── Print results summary ─────────────────────────────────────────────────────
def print_results(start_time):
    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n{CYAN}===================================={RESET}")

    if open_ports:
        print(f"{GREEN} Scan Complete — {len(open_ports)} open port(s) found{RESET}")
    else:
        print(f"{RED} Scan Complete — No open ports found{RESET}")

    print(f"{YELLOW} Duration: {duration:.2f} seconds{RESET}")
    print(f"{CYAN}===================================={RESET}\n")

    if open_ports:
        print(f"{CYAN} Open Ports Summary:{RESET}")
        print(f" {'Port':<10} {'Service'}")
        print(f" {'-'*25}")
        for port, service in sorted(open_ports):
            print(f" {str(port):<10} {service}")
        print()


# ── Resolve hostname to IP ────────────────────────────────────────────────────
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"{YELLOW} Resolved :{RESET} {target} → {ip}\n")
        return ip
    except socket.gaierror:
        print(f"{RED} [ERROR] Could not resolve host: {target}{RESET}")
        exit(1)


# ── Argument parser ───────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 Cyber Toolkit — Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP address or hostname\nExample: 127.0.0.1 or scanme.nmap.org"
    )
    parser.add_argument(
        "--start", type=int, default=1,
        help="Starting port number (default: 1)"
    )
    parser.add_argument(
        "--end", type=int, default=1024,
        help="Ending port number (default: 1024)"
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Number of threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    print_banner()

    # Resolve the target
    target = resolve_target(args.target)

    # Validate port range
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print(f"{RED} [ERROR] Invalid port range. Use 1–65535.{RESET}")
        exit(1)

    print_scan_info(target, args.start, args.end, args.threads)

    start_time = datetime.now()

    # Fill queue with ports
    fill_queue(args.start, args.end)

    # Launch threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(target, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # Print summary
    print_results(start_time)


if __name__ == "__main__":
    main()