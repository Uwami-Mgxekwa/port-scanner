import socket
import threading
import argparse
import json
import os
import webbrowser
from queue import Queue
from datetime import datetime

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

PORT_ADVICE = {
    21:   {
        "title": "FTP — File Transfer Protocol",
        "risk": "High",
        "description": "FTP transmits data and credentials in plain text, making it easy to intercept.",
        "steps": [
            "Disable FTP entirely if not actively needed.",
            "Replace with SFTP (port 22) or FTPS which encrypt the connection.",
            "If FTP must stay, restrict access to specific IP addresses via firewall rules.",
            "Enforce strong passwords and disable anonymous login.",
        ]
    },
    22:   {
        "title": "SSH — Secure Shell",
        "risk": "Low",
        "description": "SSH is generally safe but is a common brute-force target when exposed to the internet.",
        "steps": [
            "Disable password authentication and use SSH key pairs instead.",
            "Change the default port from 22 to a non-standard port to reduce automated attacks.",
            "Use fail2ban or similar tools to block repeated failed login attempts.",
            "Restrict SSH access to trusted IP addresses only.",
        ]
    },
    23:   {
        "title": "Telnet",
        "risk": "High",
        "description": "Telnet sends all data including passwords in plain text. It is considered obsolete and dangerous.",
        "steps": [
            "Disable Telnet immediately — there is no valid reason to use it on a modern system.",
            "Replace with SSH for all remote administration tasks.",
            "Block port 23 at the firewall level.",
        ]
    },
    25:   {
        "title": "SMTP — Mail Transfer",
        "risk": "Medium",
        "description": "An open SMTP port can be abused as an open relay to send spam or phishing emails.",
        "steps": [
            "Ensure your mail server is not configured as an open relay.",
            "Require authentication for all outbound mail.",
            "Use SMTPS (port 465) or STARTTLS (port 587) for encrypted mail submission.",
            "Block port 25 inbound if this machine is not a mail server.",
        ]
    },
    53:   {
        "title": "DNS — Domain Name System",
        "risk": "Low",
        "description": "An exposed DNS port can be abused for DNS amplification attacks or zone transfer leaks.",
        "steps": [
            "Restrict recursive DNS queries to internal clients only.",
            "Disable zone transfers to unauthorized servers.",
            "If this is not a DNS server, block port 53 at the firewall.",
            "Keep DNS software updated to patch known vulnerabilities.",
        ]
    },
    80:   {
        "title": "HTTP — Web Server",
        "risk": "Low",
        "description": "HTTP traffic is unencrypted. Sensitive data transmitted over HTTP can be intercepted.",
        "steps": [
            "Redirect all HTTP traffic to HTTPS (port 443).",
            "Install a valid TLS/SSL certificate.",
            "Keep the web server software updated.",
            "Review what application or service is running on this port.",
        ]
    },
    110:  {
        "title": "POP3 — Email Retrieval",
        "risk": "Medium",
        "description": "POP3 transmits email credentials and content in plain text.",
        "steps": [
            "Disable plain POP3 and use POP3S (port 995) with TLS instead.",
            "Consider migrating to IMAP over TLS (port 993) for better functionality.",
            "Block port 110 at the firewall if not needed externally.",
        ]
    },
    135:  {
        "title": "RPC — Remote Procedure Call",
        "risk": "High",
        "description": "Windows RPC has a long history of critical vulnerabilities and is a common attack vector.",
        "steps": [
            "Block port 135 at the perimeter firewall — it should never be exposed to the internet.",
            "Apply all Windows security updates promptly.",
            "Use Windows Firewall to restrict RPC access to internal networks only.",
            "Audit which services depend on RPC and disable unnecessary ones.",
        ]
    },
    139:  {
        "title": "NetBIOS — Network Basic Input/Output System",
        "risk": "High",
        "description": "NetBIOS leaks system information and is exploitable for lateral movement in networks.",
        "steps": [
            "Block ports 137–139 at the firewall — never expose to the internet.",
            "Disable NetBIOS over TCP/IP in network adapter settings if not required.",
            "Use modern SMB (port 445) instead of NetBIOS for file sharing.",
        ]
    },
    143:  {
        "title": "IMAP — Email Access",
        "risk": "Medium",
        "description": "Plain IMAP transmits credentials and email content without encryption.",
        "steps": [
            "Disable plain IMAP and enforce IMAPS (port 993) with TLS.",
            "Block port 143 externally and only allow encrypted access.",
            "Require strong passwords for all mail accounts.",
        ]
    },
    443:  {
        "title": "HTTPS — Secure Web Server",
        "risk": "Low",
        "description": "HTTPS is the standard for secure web traffic. Ensure the configuration is hardened.",
        "steps": [
            "Use TLS 1.2 or 1.3 only — disable older SSL/TLS versions.",
            "Regularly renew your SSL certificate before expiry.",
            "Run a tool like SSL Labs to check your TLS configuration.",
            "Keep the web server and its dependencies updated.",
        ]
    },
    445:  {
        "title": "SMB — Windows File Sharing",
        "risk": "High",
        "description": "SMB has been exploited by major attacks like WannaCry and NotPetya. Extremely dangerous if exposed.",
        "steps": [
            "Block port 445 at the perimeter firewall immediately — never expose to the internet.",
            "Disable SMBv1 on all systems (it is obsolete and exploitable).",
            "Apply all Windows security patches, especially MS17-010.",
            "Restrict SMB access to trusted internal hosts only.",
        ]
    },
    3306: {
        "title": "MySQL — Database Server",
        "risk": "Medium",
        "description": "An exposed database port allows direct attack attempts against your data.",
        "steps": [
            "Block port 3306 from external access — databases should never be publicly reachable.",
            "Bind MySQL to localhost (127.0.0.1) in the configuration file.",
            "Use strong, unique passwords for all database accounts.",
            "Remove default or anonymous MySQL accounts.",
        ]
    },
    3389: {
        "title": "RDP — Remote Desktop Protocol",
        "risk": "High",
        "description": "RDP is one of the most targeted services on the internet, frequently used in ransomware attacks.",
        "steps": [
            "Never expose RDP directly to the internet.",
            "Place RDP behind a VPN — only allow access through the VPN.",
            "Enable Network Level Authentication (NLA).",
            "Use a firewall to whitelist only trusted IP addresses.",
            "Enable account lockout policies to prevent brute-force attacks.",
        ]
    },
    5900: {
        "title": "VNC — Virtual Network Computing",
        "risk": "High",
        "description": "VNC provides full desktop access and is often poorly secured with weak or no passwords.",
        "steps": [
            "Never expose VNC directly to the internet.",
            "Tunnel VNC through SSH for encrypted access.",
            "Set a strong VNC password — many installations use none by default.",
            "Consider replacing VNC with a more secure remote access solution.",
        ]
    },
    8080: {
        "title": "HTTP-Alt — Alternative Web Port",
        "risk": "Low",
        "description": "Often used for development servers, proxies, or admin panels that may lack proper security.",
        "steps": [
            "Identify what application is running on this port.",
            "If it is a development server, ensure it is not exposed to the internet.",
            "Apply the same hardening as a standard HTTP/HTTPS server.",
            "Consider moving to port 443 with TLS for production use.",
        ]
    },
    8443: {
        "title": "HTTPS-Alt — Alternative Secure Web Port",
        "risk": "Low",
        "description": "Used by some applications as an alternative HTTPS port. Ensure TLS is properly configured.",
        "steps": [
            "Verify TLS is correctly configured with a valid certificate.",
            "Identify the application using this port and keep it updated.",
            "Restrict access if this is an admin interface.",
        ]
    },
}

open_ports = []
lock       = threading.Lock()
queue      = Queue()


def print_banner():
    print(f"""
{CYAN}====================================
  🔍  Port Scanner — Cyber Toolkit
===================================={RESET}""")


def print_scan_info(target, start, end, threads):
    print(f"{YELLOW} Target  :{RESET} {target}")
    print(f"{YELLOW} Range   :{RESET} {start} - {end}")
    print(f"{YELLOW} Threads :{RESET} {threads}")
    print(f"{YELLOW} Started :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{CYAN}===================================={RESET}\n")


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


def worker(target, timeout):
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, timeout)
        queue.task_done()


def fill_queue(start, end):
    for port in range(start, end + 1):
        queue.put(port)


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


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"{YELLOW} Resolved :{RESET} {target} → {ip}\n")
        return ip
    except socket.gaierror:
        print(f"{RED} [ERROR] Could not resolve host: {target}{RESET}")
        exit(1)


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


def generate_report(target, start, end, threads, timeout, start_time, duration):
    timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")

    rows = ""
    for port, service in sorted(open_ports):
        risk = "High" if port in [21, 23, 135, 139, 445, 3389, 5900] else "Medium" if port in [25, 110, 143, 3306] else "Low"
        risk_class = "risk-high" if risk == "High" else "risk-medium" if risk == "Medium" else "risk-low"
        rows += f"""
        <tr>
            <td>{port}</td>
            <td>{service}</td>
            <td><span class="badge {risk_class}">{risk}</span></td>
        </tr>"""

    ports_json = json.dumps([p for p, _ in sorted(open_ports)])
    services_json = json.dumps([s for _, s in sorted(open_ports)])

    risk_counts = {"High": 0, "Medium": 0, "Low": 0}
    for port, _ in open_ports:
        if port in [21, 23, 135, 139, 445, 3389, 5900]:
            risk_counts["High"] += 1
        elif port in [25, 110, 143, 3306]:
            risk_counts["Medium"] += 1
        else:
            risk_counts["Low"] += 1

    advice_cards = ""
    for port, service in sorted(open_ports):
        advice = PORT_ADVICE.get(port)
        if not advice:
            advice = {
                "title": f"Port {port} — {service}",
                "risk": "Low",
                "description": f"This port is running {service}. Verify it is intentionally open and serving a known application.",
                "steps": [
                    "Identify the application or service using this port.",
                    "If not needed, close the port and disable the service.",
                    "Ensure the service is kept up to date with security patches.",
                    "Restrict access via firewall rules to trusted sources only.",
                ]
            }
        risk = advice["risk"]
        risk_class = "risk-high" if risk == "High" else "risk-medium" if risk == "Medium" else "risk-low"
        steps_html = "".join(f"<li>{s}</li>" for s in advice["steps"])
        advice_cards += f"""
        <div class="advice-card">
          <div class="advice-header">
            <div>
              <span class="advice-port">Port {port}</span>
              <span class="advice-title">{advice["title"]}</span>
            </div>
            <span class="badge {risk_class}">{risk} Risk</span>
          </div>
          <p class="advice-desc">{advice["description"]}</p>
          <ul class="advice-steps">{steps_html}</ul>
        </div>"""

    if not open_ports:
        advice_cards = '<div class="no-ports">No open ports were found — no remediation required for this scan range.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Port Scan Report — {target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap');
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Inter', 'Segoe UI', sans-serif; background: #111113; color: #c9c9c9; }}
    header {{ padding: 48px 20px; text-align: center; border-bottom: 1px solid #1e1e20; }}
    header h1 {{ font-size: 1.6rem; font-weight: 600; color: #f0f0f0; letter-spacing: 0.5px; }}
    header p {{ color: #555; margin-top: 10px; font-size: 0.88rem; font-weight: 300; }}
    .container {{ max-width: 1060px; margin: 40px auto; padding: 0 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #18181a; border: 1px solid #1e1e20; border-radius: 10px; padding: 22px 20px; text-align: center; }}
    .card .value {{ font-size: 1.8rem; font-weight: 600; color: #f0f0f0; }}
    .card .label {{ font-size: 0.72rem; color: #444; margin-top: 6px; text-transform: uppercase; letter-spacing: 1.2px; }}
    .section {{ background: #18181a; border: 1px solid #1e1e20; border-radius: 10px; padding: 28px; margin-bottom: 24px; }}
    .section h2 {{ font-size: 0.75rem; font-weight: 500; color: #555; margin-bottom: 22px; text-transform: uppercase; letter-spacing: 1.5px; }}
    .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }}
    @media (max-width: 700px) {{ .charts {{ grid-template-columns: 1fr; }} }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; padding: 10px 16px; color: #444; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1.2px; border-bottom: 1px solid #1e1e20; font-weight: 500; }}
    td {{ padding: 13px 16px; border-bottom: 1px solid #1a1a1c; font-size: 0.9rem; color: #b0b0b0; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1c1c1e; }}
    .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.72rem; font-weight: 500; letter-spacing: 0.5px; }}
    .risk-high {{ background: #2a1515; color: #e05555; }}
    .risk-medium {{ background: #2a2215; color: #c98a2e; }}
    .risk-low {{ background: #152a1e; color: #3d9e6a; }}
    .no-ports {{ text-align: center; padding: 40px; color: #444; font-size: 0.95rem; }}
    .advice-card {{ border: 1px solid #1e1e20; border-radius: 8px; padding: 22px; margin-bottom: 16px; background: #111113; }}
    .advice-card:last-child {{ margin-bottom: 0; }}
    .advice-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 12px; }}
    .advice-port {{ font-size: 0.72rem; color: #444; text-transform: uppercase; letter-spacing: 1px; display: block; margin-bottom: 4px; }}
    .advice-title {{ font-size: 0.95rem; font-weight: 500; color: #e0e0e0; display: block; }}
    .advice-desc {{ font-size: 0.88rem; color: #666; line-height: 1.6; margin-bottom: 14px; }}
    .advice-steps {{ list-style: none; padding: 0; }}
    .advice-steps li {{ font-size: 0.88rem; color: #999; padding: 7px 0 7px 18px; border-bottom: 1px solid #1a1a1c; position: relative; line-height: 1.5; }}
    .advice-steps li:last-child {{ border-bottom: none; }}
    .advice-steps li::before {{ content: '→'; position: absolute; left: 0; color: #333; }}
    footer {{ text-align: center; padding: 32px 20px; color: #333; font-size: 0.8rem; border-top: 1px solid #1e1e20; margin-top: 10px; }}
    footer a {{ color: #555; text-decoration: none; transition: color 0.2s; }}
    footer a:hover {{ color: #999; }}
  </style>
</head>
<body>
  <header>
    <h1>Port Scan Report</h1>
    <p>Target: <strong style="color:#888">{target}</strong> &nbsp;&middot;&nbsp; {timestamp}</p>
  </header>

  <div class="container">
    <div class="cards">
      <div class="card">
        <div class="value">{target}</div>
        <div class="label">Target</div>
      </div>
      <div class="card">
        <div class="value">{start}–{end}</div>
        <div class="label">Port Range</div>
      </div>
      <div class="card">
        <div class="value" style="color:#3d9e6a">{len(open_ports)}</div>
        <div class="label">Open Ports</div>
      </div>
      <div class="card">
        <div class="value">{duration:.1f}s</div>
        <div class="label">Duration</div>
      </div>
      <div class="card">
        <div class="value">{threads}</div>
        <div class="label">Threads</div>
      </div>
    </div>

    <div class="section">
      <h2>Visual Overview</h2>
      <div class="charts">
        <div><canvas id="riskChart"></canvas></div>
        <div><canvas id="portChart"></canvas></div>
      </div>
    </div>

    <div class="section">
      <h2>Open Ports</h2>
      {"<table><thead><tr><th>Port</th><th>Service</th><th>Risk Level</th></tr></thead><tbody>" + rows + "</tbody></table>" if open_ports else '<div class="no-ports">No open ports found in the scanned range.</div>'}
    </div>

    <div class="section">
      <h2>Recommendations</h2>
      {advice_cards}
    </div>

    <div class="section">
      <h2>Scan Details</h2>
      <table>
        <tr><td style="color:#555;width:200px">Target</td><td>{target}</td></tr>
        <tr><td style="color:#555">Port Range</td><td>{start} – {end}</td></tr>
        <tr><td style="color:#555">Total Ports Scanned</td><td>{end - start + 1}</td></tr>
        <tr><td style="color:#555">Open Ports Found</td><td>{len(open_ports)}</td></tr>
        <tr><td style="color:#555">Threads Used</td><td>{threads}</td></tr>
        <tr><td style="color:#555">Timeout per Port</td><td>{timeout}s</td></tr>
        <tr><td style="color:#555">Scan Duration</td><td>{duration:.2f} seconds</td></tr>
        <tr><td style="color:#555">Scan Started</td><td>{timestamp}</td></tr>
      </table>
    </div>
  </div>

  <footer>
    {timestamp} &nbsp;&middot;&nbsp; Powered by <a href="https://brelinx.com" target="_blank">brelinx.com</a>
  </footer>

  <script>
    const riskCtx = document.getElementById('riskChart').getContext('2d');
    new Chart(riskCtx, {{
      type: 'doughnut',
      data: {{
        labels: ['High Risk', 'Medium Risk', 'Low Risk'],
        datasets: [{{ data: [{risk_counts['High']}, {risk_counts['Medium']}, {risk_counts['Low']}], backgroundColor: ['#e05555','#c98a2e','#3d9e6a'], borderWidth: 0 }}]
      }},
      options: {{ plugins: {{ legend: {{ labels: {{ color: '#555', font: {{ size: 12 }} }} }} }}, cutout: '68%' }}
    }});

    const portCtx = document.getElementById('portChart').getContext('2d');
    new Chart(portCtx, {{
      type: 'bar',
      data: {{
        labels: {services_json},
        datasets: [{{ label: 'Port Number', data: {ports_json}, backgroundColor: '#2a2a2e', borderColor: '#3a3a3e', borderWidth: 1, borderRadius: 4 }}]
      }},
      options: {{
        plugins: {{ legend: {{ labels: {{ color: '#555', font: {{ size: 12 }} }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#444' }}, grid: {{ color: '#1a1a1c' }} }},
          y: {{ ticks: {{ color: '#444' }}, grid: {{ color: '#1a1a1c' }} }}
        }}
      }}
    }});
  </script>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"{CYAN} Report  :{RESET} {report_path}")
    webbrowser.open(f"file:///{report_path}")


def main():
    args = parse_args()

    print_banner()

    target = resolve_target(args.target)

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print(f"{RED} [ERROR] Invalid port range. Use 1–65535.{RESET}")
        exit(1)

    print_scan_info(target, args.start, args.end, args.threads)

    start_time = datetime.now()

    fill_queue(args.start, args.end)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(target, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    duration = (datetime.now() - start_time).total_seconds()
    print_results(start_time)
    generate_report(target, args.start, args.end, args.threads, args.timeout, start_time, duration)


if __name__ == "__main__":
    main()
