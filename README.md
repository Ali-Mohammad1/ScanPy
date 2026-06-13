ScanPy – Advanced Network Scanner

ScanPy is a powerful yet easy‑to‑use network scanning tool written in Python.
It supports IPv4 and IPv6 host discovery (via fping) and TCP port scanning (multi‑threaded connect scan).
Logging, verbosity, and flexible target/port specification are built‑in.

Note: Parts of this code and documentation were written with the assistance of AI (large language models) to solve implementation challenges and improve clarity.

---

✨ Features

· Host discovery – find alive hosts in a network using fping (fast ICMP ping).
· Port scanning – scan single or multiple hosts for open TCP ports.
· IPv4 & IPv6 – fully supported for both host and port scans.
· Flexible port specification – single port, comma‑separated list, range (e.g. 1-1000), or default (1‑1023).
· Threaded scanning – configurable concurrency for port scans (--max-workers).
· Logging – logs to file and optionally to console (--verbose).
· CLI‑first design – all features accessible via command line arguments.
· Error handling – validates inputs, checks for missing dependencies (e.g. fping).

---

📦 Requirements

· Python 3.7+
· fping – required for host discovery.
    Install it on:
  · Debian/Ubuntu: sudo apt install fping
  · RHEL/CentOS: sudo yum install fping
  · macOS: brew install fping
  · Windows: not officially supported, but the tool will fallback to a basic ping (functionality may be limited).

No external Python packages are needed – only the standard library (socket, ipaddress, subprocess, concurrent.futures, logging, argparse, etc.).

---

🚀 Installation

Clone the repository and ensure the four Python files are in the same directory:

```bash
git clone https://github.com/Ali-Mohammad1/ScanPy.git
cd ScanPy
```

Make sure fping is installed (see above).

---

🧪 Usage

```
python Main.py [-h] [--log-file LOG_FILE] [--verbose] [--scan-hosts] [--network NETWORK]
               [--host-range HOST_RANGE] [--packet-count PACKET_COUNT] [--scan-ports]
               [-t TARGET] [-ts TARGETS] [-p PORTS] [--timeout TIMEOUT] [--max-workers MAX_WORKERS]
```

Host discovery only

```bash
python Main.py --scan-hosts --network 192.168.1.0/24 --host-range 100 --verbose
```

Port scan a single host

```bash
python Main.py --scan-ports -t 192.168.1.10 -p 22,80,443 --timeout 3 --max-workers 50
```

Port scan multiple hosts (list)

```bash
python Main.py --scan-ports -ts 192.168.1.10,192.168.1.11 -p 1-1000
```

Combined: discover hosts, then scan ports on them

```bash
python Main.py --scan-hosts --scan-ports --network 192.168.1.0/24 -p 80,443 --verbose
```

IPv6 example

```bash
python Main.py --scan-hosts --network 2001:db8::/64 --host-range 200
```

---

⚙️ Command line arguments

Argument Description
--log-file FILE Path to log file (default scanpy.log)
--verbose, -v Enable verbose output (console)
--scan-hosts, -sh Perform host discovery
--network NET Network in CIDR (default 192.168.1.0/24)
--host-range N, -hr Max hosts to scan (IPv4: 1‑254, IPv6: default 500)
--packet-count N, -c Number of ping packets per host (default 4)
--scan-ports, -sp Perform port scanning
-t TARGET Single target IP (requires --scan-ports)
-ts TARGETS Comma‑separated list of targets
-p PORTS Ports: single (e.g. 80), list (22,443), range (1-1000) (default 1‑1023)
--timeout SEC Socket timeout in seconds (default 5)
--max-workers N Threads for port scanning (default 100)

Note: --network and --host-range are only valid with --scan-hosts.
-t / -ts and -p are only valid with --scan-ports.

---

📁 File structure

File Purpose
Main.py Entry point, argument parsing, orchestration
Scan_Network_Hosts.py Host discovery using fping (IPv4/IPv6)
Scan_Ports.py Multi‑threaded TCP port scanning
Verification.py Logging setup, IP/CIDR validation, interactive CIDR prompt

---

🧠 How it works

1. Host discovery – builds a list of IPs from the given CIDR network, then calls fping with appropriate flags (-a for alive hosts). Parses output to return a list of responsive hosts.
2. Port scanning – for each target host, a thread pool tries to connect to each port using socket.connect_ex(). If the connection succeeds (result 0), the port is marked open.
3. Logging – uses Python’s logging module. All messages go to a file (DEBUG level). When --verbose is used, they also appear on the console.

---

⚠️ Limitations & disclaimers

· Host discovery requires fping – the tool will exit with an error if it’s missing.
    (Windows users can try installing fping via Cygwin or WSL, or modify the code to use native ping.)
· Port scanning uses a TCP connect scan – it is not stealth and will be logged by firewalls/IDS.
· Scanning networks or hosts without permission may be illegal. Use only on your own infrastructure or with explicit authorisation.
· The author and AI assistants are not responsible for any misuse.

---

🤝 Contributing & support

Contributions, bug reports, and feature requests are welcome via GitHub issues or pull requests.

· GitHub: Ali-Mohammad1
· LinkedIn: Ali Mohammed

---

🙏 Acknowledgements

· AI models (Deepseek, etc.) helped with code structuring, debugging, and writing this README.
· The open‑source community – especially fping developers.

---

📄 License

This project is open source and available under the MIT License. See LICENSE file for details.
