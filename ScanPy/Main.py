import socket
import argparse
import sys
from Verification import setup_logger, setup_logger_file
from Scan_Network_Hosts import check_type, check_fping_existence
from Scan_Ports import scan_multiple_hosts, scan_single_host

print("""
This tool devoloped by: Ali Mohammad

Follow me on github: https://github.com/Ali-Mohammad1
Follow me on linkedin: www.linkedin.com/in/ali-mohammed-7648b2406

Help me to continue and improving my skills by your support and feedbacks.
\n\n""")


def scan_hosts(logger, network: str, packets: int, range_of_hosts: int, timeout: int, verbose: bool) -> list:
    if not check_fping_existence(logger):
        logger.error("fping is not installed or not found in PATH. Please install fping to use the host scanning feature.")
        sys.exit(1)
    return check_type(logger, network, packets, range_of_hosts, timeout, verbose)

def scan_ports_single_host(logger, host: str, ports: list, timeout: int, max_workers: int, verbose: bool) -> list:
    return scan_single_host(logger, host, ports, timeout, max_workers, verbose)

def scan_ports_multiple_hosts(logger, hosts: list, ports: list, timeout: int, max_workers: int, verbose: bool) -> dict:
    return scan_multiple_hosts(hosts, ports, timeout, max_workers, verbose)

def handle_ports_input(ports: str) -> list:
    if ports is None:
        return list(range(1, 1024))
    if "," in ports:
        return [int(p.strip()) for p in ports.split(",")]
    if "-" in ports:
        start, end = map(int, ports.split("-"))
        return list(range(start, end + 1))
    if " " in ports:
        return [int(p) for p in ports.split()]
    return [int(ports)]

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"

def main():
    parser = argparse.ArgumentParser(description="ScanPy: A powerful network scanning tool for IPv4 and IPv6 hosts.")
    
    # General options
    parser.add_argument("--log-file", default="scanpy.log", help="Path to the log file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # Host scanning options
    parser.add_argument("--scan-hosts", "-sh", action="store_true", dest="scan_hosts", help="Scan hosts in the specified network")
    parser.add_argument("--network", default="192.168.1.0/24", help="Target network in CIDR notation (default: 192.168.1.0/24)")
    parser.add_argument("--host-range", "-hr", type=int, help="Maximum number of hosts to scan (default: 254)")
    parser.add_argument("--packet-count", "-c", type=int, default=4, help="Number of ping packets per host (default: 4)")
    
    # Port scanning options
    parser.add_argument("--scan-ports", "-sp", action="store_true", dest="scan_ports", help="Scan ports on the specified target")
    parser.add_argument("-t", "--target", help="Single target IP address")
    parser.add_argument("-ts", "--targets", help="Comma-separated list of target IP addresses")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443 or 1-1000)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for port scanning in seconds (default: 5)")
    parser.add_argument("--max-workers", type=int, default=100, help="Maximum number of threads for scanning (default: 100)")
    
    args = parser.parse_args()
    
    # Setup logger
    if args.log_file:
        logger = setup_logger_file(args.log_file, args.verbose)
    else:
        logger = setup_logger(args.verbose)
    
    # Validation checks
    if args.network and not args.scan_hosts:
        logger.error("Error: --network option is only valid with --scan-hosts (-sh)")
        sys.exit(1)
        
    if args.host_range is not None and not args.scan_hosts:
        logger.error("Error: --host-range option is only valid with --scan-hosts (-sh)")
        sys.exit(1)
        
    if args.ports and not (args.target or args.targets):
        logger.error("Error: --ports option requires -t/--target or -ts/--targets")
        sys.exit(1)
        
    if args.target and not args.scan_ports:
        logger.error("Error: -t/--target option is only valid with --scan-ports (-sp)")
        sys.exit(1)
        
    if args.targets and not args.scan_ports:
        logger.error("Error: -ts/--targets option is only valid with --scan-ports (-sp)")
        sys.exit(1)
        
    if args.max_workers < 1:
        logger.error("Error: --max-workers must be a positive integer")
        sys.exit(1)
    
    # Case 1: Both host and port scanning
    if args.scan_hosts and args.scan_ports:
        logger.info("Both host scanning and port scanning requested. Scanning hosts first...")
        scanned_hosts = scan_hosts(logger, args.network, args.packet_count, args.host_range, args.timeout, args.verbose)
        if scanned_hosts:
            logger.info(f"Found {len(scanned_hosts)} alive host(s): {scanned_hosts}")
            ports = handle_ports_input(args.ports)
            port_results = scan_ports_multiple_hosts(logger, scanned_hosts, ports, args.timeout, args.max_workers, args.verbose)
            if args.verbose:
                for target, open_ports in port_results.items():
                    services = [get_service_name(p) for p in open_ports]
                    logger.info(f"{target}: {list(zip(open_ports, services))}")
            else:
                logger.info(f"Port scan results: {port_results}")
        else:
            logger.warning("No alive hosts found. Skipping port scan.")
    
    # Case 2: Only host scanning
    elif args.scan_hosts:
        scanned_hosts = scan_hosts(logger, args.network, args.packet_count, args.host_range, args.timeout, args.verbose)
        logger.info(f"Discovered hosts: {scanned_hosts}")
    
    # Case 3: Only port scanning
    elif args.scan_ports:
        ports = handle_ports_input(args.ports)
        if args.targets:
            targets = [t.strip() for t in args.targets.split(",")]
            results = scan_ports_multiple_hosts(logger, targets, ports, args.timeout, args.max_workers, args.verbose)
            if args.verbose:
                for target, open_ports in results.items():
                    services = [get_service_name(p) for p in open_ports]
                    logger.info(f"{target}: {list(zip(open_ports, services))}")
            else:
                logger.info(f"Port scan results: {results}")
        elif args.target:
            result = scan_ports_single_host(logger, args.target, ports, args.timeout, args.max_workers, args.verbose)
            
            if args.verbose:
                services = [get_service_name(p) for p in result]
                logger.info(f"{args.target}: {list(zip(result, services))}")
            else:
                logger.info(f"Open ports on {args.target}: {result}")
        
        else:
            logger.error("Error: No target specified for port scanning. Use -t/--target or -ts/--targets.")
            sys.exit(1)
    else:
        logger.error("No action specified. Use --scan-hosts (-sh) or --scan-ports (-sp).")
        sys.exit(1)

if __name__ == "__main__":
    main()