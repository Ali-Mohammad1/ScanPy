import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed 


def scan_single_host(logger,host: str, ports: list, timeout=1, max_workers=100, verbose=False):
    open_ports = []
    
    if verbose:
        logger.info(f"[*] Scanning host: {host}")
        logger.info(f"[*] Ports to scan: {ports}")
        logger.info(f"max_workers: {max_workers} , timeout: {timeout} seconds")
    
    def scan_port(logger,ports):
        try:
            scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scanner.settimeout(timeout)
            scanner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            scanner.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            scanner.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            result = scanner.connect_ex((host, port))
            scanner.close()
            if result == 0:
                if verbose:
                    print(f"[+] Port {ports} is open")
                return ports
            return None
        except Exception as e:
            if verbose:
                print(f"[!] Error scanning port {ports}: {e}")
            return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor: 
        future_to_port = {executor.submit(scan_port, port): port for port in ports}
        for future in as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    open_ports.sort()
    return open_ports

def scan_multiple_hosts(hosts: list, ports: list, timeout=1, max_workers=100, verbose=False):
    results = {}
    for host in hosts:
        if verbose:
            print(f"[*] Scanning host: {host}")
        open_ports = scan_single_host(host, ports, timeout, max_workers, verbose)
        results[host] = open_ports
    return results


