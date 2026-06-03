from venv import logger
from contextlib import AbstractAsyncContextManager
import argparse
import sys
from Verification import setup_logger, validate_and_parse_ip_cidr,setup_logger_file
from Scan_Network_Hosts import check_type,clear,check_fping_existence,scan_hosts_ipv6,scan_hosts_ipv4
from Scan_Ports import scan_multiple_hosts,scan_single_host

project = """
$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$\ $$\     $$\ 
$$  __$$\ $$  __$$\ $$  __$$\ $$$\  $$ |$$  __$$\\$$\   $$  |
$$ /  \__|$$ /  \__|$$ /  $$ |$$$$\ $$ |$$ |  $$ |\$$\ $$  / 
\$$$$$$\  $$ |      $$$$$$$$ |$$ $$\$$ |$$$$$$$  | \$$$$  /  
 \____$$\ $$ |      $$  __$$ |$$ \$$$$ |$$  ____/   \$$  /   
$$\   $$ |$$ |  $$\ $$ |  $$ |$$ |\$$$ |$$ |         $$ |    
\$$$$$$  |\$$$$$$  |$$ |  $$ |$$ | \$$ |$$ |         $$ |    
 \______/  \______/ \__|  \__|\__|  \__|\__|         \__|    
"""

print("\033[34m" + project+ "\033[0m")

print("""
This tool devoloped by: Ali Mohammad

Follow me on github: https://github.com/Ali-Mohammad1
Follow me on linkedin: www.linkedin.com/in/ali-mohammed-7648b2406

Help me to continue and improving my skills by your support and feedbacks.
""")

clear(3)

def scan_hosts(logger, network:str, packets:int, range_of_hosts:int, timeout:int, verbose:bool)-> list:
  if not check_fping_existence(logger):
    logger.Error("fping is not installed or not found in PATH. Please install fping to use the host scanning feature.")
    sys.exit(1)
  
  return check_type(logger,network,packets,range_of_hosts,timeout,verbose)

def scan():
  pass

def main():
  parser = argparse.ArgumentParser(description="ScanPy: A powerful network scanning tool for IPv4 and IPv6 hosts.")
  
  parser.add_argument("scan-hosts","-sh",action="store_true",help="Scan hosts in the specified network")
  parser.add_argument("--network", default="192.168.1.1/24", help="Target network in CIDR notation")
  parser.add_argument("--host-range","hr",help="range of hosts to scan example (30 -> 192.168.1.1-30)")
  parser.add_argument("--packet-size", type=int, default=1024, help="Size of packets to send during scanning")
  
  parser.add_argument("scan-ports","-sp",action="store_true",help="Scan ports on the specified target")
  parser.add_argument("-t", "--target", help="Target IP address")
  parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (80,443,8080)")
  parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
  parser.add_argument("--log-file", default="scanpy.log", help="Path to the log file")
  parser.add_argument("--timeout", type=int, default=5, help="Timeout for port scanning in seconds")
  parser.add_argument("--max-workers", type=int, default=100, help="Maximum number of worker threads for scanning")
  
  args = parser.parse_args()
    
  if not args.log_file:
    logger = setup_logger(args.verbose)
  else:
    logger = setup_logger_file(args.log_file, args.verbose)
  
  
  if args.network and not args.scan_hosts:
    logger.Error("Error: --network option is only valid with -sh/--scan-hosts")
    sys.exit(1)
  if args.host_range and not args.scan_hosts:
    logger.Error("Error: --host-range option is only valid with -sh/--scan-hosts")
    sys.exit(1)
  if args.ports and not args.target:
    logger.Error("Error: --ports option requires -t/--target to specify the target IP address")
    sys.exit(1)
    
  if args.target and not args.scan_ports:
    print("Error: -t/--target option is only valid with -sp/--scan-ports")
    sys.exit(1)
    
  if args.max_workers < 1:
    print("Error: --max-workers must be a positive integer")
    sys.exit(1)
