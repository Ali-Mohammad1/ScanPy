import ipaddress
import sys
import subprocess
from Verification import validate_and_parse_ip_cidr
from time import sleep,time
import os
import shutil


print("Importand Note: This tool uses fping for scanning hosts. Ensure that fping is installed)")

def check_fping_existence(logger):
  if shutil.which("fping") is None:
    logger.error("fping is not installed. Please install fping to use this feature.")
    logger.info("You can install fping using the following command:")
    logger.info("For Debian/Ubuntu: sudo apt-get install fping")
    logger.info("For Red Hat/CentOS: sudo yum install fping")
    logger.info("For macOS: brew install fping")
    logger.info("Fping not supported on Windows,But code will work with ping command.")
    return False
  
  else:
    return True
    

def clear(socends:int=0):
  sleep(socends if socends > 0 else 0)
  os.system('cls' if os.name == 'nt' else 'clear')


def scan_hosts_ipv4(logger, network: str, packets: int = 4, range_of_hosts: int = 254, timeout: int = 4, verbose: bool = False):
    logger.info("Scanning IPv4 network...")
    
    if range_of_hosts > 254 or range_of_hosts <= 0 or range_of_hosts is None:
        range_of_hosts = 254
        logger.warning("Range of hosts must be between 1 and 254. Defaulting to 254.")
        logger.info("range of hosts has been reset to default value (254)")
    
    ips = list(ipaddress.ip_network(network, strict=False).hosts())[:range_of_hosts]
    
    alive_hosts = []
    
    # Build fping command: remove -g, add -q only if not verbose
    # -a : show only alive hosts
    # -c : number of packets
    # -t : timeout in milliseconds
    # -q : quiet output (added only when verbose is False)
    
    if verbose:
        command = ["fping", "-a", "-c", str(packets), "-t", str(timeout * 1000)] + [str(ip) for ip in ips]
    else:
        command = ["fping", "-a", "-q", "-c", str(packets), "-t", str(timeout * 1000)] + [str(ip) for ip in ips]
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if verbose:
            # In verbose mode: display full output on screen
            logger.info("Verbose output from fping:")
            print(result.stdout)
            
            # Extract only active IPs from the output (without extra text)
            for line in result.stdout.splitlines():
                if "is alive" in line:
                    ip = line.split()[0]  # first word is the IP address
                    alive_hosts.append(ip)
        else:
            # In normal mode: output contains only IP addresses (one per active host)
            alive_hosts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        
        # Log any warnings from stderr (e.g., ICMP errors)
        if result.stderr:
            logger.warning(f"fping stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        logger.error("Ping command timed out. Please check your network connection and try again.")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.error(f"An error occurred while scanning: {e}")
    
    # Final output (clean list)
    logger.info("Scan completed successfully.")
    logger.info(f"Alive hosts: {len(alive_hosts)}")
    if verbose:
        logger.info("Alive hosts list (clean):")
        for n, host in enumerate(alive_hosts, start=1):
            logger.info(f"{n}. {host}")
    
    return alive_hosts
    
def scan_hosts_ipv6(logger, network: str, packets: int = 4, range_of_hosts: int = 254, timeout: int = 4, verbose: bool = False):
    logger.info("Scanning IPv6 network...")
    
    # For IPv6, a typical /64 subnet has 2^64 hosts, so we limit the scan range
    if range_of_hosts <= 0 or range_of_hosts is None:
        range_of_hosts = 500
        logger.warning("Range of hosts must be a positive integer. Defaulting to 500.")
        logger.info("range of hosts has been reset to default value (500)")
        logger.info("Note: Scanning too many IPv6 addresses may be slow.")
    
    # Convert hosts iterator to list and limit by range_of_hosts
    net = ipaddress.ip_network(network, strict=False)
    all_hosts = list(net.hosts())
    if len(all_hosts) > range_of_hosts:
        all_hosts = all_hosts[:range_of_hosts]
    ips = [str(ip) for ip in all_hosts]
    
    alive_hosts = []
    
    # Build fping command with -6 for IPv6
    # -6 : use IPv6 only
    # -a : show only alive hosts
    # -c : number of packets
    # -t : timeout in milliseconds
    # -q : quiet output (added only when verbose is False)
    
    if verbose:
        command = ["fping", "-6", "-a", "-c", str(packets), "-t", str(timeout * 1000)] + ips
    else:
        command = ["fping", "-6", "-a", "-q", "-c", str(packets), "-t", str(timeout * 1000)] + ips
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if verbose:
            logger.info("Verbose output from fping:")
            print(result.stdout)
            
            # Extract only active IPv6 addresses from lines containing "is alive"
            for line in result.stdout.splitlines():
                if "is alive" in line:
                    ip = line.split()[0]  # first token is the IPv6 address
                    alive_hosts.append(ip)
        else:
            # Normal mode: stdout contains only IP addresses (one per line)
            alive_hosts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        
        if result.stderr:
            logger.warning(f"fping stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        logger.error("Ping command timed out. Please check your network connection and try again.")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.error(f"An error occurred while scanning: {e}")
    
    logger.info("Scan completed successfully.")
    logger.info(f"Alive hosts: {len(alive_hosts)}")
    if verbose:
        logger.info("Alive hosts list (clean):")
        for n, host in enumerate(alive_hosts, start=1):
            logger.info(f"{n}. {host}")
    
    return alive_hosts
  
  
  
def check_type(logger, input_ip: str, packets: int = 4, range_of_hosts: int = 254, timeout: int = 4, verbose: bool = False):

    # Convert input to a proper network format (IP/CIDR) and validate it
    parsed_network = validate_and_parse_ip_cidr(input_ip, logger,True)
    
    # Create a network object to determine IP version (IPv4 or IPv6)
    network = ipaddress.ip_network(parsed_network, strict=False)
    
    # Call the appropriate scanning function with the parsed network (not the raw input)
    if network.version == 4:
        return scan_hosts_ipv4(logger, parsed_network, packets, range_of_hosts, timeout, verbose)
    else:  # IPv6
        return scan_hosts_ipv6(logger, parsed_network, packets, range_of_hosts, timeout, verbose) 