import ipaddress
import sys
import subprocess
from Verification import validate_and_parse_ip_cidr
from time import sleep,time
import os
import shutil

def check_fping_existence(logger):
  if shutil.which("fping") is None:
    logger.Error("fping is not installed. Please install fping to use this feature.")
    logger.info("You can install fping using the following command:")
    logger.info("For Debian/Ubuntu: sudo apt-get install fping")
    logger.info("For Red Hat/CentOS: sudo yum install fping")
    logger.info("For macOS: brew install fping")
    logger.info("Fping not supported on Windows,But code will work with ping command.")
    system_exit = input("Press Enter to exit...")
    sys.exit(1)
    
check_fping_existence(logger)

def clear(socends:int):
  sleep(socends if socends > 0 else 0))
  os.system('cls' if os.name == 'nt' else 'clear')


def scan_hosts_ipv4(logger,input_ip:str,packets:int = 4,range_of_hosts:int=254,timeout:int = 4, verbose:bool = False):

  logger.Info("Scanning IPv4 network...")
    
  if range_of_hosts > 254 or range_of_hosts <= 1:
    range_of_hosts= 254
    logger.Warning("Range of hosts must be between 1 and 254. Defaulting to 254.")
  
  ips = list(ipaddress.ip_network(validate_and_parse_ip_cidr(input_ip, logger), strict=False).hosts())[:range_of_hosts]
  
  alive_hosts = []
  
  
  
  # -c : Number of packets to send
  # -t : Timeout in milliseconds
  # -q : Quiet output (only summary)
  # -a : Show alive hosts only
  # -g : Generate list of IPs to ping
  
  command = ["fping","-a","-g", "-c", str(packets), "-t", str(timeout * 1000),"-q"] + [str(ip) for ip in ips]
  
  if verbose:
    command.remove("-q")
  try:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    for line in result.stdout.splitlines():
      if line.strip():
        alive_hosts.append(line.strip())
      else:
        logger.Warning("No response received from some hosts. They may be offline or blocking ICMP requests.")
  
  if verbose:
    logger.Info("Verbose mode enabled. Displaying detailed output:")
    logger.info(result.stdout)
    start_time = time() # to calculate the time taken for the scan
  
  except subprocess.TimeoutExpired:
    logger.Error("Ping command timed out. Please check your network connection and try again.")
       
  except KeyboardInterrupt:
    logger.Warning("Scan interrupted by user.")
       
    logger.info(f"Alive hosts: {len(alive_hosts)})")
    
    for n , host in enumerate(alive_hosts, start=1):
      logger.info(f"{n}. {host}")
      
    clear(4)     
    
    return alive_hosts
      
  except Exception as e:
    logger.Error(f"An error occurred while scanning: {e}")
     
  logger.Info("Scan completed successfully.")
  end_time = time()
  
  if verbose:
    logger.info(f"Time taken for scan: {end_time - start_time:.2f} seconds")
    
  clear(3)

  logger.info(f"Alive hosts: {len(alive_hosts)})")
  if verbose:
    logger.info("Alive hosts".center(30, "-")))
    for n , host in enumerate(alive_hosts, start=1):
      logger.info(f"{n}. {host}")
      
  clear(4)
  return alive_hosts
        
    
#def scan_hosts_ipv6(logger,input_ip:str,packets:int = 4,range_of_hosts:int= 254,timeout:int = 4, verbose:bool=False):
  #pass
  
  
  
  
  
def check_type(logger,input_ip:str,packets:int = 4,range_of_hosts:int= 254,timeout:int = 4,verbose:bool=False):
  ip_add = ipaddress.ip_network(validate_and_parse_ip_cidr(input_ip, logger), strict=False)
  
  if ip_add.version == 4:
    return scan_hosts_ipv4(logger,input_ip, packets ,range_of_hosts, timeout, verbose)
  
  elif ip_add.version == 6:
    pass
    #return scan_hosts_ipv6(input_ip,packets,range_of_hosts, timeout, verbose, logger)
  