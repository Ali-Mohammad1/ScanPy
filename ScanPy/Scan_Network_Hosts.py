import ipaddress
import sys
import subprocess
from Verification import validate_and_parse_ip_cidr
from time import sleep
import os

try:
  from tqdm import tqdm
except ImportError:
  print("tqdm library not found. Please install it using 'pip install tqdm' for better progress visualization.")
  
  ask = input("Do you want to install tqdm here (y/n): ").strip().lower()
  if ask != 'y':
    sys.exit("Exiting. Please install tqdm and try again.")
  
  else:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm
    
def clear():
  os.system('cls' if os.name == 'nt' else 'clear')


def scan_hosts_ipv4(logger,input_ip:str,packets:int = 4,range_of_hosts:int=254,timeout:int = 4, verbose:bool = False):

  logger.Info("Scanning IPv4 network...")
    
  if range_of_hosts > 254 or range_of_hosts <= 1:
    range_of_hosts= 254
    logger.Warning("Range of hosts must be between 1 and 254. Defaulting to 254.")
  
  ips = list(ipaddress.ip_network(validate_and_parse_ip_cidr(input_ip, logger), strict=False).hosts())[:range_of_hosts]
  
  alive_hosts = []
  
  iterator = tqdm(ips, desc="Scanning hosts", unit="host") if not verbose else ips
  
  
  for ip in iterator:
    command = ["ping", "-c", str(packets), "-W", str(timeout), str(ip)]
     
    try:
      
       
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,timeout= timeout + 1)
       
      if verbose:
        logger.debug(f"Pinging {ip} with {packets} packets and timeout of {timeout} seconds...")
        if result.returncode == 0:
          logger.debug(f"Host {ip} is alive.)")
          alive_hosts.append(str(ip))
          
        else:
          logger.debug(f"Host {ip} is not responding.)")
      
      
    except subprocess.TimeoutExpired:
      logger.Error("Ping command timed out. Please check your network connection and try again.")
       
    except KeyboardInterrupt:
      logger.Warning("Scan interrupted by user.")
       
      logger.info(f"Alive hosts: {len(alive_hosts)})")
       
      for n , host in enumerate(alive_hosts, start=1):
        logger.info(f"{n}. {host}")
         
      sleep(4)
      clear()
      return alive_hosts
      
    except Exception as e:
      logger.Error(f"An error occurred while scanning: {e}")
     
  logger.Info("Scan completed successfully.")
  logger.info(f"Alive hosts: {len(alive_hosts)})")
  for n , host in enumerate(alive_hosts, start=1):
    logger.info(f"{n}. {host}")
  sleep(4)
  clear()
  return alive_hosts
        
    
def scan_hosts_ipv6(logger,input_ip:str,packets:int = 4,range_of_hosts:int= 254,timeout:int = 4, verbose:bool=False):
  pass
  
  
  
  
  
def check_type(logger,input_ip:str,packets:int = 4,range_of_hosts:int= 254,timeout:int = 4,verbose:bool=False):
  ip_add = ipaddress.ip_network(validate_and_parse_ip_cidr(input_ip, logger), strict=False)
  
  if ip_add.version == 4:
    return scan_hosts_ipv4(logger,input_ip, packets ,range_of_hosts, timeout, verbose)
  
  elif ip_add.version == 6:
    pass
    #return scan_hosts_ipv6(input_ip,packets,range_of_hosts, timeout, verbose, logger)
  