import ipaddress
import sys
import subprocess
from Verification import validate_and_parse_ip_cidr


def scan_hosts_ipv4(input_ip:str,range_of_hosts:int,timeout:int = 4, verbose:bool = False,logger):
  
  ip_add = ipaddress.ip_network(validate_and_parse_ip_cidr(input_ip, logger), strict=False)
  
  logger.Info("Scanning IPv4 network...")
    
    if range_of_hosts > 254 or range_of_hosts <= 1:
      range_of_hosts= 254
      logger.Warning("Range of hosts must be between 1 and 254. Defaulting to 254.")
    pass
    
    
    
    
    
    
    
def scan_hosts_ipv6():
  pass