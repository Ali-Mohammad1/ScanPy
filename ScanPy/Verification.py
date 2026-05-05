from pathlib import Path
import logging
import re
import ipaddress
import system

#set up the logger
def setup_logger(file_name:str = "scanning_log.log", verbose:bool = False):
  logger = logging.getLogger('PortScanner')
  
  # check file extension 
  if not file_name.endswith('.log'):
    file_name = str(Path(file_name).with_suffix('.log'))
  
  # preparing the log file
  file_handler = logging.FileHandler(file_name)
  file_handler.setLevel(logging.DEBUG)
  formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
  file_handler.setFormatter(formatter)
  logger.addHandler(file_handler)
  
  # preparing the output display
  console_handler = logging.StreamHandler()
  
  console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
  
  console_handler.setFormatter(formatter)
  
  logger.addHandler(console_handler)
  
  return logger
 
 
# set up the verification function to check user inputs
def validate_and_parse_ip_cidr(input_ip: str, logger):
    input_str = input_ip.strip()
    
    # the question is about cidr if it is not available in the input.
    def ask_for_cidr(ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            cidr_max = 32 if ip_obj.version == 4 else 128
            cidr_input = input(f"Enter CIDR prefix (0-{cidr_max}) for {ip_str}: ").strip()
            if not cidr_input.isdigit():
                raise ValueError("CIDR must be an integer")
            cidr = int(cidr_input)
            if not (0 <= cidr <= cidr_max):
                raise ValueError(f"CIDR must be between 0 and {cidr_max}")
            return f"{ip_str}/{cidr}"
        except Exception as e:
            logger.error(f"Invalid CIDR input: {e}")
            sys.exit(1)
            
    # the function to return the output
    def parse_and_return(candidate):
        try:
            iface = ipaddress.ip_interface(candidate)
            return str(iface)
        except ValueError as e:
            logger.error(f"Invalid IP/CIDR: {candidate} - {e}")
            sys.exit(1)
            
    # check 
    if '/' in input_str:
        try:
            ipaddress.ip_interface(input_str)
            return input_str
        except ValueError:
            logger.error(f"Invalid IP/CIDR format: {input_str}. Please enter again.")
            second = input("Enter valid IP/CIDR: ").strip()
            return parse_and_return(second)
    else:
        try:
            ipaddress.ip_address(input_str)
            full = ask_for_cidr(input_str)
            return parse_and_return(full)
        except ValueError:
            logger.error(f"Invalid IP address: {input_str}. Please enter again.")
            second = input("Enter valid IP (without CIDR): ").strip()
            try:
                ipaddress.ip_address(second)
                full = ask_for_cidr(second)
                return parse_and_return(full)
            except ValueError:
                logger.error(f"Invalid IP address again: {second}")
                sys.exit(1)
