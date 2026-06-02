import argparse
import sys
from Verification import setup_logger, validate_and_parse_ip_cidr
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