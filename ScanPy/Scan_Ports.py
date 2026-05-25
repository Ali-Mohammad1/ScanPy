import socket 
import sys
import os
import threading
from time import sleep

def scan_ports(host, ports, timeout=1,verbose=False):
  open_ports = []
  
  if verbose:
    print(f"Scanning {host} for ports: {ports}")
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    scanner.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
    scanner.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    scanner.settimeout(timeout)