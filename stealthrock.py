#!/usr/bin/env python3

import socket
import threading
from queue import Queue
import os
import argparse
import time
import sys
from termcolor import cprint 
from pyfiglet import figlet_format
import random
import concurrent.futures
import ipaddress
import csv
from collections import defaultdict
import re

class Style:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'
    MAGENTA = '\033[35m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[37m'
    VIOLET = '\33[36m'
    BOLD = '\033[1m'

COLORS = [Style.RED, Style.GREEN, Style.BLUE, Style.YELLOW, Style.MAGENTA, Style.VIOLET, Style.WHITE]

def is_valid_domain(domain):
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return bool(pattern.match(domain))

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{Style.RED}Error: Could not resolve domain {domain}{Style.RESET}")
        return None

def os_fingerprint(host):
    try:
        ttl = os.popen(f"ping -c 1 {host} | grep 'ttl=' | cut -d'=' -f2 | cut -d' ' -f1").read().strip()
        ttl = int(ttl)
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"
    except:
        return "Unable to determine"

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unassigned"

def portscan(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(host), port))
            if result == 0:
                return True
        return False
    except socket.error:
        return False

def worker(host, port, results, progress):
    if portscan(host, port):
        service = get_service_name(port)
        results[host][port] = service
    progress['scanned'] += 1
    progress['current_host'] = host
    progress['current_port'] = port

def scan_host(host, start_port, end_port, max_threads):
    results = defaultdict(dict)
    progress = {'scanned': 0, 'current_host': host, 'current_port': start_port}
    total_ports = end_port - start_port + 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(worker, host, port, results, progress) 
                   for port in range(start_port, end_port + 1)]
        
        for _ in concurrent.futures.as_completed(futures):
            percentage = (progress['scanned'] / total_ports) * 100
            print(f"\r{random.choice(COLORS)}Progress: [{int(percentage):3d}%] "
                  f"Scanning {progress['current_host']}:{progress['current_port']} | "
                  f"Open: {len(results[host])}", end="")
            sys.stdout.flush()

    return results

def parse_arguments():
    parser = argparse.ArgumentParser(description="STEALTHROCK Enhanced Port Scanner")
    parser.add_argument("-t", "--threads", type=int, default=100, 
                        help="Specify number of threads (Default 100, MAX 1000)")
    parser.add_argument("-target", "--target", required=True, 
                        help="Specify target IP address, CIDR range, or domain name")
    parser.add_argument("-s", "--start_port", type=int, default=1, 
                        help="Specify Starting Port Number (Default 1)")
    parser.add_argument("-e", "--end_port", type=int, default=65535, 
                        help="Specify Ending Port Number (Default 65535)")
    parser.add_argument("-o", "--output", help="Specify output CSV file")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Enable verbose output")
    options = parser.parse_args()

    if options.threads > 1000:
        print("Warning: Maximum thread count is 1000. Setting threads to 1000.")
        options.threads = 1000

    return options

def save_results_to_csv(results, filename):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Host', 'Port', 'Service']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for host, ports in results.items():
            for port, service in ports.items():
                writer.writerow({'Host': host, 'Port': port, 'Service': service})

def main():
    start_time = time.time()
    
    options = parse_arguments()
    
    cprint(figlet_format('STEALTHROCK', font='slant'), 'red', attrs=['bold'])
    print(f"{Style.GREEN}{Style.BOLD}{Style.UNDERLINE}\r\t\t\t\tBY - GOKUL JAMWAL\n{Style.RESET}{Style.BOLD}{Style.WHITE}")

    target = options.target
    hosts = []

    if is_valid_domain(target):
        ip = resolve_domain(target)
        if ip:
            hosts = [ip]
            print(f"{Style.GREEN}Resolved {target} to {ip}{Style.RESET}")
    else:
        try:
            hosts = list(ipaddress.ip_network(target, strict=False))
        except ValueError:
            print(f"{Style.RED}Invalid target: {target}. Please provide a valid IP, CIDR range, or domain name.{Style.RESET}")
            sys.exit(1)

    all_results = {}
    for host in hosts:
        print(f"\n{Style.GREEN}Scanning host: {Style.RED}{host}{Style.RESET}")
        os_type = os_fingerprint(str(host))
        print(f"{Style.GREEN}Operating System Fingerprint: {Style.YELLOW}{os_type}{Style.RESET}\n")
        
        results = scan_host(host, options.start_port, options.end_port, options.threads)
        all_results.update(results)

    print(f"\n{Style.GREEN}Scan completed. Results:{Style.RESET}")
    for host, ports in all_results.items():
        print(f"\n{Style.YELLOW}Open ports for {host}:{Style.RESET}")
        for port, service in ports.items():
            print(f"{Style.GREEN}  {port}/tcp\t{service}{Style.RESET}")

    if options.output:
        save_results_to_csv(all_results, options.output)
        print(f"\n{Style.GREEN}Results saved to {options.output}{Style.RESET}")

    end_time = time.time()
    print(f"\n{Style.GREEN}Time Taken: {round(end_time - start_time, 1)} Seconds{Style.RESET}")

if __name__ == "__main__":
    main()
