#!/usr/bin/python3

# Script to detect if a webserver supports HTTP/2
# location: https://github.com/beamzer/scan-scripts
# 2023-10-11 Ewald...
#
import pycurl
import ipaddress
from io import BytesIO
import requests
import concurrent.futures
import argparse

def get_headers_via_pycurl(url, verbose=False):
    buffer = BytesIO()
    c = pycurl.Curl()
    try:
        c.setopt(c.URL, url)
        c.setopt(c.HEADER, 1)
        c.setopt(c.NOBODY, 1)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
    except pycurl.error as e:
        if verbose:
            print(f"Error for {url}: {str(e)}")
        return ""
    finally:
        c.close()
    
    body = buffer.getvalue()
    return body.decode('iso-8859-1')

def supports_http2(ip, debug=False, verbose=False):
    try:
        response = requests.get(f'https://{ip}', timeout=5, stream=True)
        # if debug:
        #     print(f"\nHeaders for {ip}:")
        #     for key, value in response.headers.items():
        #         print(f"{key}: {value}")
        
        # Check via requests
        if response.raw.version == 20:
            if debug:
                print(f"{ip}: HTTP/2 detected via response.raw.version")
            return True

        # Check for upgrade header
        if response.headers.get('upgrade', '').lower() == 'h2':
            if debug:
                print(f"{ip}: HTTP/2 detected via Upgrade header")
            return True

        # Check via pycurl
        headers_pycurl = get_headers_via_pycurl(f'https://{ip}')
        if headers_pycurl.startswith("HTTP/2"):
            if debug:
                print(f"{ip}: HTTP/2 detected via pycurl")
            return True
        
        return False
    except requests.RequestException as e:
        if verbose:
            print(f"\nError for {ip}: {str(e)}")
        return False

def check_ip(ip, debug=False, verbose=False):
    # print(f'{ip} has an active web server on port 443.', end=' ')
    supports_http2(ip, debug, verbose)
    #if supports_http2(ip, debug, verbose):
    #    print('The web server supports HTTP/2.')
    # else:
    #     print('The web server does not support HTTP/2.')

def check_ips_in_parallel(targets, max_workers, debug, verbose):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda ip: check_ip(ip, debug), targets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check if a web server supports HTTP/2.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-r', '--range', help='IP range to check.')
    group.add_argument('-f', '--file', help='File with website names to check.')
    parser.add_argument('max_parallel_checks', type=int, help='Maximum number of parallel checks.')
    parser.add_argument('-d', '--debug', action='store_true', help='Print HTTP response headers for debugging.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode.')
    args = parser.parse_args()
    
    max_parallel_checks = args.max_parallel_checks
    
    if args.range:
        targets = [str(ip) for ip in ipaddress.IPv4Network(args.range, strict=False)]
    elif args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f.readlines()]
    
    check_ips_in_parallel(targets, max_parallel_checks, args.debug, args.verbose)

