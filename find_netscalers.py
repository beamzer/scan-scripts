#!/usr/bin/env python3

# script to scan for citrix netscalers when given a IP-range
# as an extra it can also show other HTTPS servers found along the way (but it doesn't work for SNI)
# and it will show all the website names found in the HTTPS certificate (including those found in SANs)
# location: https://github.com/beamzer/scan-scripts
# 2023-10-11 Ewald...


import ipaddress
import requests
import ssl
import OpenSSL
import socket
import argparse
import concurrent.futures

requests.packages.urllib3.disable_warnings()

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Scan subnet for hosts on HTTPS, parse certificates and point out Citrix Netscalers')
parser.add_argument('-i', '--iprange', type=str, nargs="+", required=True, help='The CIDR IP range to process (can be multiple separated by spaces)')
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
parser.add_argument('-s', '--silent', action='store_true', help='Silent mode, only print found Netscalers')
parser.add_argument('-t', '--timeout', type=int, default=3, help='Connection timeout in seconds')
parser.add_argument('-p', '--parallel', type=int, default=1, help='Number of parallel scans, defaults to 1')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
parser.add_argument('-n', '--nobother', action='store_true', help='Don\'t bother about Netscalers, just do the scan')

# Parse the command line arguments
args = parser.parse_args()
DEBUG = args.debug
VERBOSE = args.verbose
CIDR = args.iprange
SILENT = args.silent
TIMEOUT = args.timeout
WORKERS = args.parallel
NOBOTHER = args.nobother

DEBUG2 = False

if VERBOSE:
    print(f"scanning {CIDR}")
    print(f"timeout = {TIMEOUT}")
    print(f"parallel threads = {WORKERS}")
    NOBOTHER and print("not pointing out netscalers")
    print("\n")

if DEBUG:
    VERBOSE = True

def get_certificate_hostname(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    wrappedSocket = context.wrap_socket(sock, server_hostname=ip)

    try:
        # Establish SSL connection
        wrappedSocket.connect((ip, 443))

        # Get certificate
        der_cert = wrappedSocket.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

        # Get CN from certificate
        common_name = cert.get_subject().CN
        DEBUG and print(f"{ip} found CN: {common_name}")

        # Get SANs from certificate
        sans = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            # Check if extension is SAN
            if "subjectAltName" == ext.get_short_name().decode('utf-8'):
                # Extract SANs
                sans = str(ext)
        
        DEBUG and print(f"{ip} found SANs: {sans}")

        # return str(cert.get_subject().commonName)
        return common_name, sans
    except Exception as e:
        DEBUG2 and print(f"Unable to get certificate from {ip}, Error: {str(e)}")
        return None
    finally:
        wrappedSocket.close()


def check_ip(ip_str):
    DEBUG and print(f"checking {ip_str}")

    result = get_certificate_hostname(ip_str)
    if result is not None:
        hostname, sans = result
        
        if not SILENT:
            print(f"{ip_str}\t{hostname}\t{sans}")

        # you would expect the NOBOTHER check here, but the SSLError info is still relevant info since we came this far
        try:
            DEBUG and print(f"Checking redirect for: {hostname}")
            res = requests.get(f'https://{hostname}', verify=False, allow_redirects=True, timeout=TIMEOUT)
            if not NOBOTHER:
                # Check if redirection end with '/logon/LogonPoint/tmindex.html'
                if 'logon/LogonPoint/tmindex.html' in res.url:
                    return f'Probably Netscaler ON: IP: {ip_str}, Hostname: {hostname}, SANs: {sans}'
        except (requests.ConnectionError, requests.Timeout, ssl.SSLError):
            VERBOSE and print(f"SSLError on {ip}")
            pass

    return None


########################################################### MAIN ######################################

# iterate over all subnets defined on commandline
for subnet in CIDR:
    DEBUG and print(f"scanning: {subnet}")
    # Generate IPs from subnet
    ip_net = ipaddress.ip_network(subnet)

    # List of IP addresses to check
    ips = [str(ip) for ip in ip_net.hosts()]

    # Set maximum number of concurrent workers
    max_workers = WORKERS  # Change this to fit your needs

    # Create a ThreadPoolExecutor, ensuring we manually clean up
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    try:
        # with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_ip = {executor.submit(check_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                if data is not None:
                    print(data)
            except Exception as exc:
                print('%r oops, got an exception: %s' % (ip, exc))

    except KeyboardInterrupt:
        print('\nInterrupted by user. Shutting down operations, please wait a sec...')
        executor.shutdown(wait=False)
    finally:
        executor.shutdown(wait=True)
