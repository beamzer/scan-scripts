scan-scripts = a collection of various python scan scripts

# scan_http2.py
python script to check from a list of websites, of an ip-range if the webserver supports HTTP/2
```
% ./scan-http2.py -h
usage: scan-http2.py [-h] (-r RANGE | -f FILE) [-d] [-v] max_parallel_checks

Check if a web server supports HTTP/2.

positional arguments:
  max_parallel_checks   Maximum number of parallel checks.

options:
  -h, --help            show this help message and exit
  -r RANGE, --range RANGE
                        IP range to check.
  -f FILE, --file FILE  File with website names to check.
  -d, --debug           Print HTTP response headers for debugging.
  -v, --verbose         Enable verbose mode.
```

# formfinder.py
recursively scans a website for webpages with forms and iframes
```
% ./formfinder.py www.somewebsite.tld 1
```

# scan_https_certs.py
```
% ./scan_https_certs.py -h
usage: scan_https_certs.py [-h] -i IPRANGE [IPRANGE ...] [-d] [-t TIMEOUT] [-p PARALLEL] [-v]

Scan subnet for hosts on HTTPS, parse certificates and and print out all hostnames

options:
  -h, --help            show this help message and exit
  -i IPRANGE [IPRANGE ...], --iprange IPRANGE [IPRANGE ...]
                        The CIDR IP range to process (can be multiple separated by spaces)
  -d, --debug           Enable debug mode
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds
  -p PARALLEL, --parallel PARALLEL
                        Number of parallel scans, defaults to 1
  -v, --verbose         Enable verbose mode
```

# scan-for-CORS.py
Script to check a list of websites to see if they are vulnerable for CORS.
For an explanation of the CORS vulnerability see: https://portswigger.net/web-security/cors
```
% python3 scan-for-CORS.py
usage: scan-for-CORS.py [-h] filename
```

# find_netscalers
python script to search for citrix netscalers

This works by checking if there is a HTTPS service active on the given ip-address and when it redirects to "/logon/LogonPoint/tmindex.html" it'probably a Citrix Netscaler

```
usage: find_netscalers.py [-h] -i IPRANGE [IPRANGE ...] [-d] [-s] [-t TIMEOUT] [-p PARALLEL] [-v] [-n]

Scan subnet for hosts on HTTPS, parse certificates and point out Citrix Netscalers

optional arguments:
  -h, --help            show this help message and exit
  -i IPRANGE [IPRANGE ...], --iprange IPRANGE [IPRANGE ...]
                        The CIDR IP range to process (can be multiple separated by spaces)
  -d, --debug           Enable debug mode
  -s, --silent          Silent mode, only print found Netscalers
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds
  -p PARALLEL, --parallel PARALLEL
                        Number of parallel scans, defaults to 1
  -v, --verbose         Enable verbose mode
  -n, --nobother        Don't bother about Netscalers, just do the scan
```
