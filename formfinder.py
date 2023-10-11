#!/usr/bin/env python3

# Script to find webpages with forms and iframes given a website
# location: https://github.com/beamzer/scan-scripts
# 2023-10-11 Ewald...

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
import time
import sys

# Global variables to control what checks to perform
IFRAME = True
FORMS = True
VERBOSE = False
DEBUG = False

# Function Definitions

def handle_meta_redirect(session, url):
    """Check and follow redirections via "meta http-equiv" tags."""
    try:
        resp = session.get(url)
        soup = BeautifulSoup(resp.content, 'html.parser')
        redirect_tag = soup.find('meta', attrs={'http-equiv': lambda value: value and value.lower() == 'refresh'})
        
        if redirect_tag and 'content' in redirect_tag.attrs:
            wait_time, new_url = redirect_tag['content'].split(';')
            new_url = new_url.split('=')[1].strip('"\' ')
            new_url = urljoin(url, new_url)
            if VERBOSE:
                print(f"Following redirect to {new_url}")
            return new_url, BeautifulSoup(session.get(new_url).content, 'html.parser')
        
        return url, soup
    
    except requests.RequestException as e:
        print(f"Request failed: {str(e)}")
        return url, None

def check_iframes(session, url, soup):
    """Check and inform about the existence of iframe tags in the HTML."""
    if VERBOSE:
        print(f"Scanning for iframes: {url}")
    
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        print(f"Found iframe: {iframe.get('src', '[no src attribute]')} on {url}")

def check_forms(session, url, soup):
    """Check and inform about the existence of form tags in the HTML."""
    if VERBOSE:
        print(f"Scanning for forms: {url}")
    
    forms = soup.find_all("form")
    for form in forms:
        print(f"Found form: {form.get('action', '[no action attribute]')} on {url}")

# def get_links(url, soup):
#     """Retrieve all the linked URLs within the provided HTML soup object."""
#     links = set()
#     for a_tag in soup.find_all("a", href=True):
#         link = urljoin(url, a_tag['href'])
#         link = urldefrag(link)[0]  # Remove URL fragment
#         if link.startswith("http"):
#             links.add(link)
#     return links

def get_links(base_url, soup):
    """Retrieve all the linked URLs within the provided HTML soup object, ensuring they are part of the same domain."""
    links = set()
    base_netloc = urlparse(base_url).netloc  # Extract base URL domain
    
    for a_tag in soup.find_all("a", href=True):
        link = urljoin(base_url, a_tag['href'])
        link = urldefrag(link)[0]  # Remove URL fragment
        # Ensure the link is of http/https type and within the same domain
        if link.startswith("http") and urlparse(link).netloc == base_netloc:
            links.add(link)
    return links


def scrape_recursive(session, url, wait, visited=None):
    """Recursively scrape the URL and ones linked from it, checking for iframes/forms as configured."""
    if visited is None:
        visited = set()
    
    DEBUG and print (f"\nscrape_recursive for: {url}")

    if url.startswith(('http', 'https')):
        if url not in visited:
            visited.add(url)

            url, soup = handle_meta_redirect(session, url)

            # Check for iframes if IFRAME is True
            if IFRAME and soup:
                check_iframes(session, url, soup)

            # Check for forms if FORMS is True
            if FORMS and soup:
                check_forms(session, url, soup)

            time.sleep(wait)

            if soup:
                for link in get_links(url, soup):
                    if link not in visited:
                        scrape_recursive(session, link, wait, visited)

# Main Functionality

if __name__ == "__main__":
    try:
        # Ensure a website URL is provided as a command-line argument
        if len(sys.argv) < 2:
            print("Usage: python script_name.py [website_name] [delay_time]")
            sys.exit(1)

        website_url = sys.argv[1]
        if not website_url.startswith(("http://", "https://")):
            website_url = "https://" + website_url

        delay_time = int(sys.argv[2]) if len(sys.argv) >= 3 else 1  # Default to 1 sec if no delay is provided

        with requests.Session() as session:
            scrape_recursive(session, website_url, delay_time)

    except KeyboardInterrupt:
        print("KeyboardInterrupt caught. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)