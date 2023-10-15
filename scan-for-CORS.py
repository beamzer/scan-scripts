import requests
import argparse
import sys

def check_header(filename):
    with open(filename, 'r') as file:
        websites = file.readlines()
    
    for website in websites:
        website = website.strip()
        if not website.startswith('http://') and not website.startswith('https://'):
            website = 'https://' + website
        try:
            response = requests.get(website, headers={'Origin': 'http://example.com'})
            if 'Access-Control-Allow-Origin' in response.headers:
                print(f"Website {website} accepts the Origin header.")
                print(f"Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}")
            else:
                print(f"Website {website} does not accept the Origin header.")
        except Exception as e:
            print(f"Could not access {website}. Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Check if websites accept an Origin header.')
    parser.add_argument('filename', help='The filename containing the list of websites.')
    args = parser.parse_args()

    check_header(args.filename)

if __name__ == '__main__':
    main()

