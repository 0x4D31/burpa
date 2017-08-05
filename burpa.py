#!/usr/bin/env python
#
# Copyright (C) 2017  Adel "0x4D31" Karimi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import json
import sys
import argparse
import time

__author__ = 'Adel "0x4d31" Karimi'
__version__ = '0.1'

ASCII = r"""
########################################################
    __                                                  
   / /_  __  ___________                                
  / __ \/ / / / ___/ __ \                               
 / /_/ / /_/ / /  / /_/ /                               
/_.___/\__,_/_/  / .___/                                
    ___         ///                       __            
   /   | __  __/ /_____  ____ ___  ____ _/ /_____  _____
  / /| |/ / / / __/ __ \/ __ `__ \/ __ `/ __/ __ \/ ___/
 / ___ / /_/ / /_/ /_/ / / / / / / /_/ / /_/ /_/ / /    
/_/  |_\__,_/\__/\____/_/ /_/ /_/\__,_/\__/\____/_/     
                                                        
########################################################
"""
PROXY_URL = None
PROXY_PORT = None
API_PORT = None
INCLUDE_SCOPE = None
EXCLUDE_SCOPE = None


def config_check():
    """
    Check the Burp proxy configuration to make sure it's running
    and listening on all interfaces
    """
    print "[+] Checking the Burp proxy configuration ..."
    try:
        r = requests.get(
            "{}:{}/burp/configuration".format(PROXY_URL, API_PORT)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error retrieving the Burp configuration: {}".format(e))
        sys.exit(1)
    config = json.loads(r.text)
    running = config['proxy']['request_listeners'][0]['running']
    listen_mode = config['proxy']['request_listeners'][0]['listen_mode']
    if running and listen_mode == "all_interfaces":
        print "[-] Proxy configuration is OK"
        return True
    else:
        print "[-] Proxy configuration needs to be updated"
        return False


def config_update():
    """Update the Burp proxy configuration"""
    print "[+] Updating the Burp proxy configuration ..."
    PROXY_CONF = {
        "proxy": {
            "request_listeners": [{
                "certificate_mode": "per_host",
                "listen_mode": "all_interfaces",
                "listener_port": PROXY_PORT,
                "running": True,
                "support_invisible_proxying": True
            }]
        }
    }
    try:
        r = requests.put(
            "{}:{}/burp/configuration".format(PROXY_URL, API_PORT),
            json=PROXY_CONF
        )
        r.raise_for_status()
        print "[-] Proxy configuration updated"
    except requests.exceptions.RequestException as e:
        print("Error updating the Burp configuration: {}".format(e))
        sys.exit(1)
    return


def proxy_history():
    """Retrieve the Burp proxy history"""
    print "[+] Retrieving the Burp proxy history ..."
    try:
        r = requests.get(
            "{}:{}/burp/proxy/history".format(PROXY_URL, API_PORT)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error retrieving the Burp proxy history: {}".format(e))
        sys.exit(1)
    resp = json.loads(r.text)
    if resp['messages']:
        # Unique list of hosts
        host_set = {i['host'] for i in resp['messages']}
        print "[-] Found {} unique hosts in proxy history".format(
            len(host_set)
        )
        return list(host_set)
    else:
        print "[-] Proxy history is empty"
        return None


def update_scope(action):
    """Include in scope / Exclude from scope"""
    if action == "include":
        for i in INCLUDE_SCOPE:
            try:
                r = requests.put(
                    "{}:{}/burp/target/scope?url={}".format(
                        PROXY_URL,
                        API_PORT,
                        i
                    )
                )
                r.raise_for_status()
                print "[-] {} included in scope".format(i)
            except requests.exceptions.RequestException as e:
                print("Error updating the target scope: {}".format(e))
                sys.exit(1)
    if action == "exclude":
        for i in EXCLUDE_SCOPE:
            try:
                r = requests.delete(
                    "{}:{}/burp/target/scope?url={}".format(
                        PROXY_URL,
                        API_PORT,
                        i
                    )
                )
                r.raise_for_status()
                print "[-] {} excluded from scope".format(i)
            except requests.exceptions.RequestException as e:
                print("Error updating the target scope: {}".format(e))
                sys.exit(1)


def is_inScope(host):
    """Query whether a URL is within the current scope"""
    try:
        r = requests.get(
            "{}:{}/burp/target/scope?url={}".format(PROXY_URL, API_PORT, host)
        )
        r.raise_for_status()
        resp = json.loads(r.text)
        if resp['inScope']:
            print "[-] {} is in the scope".format(host)
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print("Error checking the target scope: {}".format(e))
        sys.exit(1)


def active_scan(baseUrl):
    """Send a URL to Burp to perform active scan"""
    try:
        r = requests.post(
            "{}:{}/burp/scanner/scans/active?baseUrl={}".format(
                PROXY_URL,
                API_PORT,
                baseUrl
            )
        )
        r.raise_for_status()
        print "[-] {} Added to the scan queue".format(baseUrl)
    except requests.exceptions.RequestException as e:
        print("Error adding {} to the scan queue: {}".format(baseUrl, e))
        sys.exit(1)


def scan_status():
    """Get the percentage completed for the scan queue items"""
    try:
        r = requests.get(
            "{}:{}/burp/scanner/status".format(PROXY_URL, API_PORT)
        )
        r.raise_for_status()
        resp = json.loads(r.text)
        print "[-] Scan is {}% done".format(resp['scanPercentage'])
        return resp['scanPercentage']
    except requests.exceptions.RequestException as e:
        print("Error getting the scan status: {}".format(e))


def main():
    global PROXY_URL, PROXY_PORT, API_PORT, INCLUDE_SCOPE, EXCLUDE_SCOPE
    parser = argparse.ArgumentParser(
        usage='burp-automator.py {proxy_url} [options]'
    )
    parser.add_argument(
        'proxy_url',
        type=str,
        help="Burp Proxy URL"
    )
    parser.add_argument(
        '-a', '--action',
        type=str,
        default="scan",
        choices=["scan", "proxy-config"],
        # metavar='',
        # help="Actions: scan, proxy-config (default: scan)"
    )
    parser.add_argument(
        '-pP', '--proxy-port',
        type=str,
        default=8080,
        # metavar='',
        # help="Burp Proxy Port (default: 8080)"
    )
    parser.add_argument(
        '-aP', '--api-port',
        type=str,
        default=8090,
        # metavar='',
        # help="Burp REST API Port (default: 8090)"
    )
    parser.add_argument(
        '--include-scope',
        nargs='*'
        # metavar='',
        # help="Included in scope"
    )
    parser.add_argument(
        '--exclude-scope',
        nargs='*'
        # metavar='',
        # help="Excluded from scope"
    )
    args = parser.parse_args()
    PROXY_URL = args.proxy_url
    PROXY_PORT = args.proxy_port
    API_PORT = args.api_port
    INCLUDE_SCOPE = args.include_scope
    EXCLUDE_SCOPE = args.exclude_scope
    if args.action == "proxy-config":
        if not config_check():
            config_update()
    elif args.action == "scan":
        targets = proxy_history()
        # Update the scope (include/exclude)
        if targets:
            print "[+] Updating the scope ..."
            if INCLUDE_SCOPE:
                update_scope("include")
            if EXCLUDE_SCOPE:
                update_scope("exclude")
            print "[+] Active scan started ..."
            # Check the scope and start the scan
            for t in targets:
                target_url = "http://" + t
                if is_inScope(target_url):
                    active_scan(target_url)
            # Get the scan status
            while scan_status() != 100:
                time.sleep(30)
                scan_status()
            print "[+] Scan finished"

            # TODO: Generate Report
            # TODO: Slack Integration
            # TODO: JIRA Integration


if __name__ == '__main__':
    print('\n'.join(ASCII.splitlines()))
    main()
