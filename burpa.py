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

import argparse
import os
import sys
import tempfile
import time

import requests
from slackclient import SlackClient

__author__ = 'Adel "0x4d31" Karimi'
__version__ = '0.1'

# ################[ configuration ]################
# Slack Report
SLACK_REPORT = False
SLACK_API_TOKEN = ""
SLACK_CHANNEL = "#burpa"
###################################################

ASCII = r"""
###################################################
            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version 0.1 / by 0x4D31  

###################################################"""


def config_check(api_port, proxy_url):
    """
    Check the Burp proxy configuration to make sure it's running
    and listening on all interfaces
    """
    # Because of an issue in burp-rest-api
    # (https://github.com/vmware/burp-rest-api/issues/17),
    # we can't load our config when running the Burp (the default
    # config getting set). So we need to set the proxy listen_mode
    # using the API
    print("[+] Checking the Burp proxy configuration ...")
    try:
        r = requests.get(
            "{}:{}/burp/configuration".format(proxy_url, api_port)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error retrieving the Burp configuration: {}".format(e))
        sys.exit(1)
    else:
        config = r.json()
        running = config['proxy']['request_listeners'][0]['running']
        listen_mode = config['proxy']['request_listeners'][0]['listen_mode']
        if running and listen_mode == "all_interfaces":
            print("[-] Proxy configuration is OK")
            return True
        else:
            print("[-] Proxy configuration needs to be updated")
            return False


def config_update(api_port, proxy_port, proxy_url):
    """Update the Burp proxy configuration"""
    print("[+] Updating the Burp proxy configuration ...")
    proxy_conf = {
        "proxy": {
            "request_listeners": [{
                "certificate_mode": "per_host",
                "listen_mode": "all_interfaces",
                "listener_port": proxy_port,
                "running": True,
                "support_invisible_proxying": True
            }]
        }
    }
    try:
        r = requests.put(
            "{}:{}/burp/configuration".format(proxy_url, api_port),
            json=proxy_conf
        )
        r.raise_for_status()
        print("[-] Proxy configuration updated")
    except requests.exceptions.RequestException as e:
        print("Error updating the Burp configuration: {}".format(e))
        sys.exit(1)


def proxy_history(api_port, proxy_url):
    """Retrieve the Burp proxy history"""
    print("[+] Retrieving the Burp proxy history ...")
    try:
        r = requests.get(
            "{}:{}/burp/proxy/history".format(proxy_url, api_port)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error retrieving the Burp proxy history: {}".format(e))
        sys.exit(1)
    else:
        resp = r.json()
        if resp['messages']:
            # Unique list of URLs
            host_set = {"{protocol}://{host}".format(**i)
                        for i in resp['messages']}
            print("[-] Found {} unique targets in proxy history".format(
                len(host_set)
            ))
            return list(host_set)
        else:
            print("[-] Proxy history is empty")


def update_scope(action, api_port, proxy_url, scope):
    """Include in scope / Exclude from scope"""
    if action == "include":
        for i in scope:
            try:
                r = requests.put(
                    "{}:{}/burp/target/scope?url={}".format(
                        proxy_url,
                        api_port,
                        i
                    )
                )
                r.raise_for_status()
                print("[-] {} included in scope".format(i))
            except requests.exceptions.RequestException as e:
                print("Error updating the target scope: {}".format(e))
                sys.exit(1)
    elif action == "exclude":
        for i in scope:
            try:
                r = requests.delete(
                    "{}:{}/burp/target/scope?url={}".format(
                        proxy_url,
                        api_port,
                        i
                    )
                )
                r.raise_for_status()
                print("[-] {} excluded from scope".format(i))
            except requests.exceptions.RequestException as e:
                print("Error updating the target scope: {}".format(e))
                sys.exit(1)


def is_in_scope(api_port, host, proxy_url):
    """Query whether a URL is within the current scope"""
    try:
        r = requests.get(
            "{}:{}/burp/target/scope?url={}".format(proxy_url, api_port, host)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error checking the target scope: {}".format(e))
        sys.exit(1)
    else:
        resp = r.json()
        if resp['inScope']:
            # print("[-] {} is in the scope".format(host))
            return True
        else:
            return False


def active_scan(api_port, base_url, proxy_url):
    """Send a URL to Burp to perform active scan"""
    try:
        r = requests.post(
            "{}:{}/burp/scanner/scans/active?baseUrl={}".format(
                proxy_url,
                api_port,
                base_url
            )
        )
        r.raise_for_status()
        print("[-] {} Added to the scan queue".format(base_url))
    except requests.exceptions.RequestException as e:
        print("Error adding {} to the scan queue: {}".format(base_url, e))
        sys.exit(1)


def scan_status(api_port, proxy_url):
    """Get the percentage completed for the scan queue items"""
    try:
        r = requests.get(
            "{}:{}/burp/scanner/status".format(proxy_url, api_port)
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error getting the scan status: {}".format(e))
    else:
        resp = r.json()
        sys.stdout.write("\r[-] Scan in progress: %{}".format(
            resp['scanPercentage'])
        )
        sys.stdout.flush()
        return resp['scanPercentage']


def scan_issues(api_port, proxy_url, url_prefix):
    """
    Returns all of the current scan issues for URLs
    matching the specified urlPrefix
    """
    try:
        if url_prefix == "ALL":
            r = requests.get(
                "{}:{}/burp/scanner/issues".format(
                    proxy_url,
                    api_port,
                )
            )
        else:
            r = requests.get(
                "{}:{}/burp/scanner/issues?urlPrefix={}".format(
                    proxy_url,
                    api_port,
                    url_prefix
                )
            )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error getting the scan issues: {}".format(e))
    else:
        resp = r.json()
        if resp['issues']:
            print("[+] Scan issues for {}:".format(url_prefix))
            uniques_issues = {
                "Issue: {issueName}, Severity: {severity}".format(**issue)
                for issue in resp['issues']
            }
            for issue in uniques_issues:
                print("  - {}".format(issue))
            return True
        else:
            return False


def scan_report(api_port, proxy_url, rtype, url_prefix):
    """
    Downloads the scan report with current Scanner issues for
    URLs matching the specified urlPrefix (HTML/XML)
    """
    try:
        if url_prefix == "ALL":
            r = requests.get(
                "{}:{}/burp/report?reportType={}".format(
                    proxy_url,
                    api_port,
                    rtype
                )
            )
        else:
            r = requests.get(
                "{}:{}/burp/report?urlPrefix={}&reportType={}".format(
                    proxy_url,
                    api_port,
                    url_prefix,
                    rtype
                )
            )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error downloading the scan report: {}".format(e))
    else:
        print("[+] Downloading HTML/XML report for {}".format(url_prefix))
        # Write the response body (byte array) to file
        file_name = "burp-report_{}_{}.{}".format(
            time.strftime("%Y%m%d-%H%M%S", time.localtime()),
            url_prefix.replace("://", "-"),
            rtype.lower()
        )
        file = os.path.join(tempfile.gettempdir(), file_name)
        with open(file, 'wb') as f:
            f.write(r.text)
        print("[-] Scan report saved to {}".format(file))
        return file_name


def slack_report(api_token, fname):
    file = os.path.join(tempfile.gettempdir(), fname)
    sc = SlackClient(api_token)
    response = sc.api_call(
        'files.upload',
        channels=SLACK_CHANNEL,
        filename=fname,
        file=open(file, 'rb'),
        title="Burp Scan Report"
    )
    if response['ok']:
        print("[+] Burp scan report uploaded to Slack")
    else:
        print("[+] Error sending Slack report: {}".format(response['error']))


def burp_stop(api_port, proxy_url):
    """Stop the Burp Suite"""
    # Because of an issue in burp-rest-api
    # (https://github.com/vmware/burp-rest-api/issues/15),
    # we can't Reset/Restore the Burp State, so we need to stop
    # the Burp after the scan to reset the state.
    # e.g. You can use a supervisord configuration to restart the
    # Burp when it stopped running:
    #   [program:burp-rest-api]
    #   command=java -jar /opt/burp-rest-api/build/libs/burp-rest-api-1.0.0.jar
    #   directory=/opt/burp-rest-api/build/libs
    #   redirect_stderr=true
    #   stdout_logfile=/var/log/burp-rest-api.log
    #   autorestart=true
    #   user=burpa
    try:
        r = requests.get(
            "{}:{}/burp/stop".format(proxy_url, api_port)
        )
	r.raise_for_status()
        print("[-] Burp is stopped")
    except requests.exceptions.RequestException as e:
        print("Error stopping the burp: {}".format(e))


def parse_cmd_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'proxy_url',
        type=str,
        help="Burp Proxy URL"
    )
    parser.add_argument(
        '-a', '--action',
        type=str,
        default="scan",
        choices=["scan", "proxy-config", "stop"],
        # metavar='',
        # help="Actions: scan, proxy-config, stop (default: scan)"
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
        '-rT', '--report-type',
        type=str,
        default="HTML",
        choices=["HTML", "XML"]
        # metavar='',
        # help="Burp scan report type (default: HTML)"
    )
    parser.add_argument(
        '-r', '--report',
        type=str,
        default="in-scope",
        choices=["in-scope", "all"],
        # metavar='',
        # help="Reports: all, in-scope (default: in-scope)"
    )
    parser.add_argument(
        '-sR', '--slack-report',
        action='store_true'
    )
    parser.set_defaults(slack_report=SLACK_REPORT)
    parser.add_argument(
        '-sAT', '--slack-api-token',
        type=str,
        default=SLACK_API_TOKEN
        # metavar='',
        # help="Slack API Token (default: in-scope)"
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
    return parser.parse_args()


def main():
    args = parse_cmd_line_args()
    scanned_urls = []

    if args.action == "proxy-config":
        if not config_check(api_port=args.api_port,
                            proxy_url=args.proxy_url):
            config_update(
                api_port=args.api_port,
                proxy_port=args.proxy_port,
                proxy_url=args.proxy_url
            )
    elif args.action == "stop":
        print("[+] Shutting down the Burp Suite ...")
        burp_stop(api_port=args.api_port,
                  proxy_url=args.proxy_url)
    elif args.action == "scan":
        targets = proxy_history(
            api_port=args.api_port,
            proxy_url=args.proxy_url
        )
        if targets:
            # Update the scope (include/exclude)
            print("[+] Updating the scope ...")
            if args.include_scope:
                update_scope(
                    action='include',
                    api_port=args.api_port,
                    scope=args.include_scope,
                    proxy_url=args.proxy_url
                )
            if args.exclude_scope:
                update_scope(
                    action='exclude',
                    api_port=args.api_port,
                    scope=args.exclude_scope,
                    proxy_url=args.proxy_url
                )
            print("[+] Active scan started ...")
            # Check the scope and start the scan
            for target_url in targets:
                if is_in_scope(api_port=args.api_port,
                               host=target_url,
                               proxy_url=args.proxy_url):
                    scanned_urls.append(target_url)
                    active_scan(
                        api_port=args.api_port,
                        base_url=target_url,
                        proxy_url=args.proxy_url
                    )
                else:
                    print("[-] {} is not in the scope".format(target_url))
            # Get the scan status
            while scan_status(api_port=args.api_port,
                              proxy_url=args.proxy_url) != 100:
                time.sleep(20)
            print("\n[+] Scan completed")
            # Print/download the scan issues/reports
            if args.report == "in-scope":
                for url in scanned_urls:
                    if scan_issues(api_port=args.api_port,
                                   proxy_url=args.proxy_url,
                                   url_prefix=url):
                        rfile = scan_report(
                            api_port=args.api_port,
                            proxy_url=args.proxy_url,
                            rtype=args.report_type,
                            url_prefix=url
                        )
                        if args.slack_report:
                            slack_report(api_token=args.slack_api_token,
                                         fname=rfile)
            elif args.report == "all":
                if scan_issues(api_port=args.api_port,
                               proxy_url=args.proxy_url,
                               url_prefix="ALL"):
                    rfile = scan_report(
                        api_port=args.api_port,
                        proxy_url=args.proxy_url,
                        rtype=args.report_type,
                        url_prefix="ALL"
                    )
                    if args.slack_report:
                        slack_report(api_token=args.slack_api_token,
                                     fname=rfile)


if __name__ == '__main__':
    print(ASCII)
    main()
