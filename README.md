<img align="left" src="https://github.com/0x4D31/burpa/blob/master/docs/burpa.png" width="90px">

# burpa: Burp Automator

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Burp Suite Automation Tool

<img align="center" src="https://github.com/0x4D31/burpa/blob/master/docs/diagram.png" width="650px">

## Requirements
* [burp-rest-api](https://github.com/vmware/burp-rest-api)
* Burp Suite Professional
* slackclient

## Usage

```
$ python burpa.py -h

###################################################
            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version 0.1 / by 0x4D31  

###################################################
usage: burpa.py [-h] [-a {scan,proxy-config,stop}] [-pP PROXY_PORT]
                [-aP API_PORT] [-rT {HTML,XML}] [-r {in-scope,all}] [-sR]
                [-sAT SLACK_API_TOKEN]
                [--include-scope [INCLUDE_SCOPE [INCLUDE_SCOPE ...]]]
                [--exclude-scope [EXCLUDE_SCOPE [EXCLUDE_SCOPE ...]]]
                proxy_url

positional arguments:
  proxy_url             Burp Proxy URL

optional arguments:
  -h, --help            show this help message and exit
  -a {scan,proxy-config,stop}, --action {scan,proxy-config,stop}
  -pP PROXY_PORT, --proxy-port PROXY_PORT
  -aP API_PORT, --api-port API_PORT
  -rT {HTML,XML}, --report-type {HTML,XML}
  -r {in-scope,all}, --report {in-scope,all}
  -sR, --slack-report
  -sAT SLACK_API_TOKEN, --slack-api-token SLACK_API_TOKEN
  --include-scope [INCLUDE_SCOPE [INCLUDE_SCOPE ...]]
  --exclude-scope [EXCLUDE_SCOPE [EXCLUDE_SCOPE ...]]
```

### TEST:

```
$ python burpa.py http://127.0.0.1 --action proxy-config

###################################################
            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version 0.1 / by 0x4D31  

###################################################
[+] Checking the Burp proxy configuration ...
[-] Proxy configuration needs to be updated
[+] Updating the Burp proxy configuration ...
[-] Proxy configuration updated

$ python burpa.py http://127.0.0.1 --action scan --include-scope http://testasp.vulnweb.com --report in-scope --slack-report

###################################################
            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version 0.1 / by 0x4D31  

###################################################
[+] Retrieving the Burp proxy history ...
[-] Found 4 unique targets in proxy history
[+] Updating the scope ...
[-] http://testasp.vulnweb.com included in scope
[+] Active scan started ...
[-] http://testasp.vulnweb.com Added to the scan queue
[-] Scan in progress: %100
[+] Scan completed
[+] Scan issues for http://testasp.vulnweb.com:
  - Issue: Robots.txt file, Severity: Information
  - Issue: Cross-domain Referer leakage, Severity: Information
  - Issue: Cleartext submission of password, Severity: High
  - Issue: Frameable response (potential Clickjacking), Severity: Information
  - Issue: Password field with autocomplete enabled, Severity: Low
  - Issue: Cross-site scripting (reflected), Severity: High
  - Issue: Unencrypted communications, Severity: Low
  - Issue: Path-relative style sheet import, Severity: Information
  - Issue: Cookie without HttpOnly flag set, Severity: Low
  - Issue: File path traversal, Severity: High
  - Issue: SQL injection, Severity: High
[+] Downloading HTML/XML report for http://testasp.vulnweb.com
[-] Scan report saved to /tmp/burp-report_20170807-235135_http-testasp.vulnweb.com.html
[+] Burp scan report uploaded to Slack
```
![screenshot](https://github.com/0x4D31/burpa/blob/master/docs/screenshot.png)
