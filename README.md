# burpa: Burp Automator
A Burp Suite Automation Tool

## Description
TBA

## Requirement
* [burp-rest-api](https://github.com/vmware/burp-rest-api)

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
usage: burpa.py {proxy_url} [options]

positional arguments:
  proxy_url             Burp Proxy URL

optional arguments:
  -h, --help            show this help message and exit
  -a {scan,proxy-config}, --action {scan,proxy-config}
  -pP PROXY_PORT, --proxy-port PROXY_PORT
  -aP API_PORT, --api-port API_PORT
  -rT REPORT_TYPE, --report-type REPORT_TYPE
  -r {in-scope,all}, --report {in-scope,all}
  --include-scope [INCLUDE_SCOPE [INCLUDE_SCOPE ...]]
  --exclude-scope [EXCLUDE_SCOPE [EXCLUDE_SCOPE ...]]
```

### TEST:

```
$ python burp-automator.py http://10.0.0.11 -a proxy-config

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

$ python burp-automator.py http://10.0.0.11 -a scan --include-scope http://testphp.vulnweb.com http://testasp.vulnweb.com

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
[-] Found 7 unique targets in proxy history
[+] Updating the scope ...
[-] http://testasp.vulnweb.com included in scope
[-] http://testphp.vulnweb.com included in scope
[+] Active scan started ...
[-] http://testasp.vulnweb.com Added to the scan queue
[-] http://testphp.vulnweb.com Added to the scan queue
[-] Scan in progress: %0
[-] Scan in progress: %20
[-] Scan in progress: %37
[-] Scan in progress: %55
[-] Scan in progress: %76
[-] Scan in progress: %94
[-] Scan in progress: %100
[+] Scan completed
[+] Scan issues for http://testasp.vulnweb.com:
  - Issue: Unencrypted communications, Severity: Low
  - Issue: Frameable response (potential Clickjacking), Severity: Information
  - Issue: Path-relative style sheet import, Severity: Information
  - Issue: Cookie without HttpOnly flag set, Severity: Low
[+] Downloading HTML/XML report for http://testasp.vulnweb.com
[-] Scan report saved to /tmp/burp_report-http-testasp.vulnweb.com 
[+] Scan issues for http://testphp.vulnweb.com:
  - Issue: Directory listing, Severity: Information
  - Issue: Flash cross-domain policy, Severity: High
  - Issue: Cross-domain Referer leakage, Severity: Information
  - Issue: Cleartext submission of password, Severity: High
  - Issue: Frameable response (potential Clickjacking), Severity: Information
  - Issue: Password field with autocomplete enabled, Severity: Low
  - Issue: Unencrypted communications, Severity: Low
  - Issue: Email addresses disclosed, Severity: Information
  - Issue: Path-relative style sheet import, Severity: Information
  - Issue: HTML does not specify charset, Severity: Information
  - Issue: User agent-dependent response, Severity: Information
  - Issue: SQL injection, Severity: High
[+] Downloading HTML/XML report for http://testphp.vulnweb.com
[-] Scan report saved to /tmp/burp_report-http-testphp.vulnweb.com.html
```
