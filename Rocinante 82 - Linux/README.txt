nmap -sV --script=vuln -oN Vuln_Scan 192.168.XX.82

Nmap scan report for rocinante.localdomain (192.168.XX.82)
Host is up (0.13s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
25/tcp   open  smtp       Postfix smtpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE

80/tcp   open  http       Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.25 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 

3128/tcp open  http-proxy Squid http proxy 3.5.23
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-server-header: squid/3.5.23
| vulners: 

3306/tcp open  mysql      MariaDB (unauthorized)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
Service Info: Host:  rocinante.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 931.15 seconds