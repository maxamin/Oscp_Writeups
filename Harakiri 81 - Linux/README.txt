nmap -A --osscan-guess --version-all -p- 192.168.XX.81 -Pn

Nmap scan report for 192.168.XX.81
Host is up (0.13s latency).
Not shown: 65529 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 aa:e5:99:0a:02:3b:d0:1b:d8:ad:19:29:62:8e:3b:83 (RSA)
|   256 8d:53:3c:db:52:88:90:71:0a:c1:f9:56:ed:9c:b0:07 (ECDSA)
|_  256 5a:4f:8b:37:52:c8:38:df:8b:4c:4b:3e:8c:f8:78:fc (ED25519)
25/tcp   open     smtp    Postfix smtpd
|_smtp-commands: harakiri, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
| ssl-cert: Subject: commonName=harakiri

|_ssl-date: TLS randomness does not represent time
80/tcp   filtered http
2255/tcp filtered vrtp
5555/tcp open     smtp    Haraka smtpd 2.8.8
|_smtp-commands: harakiri Hello Unknown [127.0.0.1], Haraka is at your service., PIPELINING, 8BITMIME, SIZE 0, 
8080/tcp open     http    nginx 1.10.3 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Coming soon
Service Info: Hosts:  harakiri, harakiri; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2641.58 seconds