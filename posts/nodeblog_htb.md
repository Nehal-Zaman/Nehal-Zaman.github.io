---
layout: post
title: Nodeblog - HackTheBox
date: 20/11/2022
author: Nehal Zaman
tags: ["nosql injection", "xxe", "insecure deserialization"]
---

![](/assets/images/writeups/nodeblog/banner.png)

**Nodeblog** is an easy linux-based box on [HackTheBox](https://hackthebox.eu). Foothold on this box is obtained by discovering an **injection** vulnerability, followed by a **XXE** and finally a **RCE**. Privilege escalation is quite straight forward if the initial steps are enumerated carefully.

Without spoiling it further, let us start with the box.

## SCANNING:

**Rustscan** can be used to quickly do a full port scan.

```
❯ rustscan -a 10.10.11.139 -r 1-65535 --ulimit 5000
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
Open 10.10.11.139:5000
Open 10.10.11.139:22
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-21 03:53 EST
Initiating Ping Scan at 03:53
Scanning 10.10.11.139 [2 ports]
Completed Ping Scan at 03:53, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:53
Completed Parallel DNS resolution of 1 host. at 03:53, 5.56s elapsed
DNS resolution of 1 IPs took 5.56s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 03:53
Scanning 10.10.11.139 [2 ports]
Discovered open port 22/tcp on 10.10.11.139
Discovered open port 5000/tcp on 10.10.11.139
Completed Connect Scan at 03:53, 2.03s elapsed (2 total ports)
Nmap scan report for 10.10.11.139
Host is up, received conn-refused (0.21s latency).
Scanned at 2022-11-21 03:53:20 EST for 2s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5000/tcp open  upnp    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.01 seconds
```

There are 2 ports open in the box: 22 and 5000.

```
❯ nmap -sC -sV -p22,5000 10.10.11.139
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-21 03:57 EST
Nmap scan report for 10.10.11.139
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.44 seconds
```

Obviously, **SSH** is running on port 22. However, `Node.js` is running on port 5000.

```
❯ sudo nmap -sU -sV 10.10.11.139
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-21 04:02 EST
Warning: 10.10.11.139 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.139
Host is up (0.21s latency).
Not shown: 997 closed udp ports (port-unreach)
PORT      STATE         SERVICE   VERSION
9103/udp  open|filtered bacula-sd
21800/udp open|filtered tvpm
26966/udp open|filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2088.39 seconds
```

There is nothing worth enough to note from the UDP scan.

## ENUMERATING WEB

