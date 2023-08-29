# Windows Credentials Protections

## Credentials Protections

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) protocol was introduced in Windows XP and was designed to be used with HTTP Protocol for authentication. Microsoft has this protocol **enabled by default in multiple versions of Windows** (Windows XP — Windows 8.0 and Windows Server 2003 — Windows Server 2012) which means that **plain-text passwords are stored in the LSASS** (Local Security Authority Subsystem Service). **Mimikatz** can interact with the LSASS allowing an attacker to **retrieve these credentials** through the following command:

```
sekurlsa::wdigest
```

This behaviour can be **deactivated/activated setting to 1** the value of _**UseLogonCredential**_ and _**Negotiate**_ in _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
If these registry keys **don't exist** or the value is **"0"**, then WDigest will be **deactivated**.

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

## LSA Protection

Microsoft in **Windows 8.1 and later** has provided additional protection for the LSA to **prevent** untrusted processes from being able to **read its memory** or to inject code. This will prevent regular `mimikatz.exe sekurlsa:logonpasswords` for working properly.\
To **activate this protection** you need to set the value _**RunAsPPL**_ in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ to 1.

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```

### Bypass

It is possible to bypass this protection using Mimikatz driver mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** is a new feature in Windows 10 (Enterprise and Education edition) that helps to protect your credentials on a machine from threats such as pass the hash. This works through a technology called Virtual Secure Mode (VSM) which utilizes virtualization extensions of the CPU (but is not an actual virtual machine) to provide **protection to areas of memory** (you may hear this referred to as Virtualization Based Security or VBS). VSM creates a separate "bubble" for key **processes** that are **isolated** from the regular **operating system** processes, even the kernel and **only specific trusted processes may communicate to the processes** (known as **trustlets**) in VSM. This means a process in the main OS cannot read the memory from VSM, even kernel processes. The **Local Security Authority (LSA) is one of the trustlets** in VSM in addition to the standard **LSASS** process that still runs in the main OS to ensure support with existing processes but is really just acting as a proxy or stub to communicate with the version in VSM ensuring actual credentials run on the version in VSM and are therefore protected from attack. For Windows 10, Credential Guard must be turned on and deployed in your organization as it is **not enabled by default.**
From [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). More information and a PS1 script to enable Credential Guard [can be found here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). However, starting in Windows 11 Enterprise, version 22H2 and Windows 11 Education, version 22H2, compatible systems have Windows Defender Credential Guard [turned on by default](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement). 

In this case **Mimikatz cannot do much to bypass** this and extract the hashes from LSASS. But you could always add your **custom SSP** and **capture the credentials** when a user tries to login in **clear-text**.\
More information about [**SSP and how to do this here**](../active-directory-methodology/custom-ssp.md).

Credentials Guard could be **enable in different ways**. To check if it was enabled using the registry you could check the value of the key _**LsaCfgFlags**_ in _**HKLM\System\CurrentControlSet\Control\LSA**_. If the value is **"1"** the it is active with UEFI lock, if **"2"** is active without lock and if **"0"** it's not enabled.\
This is **not enough to enable Credentials Guard** (but it's a strong indicator).\
More information and a PS1 script to enable Credential Guard [can be found here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```

## RDP RestrictedAdmin Mode

With Windows 8.1 and Windows Server 2012 R2, new security features were introduced. One of those security features is the _Restricted Admin mode for RDP_. This new security feature is introduced to mitigate the risk of [pass the hash](https://blog.ahasayen.com/pass-the-hash/) attacks.

When you connect to a remote computer using RDP, your credentials are stored on the remote computer that you RDP into. Usually you are using a powerful account to connect to remote servers, and having your credentials stored on all these computers is a security threat indeed.

Using _Restricted Admin mode for RDP_, when you connect to a remote computer using the command, **mstsc.exe /RestrictedAdmin**, you will be authenticated to the remote computer, but **your credentials will not be stored on that remote computer**, as they would have been in the past. This means that if a malware or even a malicious user is active on that remote server, your credentials will not be available on that remote desktop server for the malware to attack.

Note that as your credentials are not being saved on the RDP session if **try to access network resources** your credentials won't be used. **The machine identity will be used instead**.

![](../../.gitbook/assets/ram.png)

From [here](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

**Domain credentials** are used by operating system components and are **authenticated** by the **Local** **Security Authority** (LSA). Typically, domain credentials are established for a user when a registered security package authenticates the user's logon data. This registered security package may be the **Kerberos** protocol or **NTLM**.

**Windows stores the last ten domain login credentials in the event that the domain controller goes offline**. If the domain controller goes offline, a user will **still be able to log into their computer**. This feature is mainly for laptop users that do not regularly log into their company’s domain. The number of credentials that the computer stores can be controlled by the following **registry key, or via group policy**:

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

The credentials are hidden from normal users, even administrator accounts. The **SYSTEM** user is the only user that has **privileges** to **view** these **credentials**. In order for an administrator to view these credentials in the registry they must access the registry as a SYSTEM user.\
The Cached credentials are stored in the registry at the following registry location:

```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```

**Extracting from Mimikatz**: `lsadump::cache`\
From [here](http://juggernaut.wikidot.com/cached-credentials).

## Protected Users

When the signed in user is a member of the Protected Users group the following protections are applied:

* Credential delegation (CredSSP) will not cache the user's plain text credentials even when the **Allow delegating default credentials** Group Policy setting is enabled.
* Beginning with Windows 8.1 and Windows Server 2012 R2, Windows Digest will not cache the user's plain text credentials even when Windows Digest is enabled.
* **NTLM** will **not cache** the user's **plain text credentials** or NT **one-way function** (NTOWF).
* **Kerberos** will **no** longer create **DES** or **RC4 keys**. Also it will **not cache the user's plain text** credentials or long-term keys after the initial TGT is acquired.
* A **cached verifier is not created at sign-in or unlock**, so offline sign-in is no longer supported.

After the user account is added to the Protected Users group, protection will begin when the user signs in to the device. **From** [**here**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

**Table from** [**here**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
